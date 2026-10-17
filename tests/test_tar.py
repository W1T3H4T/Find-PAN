"""Tests for tar handling in find-pan.py.

``custom_tar_filter`` is the security boundary for archive extraction: any
member that slips past it gets written to disk under the extraction
directory.  These tests pin the filter's behavior, then exercise
``process_tar_file`` end-to-end over archives built in tmp_path.

``4012888888881881`` is used as the detection fixture PAN: it is Luhn-valid,
matches the VISA pattern, and — unlike 4111111111111111 or
5555555555554444 — is not shadowed by the anti-PAN "repeated numbers"
patterns.
"""

import tarfile

import pytest

DETECTABLE_PAN = "4012888888881881"


class TestCustomTarFilter:
    """custom_tar_filter() decides which tar members may be extracted."""

    @pytest.mark.parametrize(
        ("member_name", "reason"),
        [
            ("../evil.txt", "parent-directory traversal"),
            ("safe/../../evil.txt", "nested traversal"),
            ("/etc/passwd", "absolute path"),
            ("notes..txt", "any '..' in the name, even a benign one"),
        ],
        ids=["parent-traversal", "nested-traversal", "absolute-path", "benign-double-dot"],
    )
    def test_rejects_dangerous_member_names(self, scanner, member_name, reason):
        assert scanner.custom_tar_filter(tarfile.TarInfo(member_name), "/tmp/extract") is None

    def test_accepts_safe_member_names(self, scanner):
        tarinfo = tarfile.TarInfo("data/safe.txt")
        assert scanner.custom_tar_filter(tarinfo, "/tmp/extract") is tarinfo

    @pytest.mark.parametrize(
        ("mode", "expected_mode"),
        [
            (0o777, 0o755),
            (0o666, 0o644),
            (0o644, 0o644),
            (0o600, 0o600),
        ],
        ids=["world-writable", "group-writable", "normal", "restrictive"],
    )
    def test_masks_permissions(self, scanner, mode, expected_mode):
        tarinfo = tarfile.TarInfo("safe.txt")
        tarinfo.mode = mode

        result = scanner.custom_tar_filter(tarinfo, "/tmp/extract")

        assert result is tarinfo
        assert tarinfo.mode == expected_mode


@pytest.fixture
def tar_archive(tmp_path):
    """Build a tar containing a directory and one safe regular member."""
    sources = tmp_path / "sources"
    sources.mkdir()

    safe_file = sources / "safe.txt"
    safe_file.write_text(f"card number: {DETECTABLE_PAN}\n", encoding="utf-8")

    nested_directory = sources / "nested"
    nested_directory.mkdir()

    archive_path = sources / "archive.tar"
    with tarfile.open(archive_path, "w") as archive:
        archive.add(safe_file, arcname="safe.txt")
        archive.add(nested_directory, arcname="nested", recursive=False)
    return archive_path


class TestProcessTarFile:
    """process_tar_file() scans, reports, and cleans up archive members."""

    def test_scans_regular_members_and_reports_matches(
        self, scanner, compiled_patterns, tar_archive, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(scanner, "find_secure_delete_program", lambda: None)
        tar_tmp = tmp_path / "tar-tmp"
        scanner._Args.tar = str(tar_archive)
        scanner._Args.tar_tmp = str(tar_tmp)

        scanner.process_tar_file(scanner._Args, compiled_patterns)

        #   The safe member was scanned and the PAN was reported
        assert scanner._MatchCount["PAN"] == 1
        assert scanner._MatchCount["FILES"] == 1
        #   The scanned member was securely deleted after processing
        assert not (tar_tmp / "safe.txt").exists()
        #   The traversal member never reached disk
        assert not list(tar_tmp.rglob("evil.txt"))

    def test_empty_archive_processes_no_files(
        self, scanner, compiled_patterns, tmp_path
    ):
        archive_path = tmp_path / "empty.tar"
        with tarfile.open(archive_path, "w"):
            pass

        scanner._Args.tar = str(archive_path)
        scanner._Args.tar_tmp = str(tmp_path / "tar-tmp")

        scanner.process_tar_file(scanner._Args, compiled_patterns)

        assert scanner._MatchCount["FILES"] == 0
        assert scanner._MatchCount["PAN"] == 0


@pytest.mark.xfail(
    strict=True,
    reason="find-pan.py bug: process_tar_file() calls process_file() and "
    "secure_delete() on members rejected by custom_tar_filter(). When no "
    "file exists at the traversal path, secure_delete() crashes the scan "
    "with an unhandled FileNotFoundError; when a file DOES exist there "
    "(outside the extraction directory), it is scanned and then deleted. "
    "Fix process_tar_file() to skip rejected members entirely, then remove "
    "this xfail marker.",
)
def test_traversal_member_is_ignored_entirely(
    scanner, compiled_patterns, tmp_path, monkeypatch
):
    """A traversal member must not be scanned, extracted, or deleted."""
    monkeypatch.setattr(scanner, "find_secure_delete_program", lambda: None)
    sources = tmp_path / "sources"
    sources.mkdir()
    traversal_file = sources / "evil.txt"
    traversal_file.write_text("must never be extracted\n", encoding="utf-8")

    archive_path = sources / "evil.tar"
    with tarfile.open(archive_path, "w") as archive:
        archive.add(traversal_file, arcname="../evil.txt")

    tar_tmp = tmp_path / "tar-tmp"
    scanner._Args.tar = str(archive_path)
    scanner._Args.tar_tmp = str(tar_tmp)

    scanner.process_tar_file(scanner._Args, compiled_patterns)

    assert scanner._MatchCount["FILES"] == 0
    assert not list(tar_tmp.rglob("evil.txt"))
    #   The archive's own source file must still be on disk: it lives
    #   outside the extraction directory and is not ours to delete.
    assert traversal_file.exists()


class TestSecureDelete:
    """secure_delete() removes extracted files using the best tool available."""

    def test_without_tool_falls_back_to_os_remove(self, scanner, tmp_path):
        target = tmp_path / "sensitive.txt"
        target.write_text("track data\n", encoding="utf-8")

        scanner.secure_delete(None, str(target))

        assert not target.exists()

    def test_runs_the_configured_tool_without_mutating_the_caller_list(
        self, scanner, tmp_path, monkeypatch
    ):
        commands = []
        monkeypatch.setattr(
            scanner.subprocess, "run", lambda command, check: commands.append(command)
        )

        tool_command = ["sdelete64.exe"]
        scanner.secure_delete(tool_command, str(tmp_path / "sensitive.txt"))

        assert commands == [["sdelete64.exe", str(tmp_path / "sensitive.txt")]]
        assert tool_command == ["sdelete64.exe"]

    def test_tool_failure_is_logged_not_raised(
        self, scanner, tmp_path, monkeypatch, caplog
    ):
        def failing_run(command, check):
            raise scanner.subprocess.CalledProcessError(1, command)

        monkeypatch.setattr(scanner.subprocess, "run", failing_run)

        target = tmp_path / "sensitive.txt"
        target.write_text("track data\n", encoding="utf-8")

        #   Must not raise: a failed wipe is logged and the scan continues.
        scanner.secure_delete(["sdelete64.exe"], str(target))

        assert "Error securely deleting" in caplog.text


class TestFindSecureDeleteProgram:
    """find_secure_delete_program() locates an OS-appropriate wipe tool."""

    def test_discovers_posix_shred(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner.os, "name", "posix")
        monkeypatch.setattr(
            scanner.shutil,
            "which",
            lambda tool: "/usr/bin/shred" if tool == "shred" else None,
        )

        assert scanner.find_secure_delete_program() == ["/usr/bin/shred", "-u"]

    def test_discovers_windows_sdelete(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner.os, "name", "nt")
        monkeypatch.setattr(
            scanner.shutil,
            "which",
            lambda tool: r"C:\Sysinternals\sdelete64.exe"
            if tool == "sdelete64.exe"
            else None,
        )

        assert scanner.find_secure_delete_program() == [r"C:\Sysinternals\sdelete64.exe"]

    def test_returns_none_when_no_tool_found(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner.os, "name", "posix")
        monkeypatch.setattr(scanner.shutil, "which", lambda tool: None)

        assert scanner.find_secure_delete_program() is None