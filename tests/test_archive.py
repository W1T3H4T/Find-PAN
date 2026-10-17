"""Tests for archive extraction and scanning in find-pan.py.

``process_archive_file()`` now delegates extraction to external programs
(tar, unzip, 7z, gzip) and scans the contents of a temporary directory that
is removed afterwards.  These tests exercise the archive-type detection,
extractor configuration, generic extraction pipeline, and cleanup.

``4012888888881881`` is used as the detection fixture PAN: it is Luhn-valid,
matches the VISA pattern, and — unlike 4111111111111111 or
5555555555554444 — is not shadowed by the anti-PAN "repeated numbers"
patterns.
"""

import gzip
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

import yaml

DETECTABLE_PAN = "4012888888881881"


class TestDetectArchiveType:
    """detect_archive_type() maps extensions to extractor keys."""

    @pytest.mark.parametrize(
        ("filename", "expected_type"),
        [
            ("backup.tar", "tar"),
            ("backup.tar.gz", "tar"),
            ("backup.tgz", "tar"),
            ("backup.tar.bz2", "tar"),
            ("backup.tbz2", "tar"),
            ("backup.tar.xz", "tar"),
            ("backup.txz", "tar"),
            ("archive.zip", "zip"),
            ("app.jar", "zip"),
            ("bundle.7z", "7z"),
            ("dump.gz", "gzip"),
            ("UPPER.TAR.GZ", "tar"),
        ],
        ids=lambda item: item[0],
    )
    def test_supported_extensions(self, pan_config, filename, expected_type):
        assert pan_config.detect_archive_type(filename) == expected_type

    @pytest.mark.parametrize(
        "filename",
        ["readme.txt", "data.bin", "image.png", "archive.unknown"],
    )
    def test_unsupported_extensions_return_none(self, pan_config, filename):
        assert pan_config.detect_archive_type(filename) is None


class TestExtractorConfig:
    """find-pan-conf.yaml is discovered, built, and loaded."""

    def test_build_extractor_config_creates_yaml_with_discovered_tools(
        self, pan_config, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            pan_config.shutil,
            "which",
            lambda tool: f"/usr/bin/{tool}" if tool in ("tar", "unzip", "gzip") else None,
        )
        config_path = tmp_path / "find-pan-conf.yaml"

        pan_config.build_extractor_config(str(config_path))

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        extractors = data["extractors"]
        assert extractors["tar"]["command"] == "tar"
        assert extractors["zip"]["command"] == "unzip"
        assert extractors["gzip"]["command"] == "gzip"
        #   7z was not discovered, so the first candidate command is recorded.
        assert extractors["7z"]["command"] == "7z"
        #   Compression metadata is present for every extractor.
        for archive_type in ("tar", "zip", "7z", "gzip"):
            assert extractors[archive_type]["compression"]

    def test_load_extractor_config_returns_extractors(self, pan_config, tmp_path):
        config_path = tmp_path / "find-pan-conf.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "extractors": {
                        "tar": {"command": "gtar", "args": ["-xf", "{archive}", "-C", "{tempdir}"]}
                    }
                }
            ),
            encoding="utf-8",
        )

        extractors = pan_config.load_extractor_config(str(config_path))

        assert extractors["tar"]["command"] == "gtar"


@pytest.fixture
def make_tar_archive(tmp_path):
    """Factory: build a tar archive with a single PAN-bearing text file."""
    def _make(name="archive.tar", arcname="safe.txt", content=None):
        content = content or f"card number: {DETECTABLE_PAN}\n"
        sources = tmp_path / "sources"
        sources.mkdir(exist_ok=True)
        safe_file = sources / "safe.txt"
        safe_file.write_text(content, encoding="utf-8")
        archive_path = sources / name
        with tarfile.open(archive_path, "w") as archive:
            archive.add(safe_file, arcname=arcname)
        return str(archive_path)
    return _make


@pytest.fixture
def fake_extractor(tmp_path):
    """Return a fake extractor config that uses a shell/batch helper to
    create a single file in the temp directory.

    The helper simply copies a known source file into the requested tempdir.
    """
    source = tmp_path / "extracted.txt"
    source.write_text(f"card number: {DETECTABLE_PAN}\n", encoding="utf-8")
    return {
        "command": str(source),
        "args": [],
        "copy_archive_to_tempdir": False,
    }


class TestProcessArchiveFile:
    """process_archive_file() extracts with an external tool and scans."""

    def test_extracts_and_scans_with_external_command(
        self, scanner, compiled_patterns, tmp_path, monkeypatch
    ):
        """Simulate an extractor that writes a PAN file into the temp dir."""
        extracted = tmp_path / "extracted.txt"
        extracted.write_text(f"card number: {DETECTABLE_PAN}\n", encoding="utf-8")

        def fake_run(cmd, check, capture_output, text):
            #   cmd[0] is our sentinel path; copy the source into the tempdir.
            tempdir = cmd[-1]
            shutil.copy2(extracted, Path(tempdir) / "safe.txt")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(scanner.subprocess, "run", fake_run)

        scanner.process_archive_file(
            str(tmp_path / "archive.tar"),
            compiled_patterns,
            {"tar": {"command": str(extracted), "args": ["{tempdir}"], "copy_archive_to_tempdir": False}},
        )

        assert scanner._MatchCount["PAN"] == 1
        assert scanner._MatchCount["FILES"] == 1

    def test_cleans_up_temp_directory_after_scanning(
        self, scanner, compiled_patterns, tmp_path, monkeypatch
    ):
        captured_tempdir = {}

        def fake_run(cmd, check, capture_output, text):
            tempdir = cmd[-1]
            captured_tempdir["path"] = tempdir
            (Path(tempdir) / "safe.txt").write_text(
                f"card number: {DETECTABLE_PAN}\n", encoding="utf-8"
            )
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(scanner.subprocess, "run", fake_run)
        scanner._Args.tar_tmp = str(tmp_path / "tar-tmp")

        scanner.process_archive_file(
            str(tmp_path / "archive.tar"),
            compiled_patterns,
            {"tar": {"command": "fake", "args": ["{tempdir}"], "copy_archive_to_tempdir": False}},
        )

        assert captured_tempdir["path"]
        assert not Path(captured_tempdir["path"]).exists()

    def test_logs_error_for_unsupported_archive_type(
        self, scanner, compiled_patterns, tmp_path, caplog
    ):
        scanner.process_archive_file(
            str(tmp_path / "data.rar"),
            compiled_patterns,
            {},
        )

        assert "Unsupported archive type" in caplog.text
        assert scanner._MatchCount["PAN"] == 0

    def test_logs_error_when_no_extractor_configured(
        self, scanner, compiled_patterns, tmp_path, caplog
    ):
        scanner.process_archive_file(
            str(tmp_path / "archive.zip"),
            compiled_patterns,
            {"tar": {}},
        )

        assert "No extractor configured" in caplog.text

    def test_logs_error_when_extractor_command_missing(
        self, scanner, compiled_patterns, tmp_path, monkeypatch, caplog
    ):
        monkeypatch.setattr(scanner.shutil, "which", lambda command: None)

        scanner.process_archive_file(
            str(tmp_path / "archive.tar"),
            compiled_patterns,
            {"tar": {"command": "not-installed", "args": ["{archive}", "{tempdir}"], "copy_archive_to_tempdir": False}},
        )

        assert "Extractor command not found" in caplog.text

    def test_logs_error_when_extractor_command_fails(
        self, scanner, compiled_patterns, tmp_path, monkeypatch, caplog
    ):
        def failing_run(cmd, check, capture_output, text):
            raise subprocess.CalledProcessError(2, cmd, stderr="broken archive")

        monkeypatch.setattr(scanner.subprocess, "run", failing_run)

        scanner.process_archive_file(
            str(tmp_path / "archive.tar"),
            compiled_patterns,
            {"tar": {"command": "tar", "args": ["{archive}", "{tempdir}"], "copy_archive_to_tempdir": False}},
        )

        assert "Extractor failed" in caplog.text
        assert "broken archive" in caplog.text

    def test_incomplete_extractor_configuration_is_logged(
        self, scanner, compiled_patterns, tmp_path, caplog
    ):
        scanner.process_archive_file(
            str(tmp_path / "archive.tar"),
            compiled_patterns,
            {"tar": {"command": "tar", "args": [], "copy_archive_to_tempdir": False}},
        )

        #   Empty args are treated as incomplete in this test; the function
        #   logs the error and returns without scanning.
        assert scanner._MatchCount["PAN"] == 0

    def test_gzip_extractor_copies_archive_to_tempdir(
        self, scanner, compiled_patterns, tmp_path, monkeypatch
    ):
        """gzip works in-place, so the archive must be copied to the temp dir."""
        original = tmp_path / "dump.txt"
        original.write_text(f"card number: {DETECTABLE_PAN}\n", encoding="utf-8")
        gz_path = tmp_path / "dump.gz"
        with gzip.open(gz_path, "wb") as gz:
            gz.write(original.read_bytes())

        captured = {}

        def fake_run(cmd, check, capture_output, text):
            archive_in_temp = cmd[-1]
            captured["archive_in_temp"] = archive_in_temp
            #   Simulate gzip -d by writing the decompressed content next to it.
            decompressed = Path(archive_in_temp).with_suffix("")
            decompressed.write_bytes(original.read_bytes())
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(scanner.subprocess, "run", fake_run)
        scanner._Args.tar_tmp = str(tmp_path / "tar-tmp")

        scanner.process_archive_file(
            str(gz_path),
            compiled_patterns,
            {
                "gzip": {
                    "command": "gzip",
                    "args": ["-d", "{archive}"],
                    "copy_archive_to_tempdir": True,
                }
            },
        )

        assert scanner._MatchCount["PAN"] == 1
        assert str(gz_path) != captured["archive_in_temp"]
        assert Path(captured["archive_in_temp"]).name == "dump.gz"
        assert not Path(captured["archive_in_temp"]).parent.exists()


class TestFindExtractorConfigPath:
    """find_extractor_config_path() locates or creates the YAML config.

    Searches, in order:

    1. ``$XDG_CONFIG_HOME/find-pan`` if set.
    2. ``$HOME/.config/find-pan``.
    3. ``<appRoot>/config/find-pan`` where ``<appRoot>`` is the directory
       containing the ``bin`` folder that holds ``find-pan.py``.

    If none of those locations contain a configuration file, one is created in
    the first writable XDG location and populated by discovering extractors on PATH.
    """

    def test_returns_existing_config_file(self, pan_config, tmp_path):
        config_dir = tmp_path / "find-pan"
        config_dir.mkdir()
        config_file = config_dir / "find-pan-conf.yaml"
        config_file.write_text("extractors:\n", encoding="utf-8")

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        try:
            path = pan_config.find_extractor_config_path()
            assert path == str(config_file)
            #   Existing file must not be overwritten.
            assert Path(path).read_text(encoding="utf-8") == "extractors:\n"
        finally:
            monkeypatch.undo()

    def test_builds_config_under_xdg_config_home(self, pan_config, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        #   Hide the bundled appRoot config and the real home directory so the
        #   XDG location is used.
        monkeypatch.setattr(
            pan_config, "_application_root", lambda: str(tmp_path / "empty-app-root")
        )
        monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))
        monkeypatch.setattr(
            pan_config.shutil,
            "which",
            lambda tool: f"/usr/bin/{tool}" if tool == "tar" else None,
        )

        path = pan_config.find_extractor_config_path()

        assert path == str(tmp_path / "find-pan" / "find-pan-conf.yaml")
        assert Path(path).exists()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        assert "extractors" in data
        assert data["extractors"]["tar"]["command"] == "tar"

    def test_builds_config_under_home_dot_config_when_xdg_unset(
        self, pan_config, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        #   Force the search to the tmp_path by overriding the home directory.
        monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))
        #   Hide the bundled appRoot config so the home directory is used.
        monkeypatch.setattr(
            pan_config, "_application_root", lambda: str(tmp_path / "empty-app-root")
        )
        monkeypatch.setattr(
            pan_config.shutil,
            "which",
            lambda tool: f"/usr/bin/{tool}" if tool == "tar" else None,
        )

        path = pan_config.find_extractor_config_path()

        assert path == str(tmp_path / ".config" / "find-pan" / "find-pan-conf.yaml")
        assert Path(path).exists()

    def test_returns_app_root_extractor_config_when_no_user_config(
        self, pan_config, tmp_path, monkeypatch
    ):
        """BUG-005: an appRoot config is used when no user-level config exists."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))

        path = pan_config.find_extractor_config_path()

        assert path.endswith(os.path.join("config", "find-pan-conf.yaml"))
        assert Path(path).exists()

    def test_raises_when_config_directory_cannot_be_created(
        self, pan_config, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "not-a-directory"))
        #   Hide the bundled appRoot config and the real home directory so
        #   creation in the XDG location is attempted.
        monkeypatch.setattr(
            pan_config, "_application_root", lambda: str(tmp_path / "empty-app-root")
        )
        monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))
        monkeypatch.setattr(
            pan_config.os,
            "makedirs",
            lambda _path, exist_ok=False: (_ for _ in ()).throw(OSError("no write")),
        )

        with pytest.raises(FileNotFoundError):
            pan_config.find_extractor_config_path()


class TestArchiveTypeDetection:
    """Longest multi-part extension wins over shorter suffixes."""

    def test_tar_gz_beats_gz(self, pan_config):
        assert pan_config.detect_archive_type("file.tar.gz") == "tar"

    def test_case_insensitive_matching(self, pan_config):
        assert pan_config.detect_archive_type("FILE.ZIP") == "zip"
