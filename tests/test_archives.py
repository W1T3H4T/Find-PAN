"""Tests for find_pan.archives.extract_archive."""

import gzip
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from find_pan import archives
from find_pan.errors import ExtractorError, ExtractorUnavailable

LOGGER = logging.getLogger("test.archives")


@pytest.mark.parametrize("version,callback_name", [((3, 11), "onerror"), ((3, 12), "onexc")])
def test_remove_tree_uses_version_appropriate_error_callback(monkeypatch, tmp_path, version, callback_name):
    root = tmp_path / "extract"
    child = root / "file.txt"
    accessible = Mock()
    retry = Mock()
    error = PermissionError("denied")

    def rmtree(path, **kwargs):
        assert path == str(root)
        assert list(kwargs) == [callback_name]
        argument = (type(error), error, None) if callback_name == "onerror" else error
        kwargs[callback_name](retry, str(child), argument)

    monkeypatch.setattr(archives.shutil, "rmtree", rmtree)
    monkeypatch.setattr(archives, "_make_user_accessible", accessible)
    with monkeypatch.context() as context:
        context.setattr(archives.sys, "version_info", version)
        archives._remove_tree(str(root))
    assert accessible.call_args_list == [((str(root),),), ((str(child),),)]
    retry.assert_called_once_with(str(child))


def test_kill_tree_uses_windows_taskkill(monkeypatch):
    process = Mock(pid=123)
    runner = Mock()
    monkeypatch.setattr(archives, "_IS_WINDOWS", True)
    monkeypatch.setattr(archives.subprocess, "run", runner)
    archives._kill_tree(process)
    runner.assert_called_once_with(["taskkill", "/F", "/T", "/PID", "123"], capture_output=True, check=False)
    process.kill.assert_called_once_with()
    process.wait.assert_called_once_with()


def test_kill_tree_uses_posix_process_group(monkeypatch):
    process = Mock(pid=123)
    killpg = Mock()
    monkeypatch.setattr(archives, "_IS_WINDOWS", False)
    monkeypatch.setattr(archives.os, "killpg", killpg, raising=False)
    monkeypatch.setattr(archives.signal, "SIGKILL", 9, raising=False)
    archives._kill_tree(process)
    killpg.assert_called_once_with(123, 9)
    process.kill.assert_called_once_with()
    process.wait.assert_called_once_with()


@pytest.fixture(autouse=True)
def system_temp(tmp_path, monkeypatch):
    """Point the system temp directory at tmp_path so cleanup can be observed."""
    root = tmp_path / "system-temp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def tar_config(**overrides):
    entry = {"command": "tar", "args": ["{archive}", "{tempdir}"], "copy_archive_to_tempdir": False}
    entry.update(overrides)
    return {"tar": entry}


class Runner:
    """Records the command and optionally runs a side effect inside the temp dir."""

    def __init__(self, effect=None, error=None):
        self.effect, self.error, self.commands = effect, error, []

    def __call__(self, cmd, check, capture_output, text):
        self.commands.append(cmd)
        if self.error:
            raise self.error
        if self.effect:
            self.effect(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_extract_archive_uses_system_temp_and_removes_it(tmp_path, system_temp):
    def effect(cmd):
        (Path(cmd[-1]) / "safe.txt").write_text("hello", encoding="utf-8")

    runner = Runner(effect)
    with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="fake"),
                                  LOGGER, runner=runner) as directory:
        assert Path(directory).parent == system_temp
        assert (Path(directory) / "safe.txt").read_text(encoding="utf-8") == "hello"
        kept = directory
    assert not Path(kept).exists()
    assert list(system_temp.iterdir()) == []


def test_extract_archive_formats_args_with_archive_and_tempdir(tmp_path):
    runner = Runner()
    config = tar_config(command="fake", args=["-x", "{archive}", "-C", "{tempdir}"])
    with archives.extract_archive(str(tmp_path / "a.tar"), config, LOGGER, runner=runner) as directory:
        assert runner.commands[0][1:] == ["-x", str(tmp_path / "a.tar"), "-C", directory]


def test_archive_type_argument_overrides_the_extension(tmp_path):
    """Content, not the extension, picks the extractor."""
    runner = Runner()
    config = {"zip": {"command": "unzip", "args": ["{archive}", "{tempdir}"]}}
    with archives.extract_archive(str(tmp_path / "mystery.dat"), config, LOGGER,
                                  archive_type="zip", runner=runner):
        assert "unzip" in Path(runner.commands[0][0]).name.lower()


def test_extract_archive_copies_archive_when_configured(tmp_path):
    gz_path = tmp_path / "dump.gz"
    with gzip.open(gz_path, "wb") as handle:
        handle.write(b"data")
    runner = Runner()
    config = {"gzip": {"command": "gzip", "args": ["-d", "{archive}"], "copy_archive_to_tempdir": True}}
    with archives.extract_archive(str(gz_path), config, LOGGER, runner=runner) as directory:
        copied = Path(runner.commands[0][-1])
        assert copied.name == "dump.gz" and copied.parent == Path(directory)
        assert copied.exists()
    assert not copied.parent.exists()


def test_failing_tool_raises_extractor_error_and_removes_dir(tmp_path, system_temp):
    def effect(cmd):
        raise subprocess.CalledProcessError(2, cmd, stderr="broken archive")

    runner = Runner(effect)
    with pytest.raises(ExtractorError, match="Extractor failed.*broken archive") as info:
        with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="fake"),
                                      LOGGER, runner=runner):
            pass
    assert not isinstance(info.value, ExtractorUnavailable)
    assert list(system_temp.iterdir()) == []


def test_unknown_type_is_unavailable(tmp_path):
    with pytest.raises(ExtractorUnavailable, match="Unsupported archive type"):
        with archives.extract_archive(str(tmp_path / "data.rar"), {}, LOGGER):
            pass


def test_missing_extractor_entry_is_unavailable(tmp_path):
    with pytest.raises(ExtractorUnavailable, match="No extractor configured"):
        with archives.extract_archive(str(tmp_path / "a.zip"), {"tar": {}}, LOGGER):
            pass


def test_incomplete_extractor_is_unavailable(tmp_path):
    with pytest.raises(ExtractorUnavailable, match="Incomplete extractor configuration"):
        with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(args=[]), LOGGER):
            pass


def test_missing_command_is_unavailable(tmp_path, monkeypatch, system_temp):
    monkeypatch.setattr(archives.shutil, "which", lambda command: None)
    runner = Runner(error=FileNotFoundError("nope"))
    with pytest.raises(ExtractorUnavailable, match="Extractor command not found"):
        with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="not-installed"),
                                      LOGGER, runner=runner):
            pass
    assert list(system_temp.iterdir()) == []


def test_copy_failure_raises_extractor_error(tmp_path, system_temp):
    config = {"gzip": {"command": "gzip", "args": ["-d", "{archive}"], "copy_archive_to_tempdir": True}}
    with pytest.raises(ExtractorError, match="Cannot copy"):
        with archives.extract_archive(str(tmp_path / "missing.gz"), config, LOGGER, runner=Runner()):
            pass
    assert list(system_temp.iterdir()) == []



def test_other_extractors_keep_the_default_working_directory(tmp_path, monkeypatch):
    calls = []

    def fake_run_limited(cmd, directory, limits, cwd=None):
        calls.append(cwd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(archives, "_IS_WINDOWS", True)
    monkeypatch.setattr(archives, "run_limited", fake_run_limited)
    config = {"zip": {"command": "unzip", "args": ["{archive}", "-d", "{tempdir}"]}}
    with archives.extract_archive(str(tmp_path / "a.zip"), config, LOGGER):
        pass
    assert calls == [None]


# --- cleanup of read-only members ------------------------------------------------------------------------


def test_read_only_extracted_members_do_not_leave_the_temp_directory_behind(tmp_path, system_temp):
    """Windows cannot delete read-only files (and POSIX cannot delete inside a read-only directory)."""
    import stat

    def effect(cmd):
        locked = Path(cmd[-1]) / "locked"
        locked.mkdir()
        member = locked / "member.txt"
        member.write_text("read only", encoding="utf-8")
        os.chmod(member, stat.S_IREAD)
        os.chmod(locked, stat.S_IREAD | stat.S_IEXEC)

    runner = Runner(effect)
    with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="fake"), LOGGER, runner=runner):
        pass
    assert list(system_temp.iterdir()) == []
