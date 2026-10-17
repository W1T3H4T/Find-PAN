"""Tests for bin/purge-log-files.py: option-like names, the no-tool warning and the crashes found next to them."""

import importlib.util
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("purge_log_files", ROOT / "bin" / "purge-log-files.py")
purge = importlib.util.module_from_spec(spec)
sys.modules["purge_log_files"] = purge
spec.loader.exec_module(purge)


@pytest.fixture(autouse=True)
def logger(monkeypatch):
    monkeypatch.setattr(purge, "_LogObj", logging.getLogger("test.purge"))


def old_file(path: Path, days: int = 10) -> Path:
    path.write_text("old log", encoding="utf-8")
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))
    return path


def test_functions_work_when_imported_without_main(tmp_path):
    """Previously delete_file used a global that only __main__ set, and len(None) crashed."""
    target = old_file(tmp_path / "file-1.log")
    purge.delete_file(str(target), [False])
    assert not target.exists()


def test_without_a_secure_delete_tool_the_file_is_removed_with_a_clear_warning(tmp_path, caplog):
    target = old_file(tmp_path / "file-1.log")
    flag = [False]
    with caplog.at_level(logging.WARNING, logger="test.purge"):
        purge.delete_file(str(target), flag, secure_del_app=None)
    assert not target.exists() and flag == [True]
    assert "NOT securely" in caplog.text            # no false sense of security


def test_the_fallback_warning_is_reported_once_per_run(tmp_path, caplog):
    flag = [False]
    with caplog.at_level(logging.WARNING, logger="test.purge"):
        for name in ("file-1.log", "file-2.log"):
            purge.delete_file(str(old_file(tmp_path / name)), flag, secure_del_app=None)
    assert caplog.text.count("NOT securely") == 1


def test_secure_delete_command_is_a_flat_list_with_an_absolute_path(tmp_path, monkeypatch):
    target = old_file(tmp_path / "file-1.log")
    calls = []
    monkeypatch.setattr(purge.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0))
    purge.delete_file(str(target), [False], secure_del_app=["/usr/bin/shred", "-u"])
    assert calls == [["/usr/bin/shred", "-u", "--", str(target)]]
    assert all(isinstance(part, str) for part in calls[0])


def test_a_leading_dash_name_cannot_become_an_option(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    old_file(tmp_path / "-rf.log")
    calls = []
    monkeypatch.setattr(purge.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0))
    purge.delete_file("-rf.log", [False], secure_del_app=["shred", "-u"])
    assert os.path.isabs(calls[0][-1]) and "--" in calls[0]


def test_sdelete_style_tools_get_an_absolute_path_without_double_dash(tmp_path, monkeypatch):
    target = old_file(tmp_path / "file-1.log")
    calls = []
    monkeypatch.setattr(purge.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0))
    purge.delete_file(str(target), [False], secure_del_app=["C:/tools/sdelete64.exe"])
    assert calls == [["C:/tools/sdelete64.exe", str(target)]]


def test_a_failing_secure_delete_leaves_the_file_and_warns(tmp_path, monkeypatch, caplog):
    target = old_file(tmp_path / "file-1.log")

    def fail(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(purge.subprocess, "run", fail)
    with caplog.at_level(logging.WARNING, logger="test.purge"):
        purge.delete_file(str(target), [False], secure_del_app=["shred", "-u"])
    assert target.exists() and "Error during secure delete" in caplog.text


def test_a_vanished_file_does_not_abort_the_run(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="test.purge"):
        purge.delete_file(str(tmp_path / "already-gone.log"), [False], secure_del_app=None)
    assert "already-gone.log" in caplog.text


def test_process_log_dir_only_removes_old_files_with_the_prefix(tmp_path, monkeypatch):
    #   Windows reports creation time, which os.utime cannot set; age from the modification time instead.
    monkeypatch.setattr(purge, "get_file_age_in_days", lambda path: (time.time() - os.stat(path).st_mtime) / 86400)
    old = old_file(tmp_path / "file-old.log", days=30)
    fresh = old_file(tmp_path / "file-new.log", days=0)
    other = old_file(tmp_path / "other-old.log", days=30)
    purge.process_log_dir(str(tmp_path), 7, "file-", None)
    assert not old.exists() and fresh.exists() and other.exists()


def test_find_secure_delete_program_returns_a_command_list_or_none(monkeypatch):
    monkeypatch.setattr(purge, "which", lambda tool: None)
    assert purge.find_secure_delete_program() is None
    monkeypatch.setattr(purge, "which", lambda tool: f"/bin/{tool}")
    found = purge.find_secure_delete_program()
    assert found is None or isinstance(found, list)
