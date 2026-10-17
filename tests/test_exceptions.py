"""Tests for bin/find-pan.py exception reporting."""

import pytest


def test_print_exception_info_accepts_none(find_pan, monkeypatch, capsys):
    """BUG-002: the handler must not crash when called with None."""
    monkeypatch.setattr(find_pan.sys, "exit", lambda code: None)
    find_pan.print_exception_info(None)
    captured = capsys.readouterr()
    assert "Exception Information:" in captured.out


def test_print_exception_info_works_without_program_name(find_pan, monkeypatch, capsys):
    """BUG-003: the handler must not depend on the late ProgramName global."""
    assert "ProgramName" not in find_pan.__dict__
    monkeypatch.setattr(find_pan.sys, "exit", lambda code: None)
    find_pan.print_exception_info("extra context")
    captured = capsys.readouterr()
    assert "Info    : extra context" in captured.out


def test_print_exception_info_reports_active_exception(find_pan, monkeypatch, capsys):
    """The handler reports the exception currently being handled."""
    monkeypatch.setattr(find_pan.sys, "exit", lambda code: None)
    try:
        raise ValueError("boom")
    except Exception as e:
        find_pan.print_exception_info(e)
    captured = capsys.readouterr()
    assert "Type    : ValueError" in captured.out
    assert "Message : boom" in captured.out


def test_print_exception_info_exits_with_one(find_pan):
    """The handler terminates the process with status 1."""
    with pytest.raises(SystemExit) as exc_info:
        find_pan.print_exception_info(None)
    assert exc_info.value.code == 1


def test_set_log_directory_initializes_variables_on_failure(scanner, monkeypatch):
    """BUG-007: failing log-dir creation must not raise UnboundLocalError."""
    import os as _os

    original_makedirs = _os.makedirs

    def failing_makedirs(path, exist_ok=False):
        if str(path).endswith("logs"):
            raise OSError("cannot create log directory")
        return original_makedirs(path, exist_ok=exist_ok)

    monkeypatch.setattr(scanner.os, "makedirs", failing_makedirs)
    monkeypatch.setattr(scanner.sys, "exit", lambda code: None)

    scanner.set_log_directory_and_filenames()
    #   The function returns without raising UnboundLocalError; values are empty.
    captured = ""  # no assertion needed; reaching this line is the test
