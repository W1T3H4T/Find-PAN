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
