"""Tests for find_pan.filetypes."""

import logging
import sys
import types

import pytest

from find_pan import filetypes

LOGGER = logging.getLogger("test.filetypes")


def install_magic(monkeypatch, mime=None, error=None):
    class Magic:
        def __init__(self, *args, **kwargs):
            pass

        def from_file(self, path):
            if error:
                raise error
            return mime

    module = types.ModuleType("magic")
    module.Magic = Magic
    monkeypatch.setitem(sys.modules, "magic", module)



def test_binary_content_needs_both_nul_and_ff(tmp_path):
    both = tmp_path / "both.bin"
    both.write_bytes(b"abc\x00def\xffghi" + b"x" * 20)
    only_nul = tmp_path / "nul.bin"
    only_nul.write_bytes(b"abc\x00def" + b"x" * 20)
    text = tmp_path / "text.txt"
    text.write_text("plain text\n", encoding="utf-8")
    assert filetypes.has_binary_content(str(both))
    assert not filetypes.has_binary_content(str(only_nul))
    assert not filetypes.has_binary_content(str(text))



def test_executable_detected_via_stubbed_magic(tmp_path, monkeypatch):
    install_magic(monkeypatch, mime="application/x-dosexec")
    target = tmp_path / "prog.exe"
    target.write_bytes(b"MZ")
    assert filetypes.is_executable(str(target), LOGGER)


def test_text_file_not_executable(tmp_path, monkeypatch):
    install_magic(monkeypatch, mime="text/plain")
    target = tmp_path / "a.txt"
    target.write_text("hi", encoding="utf-8")
    assert not filetypes.is_executable(str(target), LOGGER)


def test_magic_import_error_returns_false_and_warns(tmp_path, monkeypatch, caplog):
    monkeypatch.setitem(sys.modules, "magic", None)  # makes `import magic` raise ImportError
    target = tmp_path / "a.txt"
    target.write_text("hi", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=LOGGER.name):
        assert not filetypes.is_executable(str(target), LOGGER)
    assert "python-magic is not available" in caplog.text


def test_magic_failure_falls_back_with_warning(tmp_path, monkeypatch, caplog):
    install_magic(monkeypatch, error=RuntimeError("libmagic broke"))
    target = tmp_path / "a.txt"
    target.write_text("hi", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=LOGGER.name):
        assert not filetypes.is_executable(str(target), LOGGER)
    assert "using fallback" in caplog.text


def test_unreadable_binary_check_propagates_oserror(tmp_path):
    with pytest.raises(OSError):
        filetypes.has_binary_content(str(tmp_path / "missing.bin"))
