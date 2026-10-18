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

        def from_buffer(self, buffer):
            if error:
                raise error
            return mime

    module = types.ModuleType("magic")
    module.Magic = Magic
    monkeypatch.setitem(sys.modules, "magic", module)





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


def test_reading_the_head_of_a_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        filetypes.read_head(str(tmp_path / "missing.bin"))


# --- a libmagic that crashes the interpreter must never be loaded in-process ---------------------------------------------------------


def no_magic_module(monkeypatch):
    """Make `magic` genuinely un-imported, as it is in a fresh run."""
    monkeypatch.delitem(sys.modules, "magic", raising=False)
    filetypes._libmagic_loads.cache_clear()


def test_a_libmagic_that_fails_its_probe_is_never_imported(tmp_path, monkeypatch, caplog):
    no_magic_module(monkeypatch)
    monkeypatch.setattr(filetypes, "_run_probe", lambda: False)
    target = tmp_path / "a.txt"
    target.write_text("hi", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=LOGGER.name):
        assert not filetypes.is_executable(str(target), LOGGER)
    assert "magic" not in sys.modules                              # the crashing import was never attempted
    assert "python-magic is not available" in caplog.text


def test_the_probe_result_is_remembered(monkeypatch):
    no_magic_module(monkeypatch)
    calls = []
    monkeypatch.setattr(filetypes, "_run_probe", lambda: calls.append(1) or True)
    assert filetypes._libmagic_loads() and filetypes._libmagic_loads()
    assert calls == [1]


def test_a_working_libmagic_passes_the_probe_and_is_then_imported(tmp_path, monkeypatch):
    no_magic_module(monkeypatch)
    monkeypatch.setattr(filetypes, "_run_probe", lambda: True)
    imported = []

    def fake_import(name, *args, **kwargs):
        imported.append(name)
        install_magic(monkeypatch, mime="application/x-dosexec")
        return sys.modules["magic"]

    monkeypatch.setattr(filetypes, "_import_module", fake_import)
    target = tmp_path / "a.exe"
    target.write_bytes(b"MZ")
    assert filetypes.is_executable(str(target), LOGGER)
    assert imported == ["magic"]


@pytest.mark.parametrize("result, expected", [
    (types.SimpleNamespace(returncode=0), True),
    (types.SimpleNamespace(returncode=1), False),
    (types.SimpleNamespace(returncode=-1073741819), False),        # Windows access violation (0xC0000005)
    (types.SimpleNamespace(returncode=-11), False),                # SIGSEGV
])
def test_the_probe_reads_the_child_exit_status(monkeypatch, result, expected):
    monkeypatch.setattr(filetypes.subprocess, "run", lambda *args, **kwargs: result)
    assert filetypes._run_probe() is expected


@pytest.mark.parametrize("error", [filetypes.subprocess.TimeoutExpired("x", 1), OSError("no interpreter")])
def test_a_probe_that_cannot_finish_counts_as_a_failure(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(filetypes.subprocess, "run", fail)
    assert filetypes._run_probe() is False


def test_the_probe_really_runs_in_a_child_process_and_does_not_import_magic_here(monkeypatch):
    seen = {}

    def spy(command, **kwargs):
        seen["command"] = command
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(filetypes.subprocess, "run", spy)
    assert filetypes._run_probe()
    assert seen["command"][0] == sys.executable and "import magic" in seen["command"][-1]


def test_the_unavailable_warning_is_logged_once_not_once_per_file(tmp_path, monkeypatch, caplog):
    monkeypatch.setitem(sys.modules, "magic", None)
    target = tmp_path / "a.txt"
    target.write_text("hi", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=LOGGER.name):
        for _ in range(5):
            filetypes.is_executable(str(target), LOGGER)
    assert caplog.text.count("python-magic is not available") == 1
