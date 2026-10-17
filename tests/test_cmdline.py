"""Tests for command-line argument handling in find-pan.py."""

import argparse
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIND_PAN_PATH = ROOT / "bin" / "find-pan.py"
PAN_CONFIG_PATH = ROOT / "bin" / "pan_config.py"


def _load_script_module(module_name: str, script_path: Path):
    """Load a repository script as a module without a package install."""
    specification = importlib.util.spec_from_file_location(module_name, script_path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture
def find_pan():
    """A freshly loaded find-pan.py module (magic stubbed, main not run)."""
    magic_stub = types.ModuleType("magic")

    class _StubMagic:
        def __init__(self, *args, **kwargs):
            pass

        def from_file(self, file_path):
            raise RuntimeError("magic is stubbed in tests")

    magic_stub.Magic = _StubMagic
    sys.modules["magic"] = magic_stub

    #   Ensure pan_config is importable before find-pan.py loads.
    _load_script_module("pan_config", PAN_CONFIG_PATH)
    return _load_script_module("find_pan", FIND_PAN_PATH)


@pytest.fixture
def scanner(find_pan, tmp_path):
    """find-pan.py with globals ready for isolated testing."""
    scanner = find_pan
    scanner._MatchCount.clear()
    scanner._LastReportDelta = 0

    arguments = {
        "path": None,
        "tar": None,
        "tar_tmp": str(tmp_path / "tar-tmp"),
        "log_dir": str(tmp_path / "logs"),
        "rgx_patterns": str(ROOT / "config" / "find-pan-regex.json"),
        "rgx_prefix": False,
        "skip_binary": False,
        "line_limit": 0,
        "report_delta": 500,
        "csv": None,
        "verbose": False,
        "debug": False,
        "version": False,
        "exception_test": False,
    }
    scanner._Args = argparse.Namespace(**arguments)

    scanner._TraceLogObj = logging.getLogger("find-pan-tests.trace")
    scanner._DefaultLogObj = logging.getLogger("find-pan-tests.default")
    return scanner


def test_process_cmdline_arguments_does_not_load_json_config(find_pan, monkeypatch):
    """BUG-006: building the parser must not call find_json_regex_config()."""
    calls = []

    def fake_find_json_regex_config():
        calls.append("find_json_regex_config")
        raise FileNotFoundError("config missing")

    monkeypatch.setattr(find_pan, "find_json_regex_config", fake_find_json_regex_config)

    parser = find_pan.process_cmdline_arguments()
    #   argparse defaults are evaluated when add_argument is called, but the
    #   default is now None, so no config lookup should occur during parser setup.
    assert calls == []

    args = parser.parse_args([])
    assert args.rgx_patterns is None
    assert calls == []


def test_version_path_works_without_json_config(find_pan, monkeypatch, tmp_path, capsys):
    """BUG-006: --version resolves the JSON config lazily and can still print."""
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    monkeypatch.setenv("HOME", str(tmp_path / "no-home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "no-home"))
    #   Point application root at an empty directory so no bundled config exists.
    monkeypatch.setattr(
        find_pan, "find_json_regex_config",
        lambda: (_ for _ in ()).throw(FileNotFoundError("no config")),
    )

    parser = find_pan.process_cmdline_arguments()
    args = parser.parse_args(["--version"])

    #   Simulate the __main__ version check without actually exiting.
    monkeypatch.setattr(parser, "exit", lambda status=0, message=None: None)
    if args.version:
        find_pan.print_version_info(parser)
        parser.exit()

    captured = capsys.readouterr()
    assert "v2.3.1" in captured.out


def test_rgx_patterns_resolved_after_parse_args(find_pan):
    """BUG-006: the default rgx_patterns is resolved lazily after parsing."""
    parser = find_pan.process_cmdline_arguments()
    args = parser.parse_args([])
    assert args.rgx_patterns is None

    #   After the __main__ style resolution the path should be set.
    args.rgx_patterns = find_pan.find_json_regex_config()
    assert Path(args.rgx_patterns).exists()


def test_pan_logger_handler_not_duplicated(scanner):
    """BUG-008: the PAN file handler must be added exactly once."""
    loggers = scanner.setup_custom_loggers()
    pan_logger = loggers["Log"]

    file_handlers = [
        handler for handler in pan_logger.handlers if isinstance(handler, logging.FileHandler)
    ]
    assert len(file_handlers) == 1, (
        f"BUG-008: expected one FileHandler for PAN logger, got {len(file_handlers)}"
    )


