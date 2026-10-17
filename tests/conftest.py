"""Shared fixtures for the Find-PAN test suite.

bin/find-pan.py cannot be imported directly (hyphenated file name), so the
``find_pan`` fixture loads it via importlib.  Each test gets a fresh module
instance, which isolates the module-level globals (``_Args``, ``_MatchCount``,
``_TraceLogObj``) without any monkeypatching.

find-pan.py imports python-magic at module scope, and importing the real
``magic`` can crash in environments with a broken libmagic (it segfaults on
the repository's own Windows dev machine).  A deterministic stub is installed
in ``sys.modules`` before the module loads; tests that care about MIME
detection should configure or replace the stub explicitly.
"""

import argparse
import importlib.util
import json
import logging
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIND_PAN_PATH = ROOT / "bin" / "find-pan.py"
PAN_CONFIG_PATH = ROOT / "bin" / "pan_config.py"
PAN_GENERATOR_PATH = ROOT / "bin" / "generate-pan.py"
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"

#   Default argument values, mirroring process_cmdline_arguments() in
#   find-pan.py.  Path arguments are filled in per test via tmp_path.
DEFAULT_ARGUMENTS = {
    "path": None,
    "tar": None,
    "tar_tmp": "",
    "log_dir": "",
    "rgx_patterns": str(CONFIGURATION_PATH),
    "rgx_prefix": False,
    "skip_binary": False,
    "line_limit": 0,
    "report_delta": 500,
    "csv": None,
    "verbose": False,
    "debug": False,
    "mask": False,
    "version": False,
    "exception_test": False,
}


class _StubMagic:
    """Minimal stand-in for magic.Magic; refuses if actually used."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def from_file(self, file_path):
        raise RuntimeError(
            f"MIME detection is stubbed out in tests (tried to inspect {file_path!r})."
        )


_MAGIC_STUB = types.ModuleType("magic")
_MAGIC_STUB.Magic = _StubMagic


def load_script_module(module_name: str, script_path: Path):
    """Load a repository script as a module without a package install."""
    specification = importlib.util.spec_from_file_location(module_name, script_path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def configuration_path() -> Path:
    """Path to the PAN regex configuration shared by the tools."""
    return CONFIGURATION_PATH


@pytest.fixture(scope="session")
def pan_generator():
    """Load the PAN generator module without a package installation."""
    return load_script_module("pan_generator", PAN_GENERATOR_PATH)


@pytest.fixture(scope="session")
def pan_config():
    """Load the pan_config module without requiring a package installation."""
    return load_script_module("pan_config", PAN_CONFIG_PATH)


@pytest.fixture
def find_pan(pan_config):
    """A freshly loaded find-pan.py module (magic stubbed, main not run).

    Depends on ``pan_config`` so the configuration helper module is already
    present in ``sys.modules`` before find-pan.py tries to import it.
    """
    sys.modules["magic"] = _MAGIC_STUB
    return load_script_module("find_pan", FIND_PAN_PATH)


@pytest.fixture
def pattern_configuration(configuration_path) -> dict:
    """The parsed PAN regex configuration."""
    with configuration_path.open(encoding="utf-8") as configuration_file:
        return json.load(configuration_file)


@pytest.fixture
def scanner(find_pan, tmp_path):
    """find-pan.py with globals ready for isolated testing.

    Resets the match counters, points ``_Args`` at tmp_path, and installs
    quiet loggers so tests can assert on state without console noise.
    """
    scanner = find_pan
    scanner._MatchCount.clear()
    scanner._LastReportDelta = 0

    arguments = dict(
        DEFAULT_ARGUMENTS,
        tar_tmp=str(tmp_path / "tar-tmp"),
        log_dir=str(tmp_path / "logs"),
    )
    scanner._Args = argparse.Namespace(**arguments)

    scanner._TraceLogObj = logging.getLogger("find-pan-tests.trace")
    scanner._DefaultLogObj = logging.getLogger("find-pan-tests.default")
    return scanner


@pytest.fixture
def compiled_patterns(pan_config, pattern_configuration) -> list:
    """Scanner patterns compiled from the real configuration (no prefix)."""
    return pan_config.compile_regex_patterns(pattern_configuration)