"""Shared fixtures for the Find-PAN test suite.

The application lives in the ``find_pan`` package (``src/``, put on the import
path by ``pythonpath`` in ``pyproject.toml``).  The helper scripts in ``bin/``
that have hyphenated names are loaded by path where a test needs them.

``python-magic`` is imported lazily by ``find_pan.filetypes``; tests that
exercise it install their own stub, so the real library (which can crash on a
broken libmagic) is never imported by the suite.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from find_pan.config import compile_regex_patterns

ROOT = Path(__file__).resolve().parents[1]
PAN_GENERATOR_PATH = ROOT / "bin" / "generate-pan.py"
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"


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


@pytest.fixture
def pattern_configuration(configuration_path) -> dict:
    """The parsed PAN regex configuration."""
    with configuration_path.open(encoding="utf-8") as configuration_file:
        return json.load(configuration_file)


@pytest.fixture
def compiled_patterns(pattern_configuration) -> list:
    """Scanner patterns compiled from the real configuration (no prefix)."""
    return compile_regex_patterns(pattern_configuration)
