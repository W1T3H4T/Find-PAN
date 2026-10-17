"""Tests for processing the PAN regex configuration."""

import importlib.util
import json
import random
import re
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"
GENERATOR_PATH = ROOT / "bin" / "generate-pan.py"


@pytest.fixture(scope="module")
def pan_generator():
    """Load the PAN generator module without requiring a package installation."""
    specification = importlib.util.spec_from_file_location("generate_pan", GENERATOR_PATH)
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_regex_configuration_loads_and_compiles():
    """Every configured regex section loads and compiles successfully."""
    with CONFIGURATION_PATH.open(encoding="utf-8") as configuration_file:
        configuration = json.load(configuration_file)

    for section_name in ("Anti-PAN Pattern", "TRACK Pattern", "PAN Pattern"):
        patterns = configuration[section_name]
        assert patterns
        for pattern_data in patterns.values():
            assert pattern_data["regex"]
            for regex in pattern_data["regex"]:
                re.compile(regex)


def test_pan_regex_configuration_is_processed(pan_generator):
    """Every configured PAN regex generates a matching, Luhn-valid PAN."""
    patterns = pan_generator.load_pan_patterns(CONFIGURATION_PATH)
    random_source = random.Random(0)

    assert patterns
    for pattern_name, pattern_data in patterns.items():
        generated_pans = pan_generator.generate_pans(pattern_name, pattern_data, random_source)

        assert len(generated_pans) == len(pattern_data["regex"])
        for generated_pan in generated_pans:
            assert re.fullmatch(generated_pan.regex, generated_pan.pan)
            assert pan_generator.luhn_check(generated_pan.pan)
