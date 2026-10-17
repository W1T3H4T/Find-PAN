#!/usr/bin/env python3
"""Validate synthetic PAN generation against every configured PAN regex."""

import importlib.util
import random
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "bin" / "generate-pan.py"
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"

specification = importlib.util.spec_from_file_location("generate_pan", GENERATOR_PATH)
generator = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = generator
specification.loader.exec_module(generator)

patterns = generator.load_pan_patterns(CONFIGURATION_PATH)
random_source = random.Random(0)

for pattern_name, pattern_data in patterns.items():
    generated_pans = generator.generate_pans(pattern_name, pattern_data, random_source)
    assert len(generated_pans) == len(pattern_data["regex"])

    for generated_pan in generated_pans:
        assert re.fullmatch(generated_pan.regex, generated_pan.pan)
        assert generator.luhn_check(generated_pan.pan)

print("test_generate_pan.py: All configured PAN regexes generated valid Luhn PANs!")
