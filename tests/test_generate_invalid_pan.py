"""generate-invalid-pan.py: every value fits a PAN pattern, fails Luhn, and is counted as a Luhn failure."""

import importlib.util
import re
from pathlib import Path

from find_pan import detectors
from find_pan.models import MatchKind

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "generate-invalid-pan.py"


def load():
    spec = importlib.util.spec_from_file_location("generate_invalid_pan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_generated_value_is_reported_as_exactly_one_luhn_failure(compiled_patterns):
    values = list(load().generate(600))
    assert len(values) == 600
    for value in values:
        digits = re.sub(r"[ -]", "", value)
        assert not detectors.luhn_check(digits)
        found = detectors.scan_line("f", 1, value, compiled_patterns)
        assert [m.kind for m in found] == [MatchKind.BAD_LUHN], value


def test_the_values_cover_every_separator_style():
    values = list(load().generate(30))
    assert any(" " in v for v in values) and any("-" in v for v in values) and any(v.isdigit() for v in values)


def test_the_shipped_regression_file_has_5000_lines_that_all_fail_luhn(compiled_patterns):
    path = Path(__file__).resolve().parents[1] / "RegressionTests" / "Invalid-PAN.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5000
    failures = sum(
        [m.kind for m in detectors.scan_line("f", n, line, compiled_patterns)] == [MatchKind.BAD_LUHN]
        for n, line in enumerate(lines, 1))
    assert failures == 5000


def test_a_value_that_another_pattern_reports_as_a_pan_is_rejected(compiled_patterns):
    """A Luhn failure can contain a shorter number that is a PAN; such a value is not a clean invalid PAN."""
    generator = load()
    for value in ("356390065567496961", "3063 9373 9271 6039 90", "6226-3949-3248-0903-215"):
        assert not generator.confirmed(value, compiled_patterns)
    assert generator.confirmed("4556737586899850", compiled_patterns)
