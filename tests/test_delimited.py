"""PANs written with spaces or hyphens (4556-7375-8689-9855) are normalized, then matched as usual."""

import json
import re
from pathlib import Path

import pytest

from find_pan import detectors
from find_pan.models import MatchKind

CONFIGURATION_PATH = Path(__file__).resolve().parents[1] / "config" / "find-pan-regex.json"
PAN = "4556737586899855"
SECOND = "4012888888881881"
AMEX = "371449635398431"
DINERS = "30569309025904"
TRACK2 = ";4556737586899855=25121010000012345678?"


def scan(patterns, line):
    return detectors.scan_line("f.txt", 1, line, patterns)


def pans(patterns, line):
    return [m for m in scan(patterns, line) if m.kind is MatchKind.PAN]


def group(digits, sizes, separator):
    parts, start = [], 0
    for size in sizes:
        parts.append(digits[start:start + size])
        start += size
    return separator.join(parts)


# --- configuration -----------------------------------------------------------------------------------------------


def test_the_regex_file_defines_delimited_candidates_that_compile():
    configuration = json.loads(CONFIGURATION_PATH.read_text(encoding="utf-8"))
    entries = configuration[detectors.DELIMITED_CATEGORY]
    assert entries
    for entry in entries.values():
        for regex in entry["regex"]:
            re.compile(regex)


# --- normalization -----------------------------------------------------------------------------------------------


def test_normalization_removes_separators_and_remembers_original_positions(compiled_patterns):
    line = f"id {group(PAN, (4, 4, 4, 4), '-')} end"
    normalized = detectors.normalize(line, compiled_patterns)
    assert normalized.text == f"id {PAN} end"
    assert normalized.start(3) == 3 and normalized.end(3 + 16) == 3 + 19        # the PAN's span in the original
    assert normalized.start(0) == 0 and normalized.end(2) == 2                  # untouched text maps to itself


def test_text_without_a_delimited_candidate_is_unchanged(compiled_patterns):
    line = f"no change {PAN} 12-34 56"
    normalized = detectors.normalize(line, compiled_patterns)
    assert normalized.text == line


# --- detection ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("separator", ["-", " "])
def test_a_delimited_pan_is_reported_with_its_original_text_and_compact_digits(compiled_patterns, separator):
    line = f"card {group(PAN, (4, 4, 4, 4), separator)} on file"
    [match] = pans(compiled_patterns, line)
    assert (match.matched_data, match.pan, match.offset) == (group(PAN, (4, 4, 4, 4), separator), PAN, 5)
    assert match.source_line == line and match.line_number == 1


@pytest.mark.parametrize("digits, sizes", [(AMEX, (4, 6, 5)), (DINERS, (4, 6, 4)), ("4556737586899855006", (4, 4, 4, 4, 3))])
def test_other_layouts_are_recognised(compiled_patterns, digits, sizes):
    detected = pans(compiled_patterns, f"x {group(digits, sizes, '-')} y")
    assert [m.pan for m in detected] == [digits]


def test_the_ordinary_pattern_decides_which_numbers_are_pans(compiled_patterns):
    assert pans(compiled_patterns, "number 5000-0000-0000-0009 here") == []         # Luhn-valid, no brand pattern


def test_a_luhn_failure_is_not_a_pan_exactly_as_for_contiguous_digits(compiled_patterns):
    bad = PAN[:-1] + "0"
    delimited = scan(compiled_patterns, f"x {group(bad, (4, 4, 4, 4), '-')} y")
    contiguous = scan(compiled_patterns, f"x {bad} y")
    assert [m.kind for m in delimited] == [m.kind for m in contiguous] == [MatchKind.BAD_LUHN]


def test_mixed_separators_are_not_a_delimited_pan(compiled_patterns):
    assert scan(compiled_patterns, "x 4556-7375 8689-9855 y") == []


def test_an_anti_pan_pattern_applies_to_the_normalized_digits(compiled_patterns):
    sequential = "1234567890123456789"
    found = scan(compiled_patterns, f"x {group(sequential, (4, 4, 4, 4, 3), '-')} y")
    assert [m.kind for m in found] == [MatchKind.ANTI_PAN]
    assert found[0].matched_data == "1234-5678-9012-3456-789"


def test_positions_after_an_earlier_normalization_are_original_positions(compiled_patterns):
    first, second = group(PAN, (4, 4, 4, 4), "-"), group(SECOND, (4, 4, 4, 4), " ")
    line = f"{first} then {PAN} and {second}"
    found = pans(compiled_patterns, line)
    assert [(m.matched_data, m.offset) for m in found] == [
        (first, 0), (PAN, line.index(PAN, 20)), (second, line.index(second))]


# --- track data is not affected ----------------------------------------------------------------------------------


def test_track_patterns_see_the_original_text_only(compiled_patterns):
    spaced = TRACK2.replace("4556737586899855", group(PAN, (4, 4, 4, 4), "-"))
    assert MatchKind.TRACK not in [m.kind for m in scan(compiled_patterns, spaced)]


def test_no_pan_is_found_inside_track_data(compiled_patterns):
    found = scan(compiled_patterns, f"swipe {TRACK2} done")
    assert [m.kind for m in found] == [MatchKind.TRACK]
