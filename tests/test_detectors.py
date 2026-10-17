"""Tests for find_pan.detectors: Luhn validation and per-line scanning.

``luhn_check`` is the scanner's last line of defense against false
positives, and the repository carries two independent implementations
(find-pan.py and generate-pan.py).  These tests pin the known-valid cases
and guard the two implementations against drifting apart.
"""

import random

import pytest

from find_pan import detectors
from find_pan.models import MatchKind

#   Well-known industry test PANs, all Luhn-valid.  Note that several of
#   these (4111..., 4242..., 5555...) are deliberately swallowed by the
#   scanner's anti-PAN patterns; that is irrelevant to the Luhn check, which
#   is tested here in isolation.
KNOWN_VALID_PANS = [
    ("Visa", "4111111111111111"),
    ("Visa (Stripe)", "4242424242424242"),
    ("Mastercard (Stripe)", "5555555555554444"),
    ("American Express", "378282246310005"),
    ("American Express (alt)", "371449635398431"),
    ("Discover (Stripe)", "6011111111111117"),
    ("Diners Club", "30569309025904"),
    ("JCB (Stripe)", "3566002020360505"),
    ("Visa (commonly mistyped)", "4012888888881881"),
]

#   The same PANs with a mistyped check digit; changing the last digit by
#   five can never preserve the checksum.
DERIVED_INVALID_PANS = [
    (name, pan[:-1] + str((int(pan[-1]) + 5) % 10))
    for name, pan in KNOWN_VALID_PANS
]


@pytest.mark.parametrize(
    ("network", "pan"),
    KNOWN_VALID_PANS,
    ids=[name for name, _ in KNOWN_VALID_PANS],
)
def test_luhn_accepts_known_valid_pans(network, pan):
    assert detectors.luhn_check(pan)


@pytest.mark.parametrize(
    ("network", "pan"),
    DERIVED_INVALID_PANS,
    ids=[name for name, _ in DERIVED_INVALID_PANS],
)
def test_luhn_rejects_altered_check_digits(network, pan):
    assert not detectors.luhn_check(pan)


@pytest.mark.parametrize(
    ("network", "pan"),
    KNOWN_VALID_PANS,
    ids=[name for name, _ in KNOWN_VALID_PANS],
)
def test_luhn_rejects_transposed_digits(network, pan):
    """Swapping two adjacent digits breaks the checksum.

    Luhn cannot detect swapping equal digits (nothing changes) or swapping 0 and 9 (a known
    limitation of the algorithm), so the first adjacent pair that is neither is swapped.
    """
    index = next(i for i in range(len(pan) - 1)
                 if pan[i] != pan[i + 1] and {pan[i], pan[i + 1]} != {"0", "9"})
    transposed = pan[:index] + pan[index + 1] + pan[index] + pan[index + 2:]
    assert transposed != pan
    assert not detectors.luhn_check(transposed)


def test_luhn_cannot_detect_swapping_zero_and_nine():
    """Documents the algorithm's blind spot, which the transposition test above steers around."""
    for digits in ("1234095678901234", "5500090000000004", "0990099009900990", "4556737586890995"):
        assert "09" in digits
        assert detectors.luhn_check(digits) == detectors.luhn_check(digits.replace("09", "90", 1))


def test_luhn_rejects_empty_and_all_zero_strings():
    """An empty or all-zero string has a zero checksum but is never a PAN."""
    assert not detectors.luhn_check("")
    assert not detectors.luhn_check("0")
    assert not detectors.luhn_check("00")
    assert not detectors.luhn_check("0000000000000000")


def test_luhn_raises_on_non_numeric_input():
    with pytest.raises(ValueError):
        detectors.luhn_check("4111-1111-1111-1111")


def test_luhn_accepts_every_generated_pan(pan_generator, configuration_path):
    """Every PAN from the generator must pass the scanner's Luhn check.

    This is the end-to-end contract between generate-pan.py and find-pan.py:
    a synthetic PAN that the scanner rejects would break the test-data
    pipeline.
    """
    patterns = pan_generator.load_pan_patterns(configuration_path)
    rng = random.Random(0)

    for pattern_name, pattern_data in patterns.items():
        generated_pans = pan_generator.generate_pans(pattern_name, pattern_data, 1, rng)
        for generated_pan in generated_pans:
            assert detectors.luhn_check(generated_pan.pan), (
                f"Scanner rejected generated PAN {generated_pan.pan} "
                f"({pattern_name}, regex {generated_pan.regex_index})"
            )


def test_luhn_implementations_agree(pan_generator):
    """find-pan.py and generate-pan.py must never disagree on validity.

    The two implementations are maintained independently; this pins them
    to identical verdicts across a deterministic sample of digit strings
    (most of which are Luhn-invalid).
    """
    rng = random.Random(1)

    for _ in range(500):
        length = rng.randint(2, 19)
        digits = "".join(rng.choice("0123456789") for _ in range(length))
        assert detectors.luhn_check(digits) == pan_generator.luhn_check(digits), (
            f"Implementations disagree on {digits!r}"
        )

#   --- scan_line -------------------------------------------------------------

VALID_PAN = "4556737586899855"
BAD_PAN = "4556737586899856"      # VALID_PAN with the check digit changed
SECOND_PAN = "4012888888881881"
THIRD_PAN = "5424000000000015"


def _scan(line, compiled_patterns):
    return detectors.scan_line("sample.txt", 7, line, compiled_patterns)


def _kinds(matches):
    return [match.kind for match in matches]


def test_three_valid_pans_on_one_line(compiled_patterns):
    line = f"a {VALID_PAN} b {SECOND_PAN} c {THIRD_PAN}\n"
    matches = _scan(line, compiled_patterns)
    assert _kinds(matches) == [MatchKind.PAN] * 3
    assert sorted(m.offset for m in matches) == [2, 2 + 17 + 2, 2 + 17 + 2 + 17 + 2]
    assert all(m.file_path == "sample.txt" and m.line_number == 7 for m in matches)
    assert all(m.source_line == line for m in matches)
    assert {m.pan for m in matches} == {VALID_PAN, SECOND_PAN, THIRD_PAN}


def test_bad_luhn_does_not_hide_valid_pan(compiled_patterns):
    matches = _scan(f"{BAD_PAN} {VALID_PAN}\n", compiled_patterns)
    assert _kinds(matches).count(MatchKind.BAD_LUHN) == 1
    assert _kinds(matches).count(MatchKind.PAN) == 1
    bad = next(m for m in matches if m.kind is MatchKind.BAD_LUHN)
    assert bad.pan == BAD_PAN and bad.matched_data == BAD_PAN


def test_anti_pan_excludes_only_its_span(compiled_patterns):
    matches = _scan(f"123456789012345678 card {VALID_PAN}\n", compiled_patterns)
    assert _kinds(matches).count(MatchKind.ANTI_PAN) == 1
    assert _kinds(matches).count(MatchKind.PAN) == 1
    anti = next(m for m in matches if m.kind is MatchKind.ANTI_PAN)
    assert anti.pan == ""


def test_multiple_anti_pans_on_one_line(compiled_patterns):
    matches = _scan("123456789012345678 and 654321098765432109\n", compiled_patterns)
    assert _kinds(matches) == [MatchKind.ANTI_PAN] * 2


def test_same_bad_number_two_patterns_yields_one_bad_luhn(compiled_patterns):
    matches = _scan(f"{BAD_PAN}\n", compiled_patterns)
    assert _kinds(matches) == [MatchKind.BAD_LUHN]


def test_two_tracks_one_line(compiled_patterns):
    line = (";4556737586899855=25121010000000000000? "
            ";4012888888881881=25121010000000000000?\n")
    matches = _scan(line, compiled_patterns)
    assert _kinds(matches) == [MatchKind.TRACK] * 2
    assert [m.pan for m in matches] == [VALID_PAN, SECOND_PAN]


def test_track1_pan_extracted_without_framing():
    assert detectors.extract_pan("%B4556737586899855^DOE/JANE^25121010000?") == VALID_PAN
    assert detectors.extract_pan(";4556737586899855=2512101?") == VALID_PAN
    assert detectors.extract_pan("4556 7375 8689 9855") == VALID_PAN


def test_invalid_timestamp_is_not_anti_pan(compiled_patterns):
    # 14 digits that look like a timestamp but are not a real date
    matches = _scan("ts 20991399999999 end\n", compiled_patterns)
    assert MatchKind.ANTI_PAN not in _kinds(matches)


def test_valid_timestamp_function():
    assert detectors.valid_timestamp("20240115123045")
    assert not detectors.valid_timestamp("20241301123045")
    assert not detectors.valid_timestamp("1234")


def test_unknown_category_raises_value_error():
    import re

    patterns = [("Mystery Pattern", "x", re.compile("x"))]
    with pytest.raises(ValueError):
        detectors.scan_line("f", 1, "x", patterns)


def test_line_without_matches_returns_empty_list(compiled_patterns):
    assert _scan("nothing to see here\n", compiled_patterns) == []
