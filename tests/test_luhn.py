"""Tests for Luhn checksum validation in find-pan.py.

``luhn_check`` is the scanner's last line of defense against false
positives, and the repository carries two independent implementations
(find-pan.py and generate-pan.py).  These tests pin the known-valid cases
and guard the two implementations against drifting apart.
"""

import random

import pytest

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
def test_luhn_accepts_known_valid_pans(scanner, network, pan):
    assert scanner.luhn_check(pan)


@pytest.mark.parametrize(
    ("network", "pan"),
    DERIVED_INVALID_PANS,
    ids=[name for name, _ in DERIVED_INVALID_PANS],
)
def test_luhn_rejects_altered_check_digits(scanner, network, pan):
    assert not scanner.luhn_check(pan)


@pytest.mark.parametrize(
    ("network", "pan"),
    KNOWN_VALID_PANS,
    ids=[name for name, _ in KNOWN_VALID_PANS],
)
def test_luhn_rejects_transposed_digits(scanner, network, pan):
    """Swapping two distinct adjacent digits breaks the checksum.

    Equal adjacent digits are skipped: Luhn cannot detect that
    transposition (a known limitation of the algorithm).
    """
    if pan[0] == pan[1]:
        pytest.skip("Luhn cannot detect transposition of equal digits")
    transposed = pan[1] + pan[0] + pan[2:]
    assert not scanner.luhn_check(transposed)


def test_luhn_rejects_empty_and_all_zero_strings(scanner):
    """An empty or all-zero string has a zero checksum but is never a PAN."""
    assert not scanner.luhn_check("")
    assert not scanner.luhn_check("0")
    assert not scanner.luhn_check("00")
    assert not scanner.luhn_check("0000000000000000")


def test_luhn_raises_on_non_numeric_input(scanner):
    with pytest.raises(ValueError):
        scanner.luhn_check("4111-1111-1111-1111")


def test_luhn_accepts_every_generated_pan(scanner, pan_generator, configuration_path):
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
            assert scanner.luhn_check(generated_pan.pan), (
                f"Scanner rejected generated PAN {generated_pan.pan} "
                f"({pattern_name}, regex {generated_pan.regex_index})"
            )


def test_luhn_implementations_agree(scanner, pan_generator):
    """find-pan.py and generate-pan.py must never disagree on validity.

    The two implementations are maintained independently; this pins them
    to identical verdicts across a deterministic sample of digit strings
    (most of which are Luhn-invalid).
    """
    rng = random.Random(1)

    for _ in range(500):
        length = rng.randint(2, 19)
        digits = "".join(rng.choice("0123456789") for _ in range(length))
        assert scanner.luhn_check(digits) == pan_generator.luhn_check(digits), (
            f"Implementations disagree on {digits!r}"
        )