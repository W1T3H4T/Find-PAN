"""Tests for find_pan.redact."""

from find_pan import redact
from find_pan.models import Match, MatchKind

PAN = "4556737586899855"
OTHER_PAN = "4012888888881881"


def _match(matched, pan=PAN, line=None, kind=MatchKind.PAN):
    return Match("f.txt", 1, 0, kind, "VISA", r"\d+", matched, line or f"x {matched}\n", pan)


def test_mask_pan_keeps_first_six_and_last_four():
    assert redact.mask_pan(PAN) == "455673******9855"


def test_mask_pan_short_value_fully_masked():
    assert redact.mask_pan("123456789") == "*********"


def test_mask_matched_data_plain_pan_with_separators():
    assert redact.mask_matched_data("4556 7375 8689 9855", PAN) == "4556 73** **** 9855"


def test_mask_matched_data_track_fully_masked():
    assert redact.mask_matched_data(f";{PAN}=2512", PAN) == ";****************=****"


def test_mask_text_masks_every_long_digit_run():
    text = f"a {PAN} b {OTHER_PAN} c 12345"
    assert redact.mask_text(text) == "a 455673******9855 b 401288******1881 c 12345"


def test_apply_disabled_returns_identical_values():
    match = _match(PAN)
    view = redact.Redactor(False).apply(match)
    assert (view.matched_data, view.source_line, view.pan) == (PAN, match.source_line, PAN)


def test_apply_masks_matched_data_pan_and_source_line():
    view = redact.Redactor(True).apply(_match(PAN))
    assert PAN not in (view.matched_data, view.source_line, view.pan)
    assert view.pan == "455673******9855"


def test_apply_masks_other_long_digit_runs_in_source_line():
    match = _match(PAN, line=f"{PAN} then {OTHER_PAN}\n")
    view = redact.Redactor(True).apply(match)
    assert PAN not in view.source_line
    assert OTHER_PAN not in view.source_line


def test_apply_masks_track_fully():
    track = f"%B{PAN}^DOE/JANE^25121010000?"
    view = redact.Redactor(True).apply(_match(track, kind=MatchKind.TRACK))
    assert PAN not in view.matched_data
    assert "2512" not in view.matched_data
    assert PAN not in view.source_line


def test_apply_does_not_mutate_input_match():
    match = _match(PAN)
    redact.Redactor(True).apply(match)
    assert match.matched_data == PAN and match.pan == PAN


def test_apply_preserves_other_fields():
    match = _match(PAN)
    view = redact.Redactor(True).apply(match)
    assert (view.file_path, view.line_number, view.offset, view.kind, view.pattern_name) == (
        "f.txt", 1, 0, MatchKind.PAN, "VISA")


def test_apply_masks_other_tracks_in_source_line():
    """Final-review finding 1: another match's track data must not survive in the line."""
    other = ";4012888888881881=2512101123?"
    line = f"x {PAN} {other} %B{OTHER_PAN}^DOE/JOHN^251210112345?\n"
    view = redact.Redactor(True).apply(_match(PAN, line=line))
    assert "2512101123" not in view.source_line
    assert "251210112345" not in view.source_line
    assert PAN not in view.source_line and OTHER_PAN not in view.source_line
    assert "DOE/JOHN" in view.source_line  # only digits are masked


def test_mask_text_masks_track_digits_of_any_length():
    assert redact.mask_text(";4012888888881881=2512?") == ";****************=****?"


def test_mask_text_masks_separator_formatted_cards():
    """Deferred minor 2: cards written with spaces or dashes are masked in logged lines."""
    assert redact.mask_text("a 5500-0000-0000-0004 b") == "a 5500-00**-****-0004 b"
    assert redact.mask_text("a 4556 7375 8689 9855 b") == "a 4556 73** **** 9855 b"
    assert redact.mask_text("amex 3782 822463 10005") == "amex 3782 82**** *0005"
    assert redact.mask_text("date 2024-01-15 and 1234 5678") == "date 2024-01-15 and 1234 5678"
