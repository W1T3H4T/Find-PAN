"""Expected-value lists (--pan-list, --track-list): loading, finding and the ledger."""

import pytest

from find_pan import targets
from find_pan.errors import ConfigError
from find_pan.models import MatchKind

PAN = "4556737586899855"
OTHER = "5500000000000004"
TRACK2 = ";4556737586899855=25121010000012345678?"
TRACK1 = "%B4556737586899855^DOE/JOHN^25121010000012345678?"


def write(tmp_path, text, name="list.txt"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- loading -----------------------------------------------------------------------------------------------------


def test_a_pan_list_ignores_blank_lines_and_comments_and_strips_separators(tmp_path):
    path = write(tmp_path, f"# expected after authorization\n\n{PAN}\n  5500-0000 0000-0004  \n{PAN}\n")
    assert targets.load_pan_list(path) == (PAN, OTHER)               # separators stripped, duplicates dropped


@pytest.mark.parametrize("bad", ["12345", "4556 7375 abcd 9855", "45567375868998551234567"])
def test_a_pan_list_rejects_values_that_are_not_pans_naming_the_line(tmp_path, bad):
    path = write(tmp_path, f"{PAN}\n{bad}\n")
    with pytest.raises(ConfigError, match=r"list\.txt:2"):
        targets.load_pan_list(path)


def test_a_pan_list_with_no_values_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="no values"):
        targets.load_pan_list(write(tmp_path, "# nothing here\n\n"))


def test_a_missing_list_file_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        targets.load_pan_list(str(tmp_path / "absent.txt"))


def test_a_track_list_accepts_track_1_and_track_2(tmp_path):
    assert targets.load_track_list(write(tmp_path, f"{TRACK1}\n{TRACK2}\n")) == (TRACK1, TRACK2)


def test_a_track_list_rejects_text_that_is_not_track_data(tmp_path):
    with pytest.raises(ConfigError, match=r"list\.txt:2"):
        targets.load_track_list(write(tmp_path, f"{TRACK2}\nnot a track\n"))


# --- finding -----------------------------------------------------------------------------------------------------


def test_a_listed_pan_is_found_between_non_digits_only():
    expected = targets.Targets(pans=(PAN,))
    hits = expected.find(f"a {PAN} b {PAN}, x{PAN}")
    assert [(h.kind, h.value, h.start) for h in hits] == [
        (MatchKind.PAN, PAN, 2), (MatchKind.PAN, PAN, 2 + 16 + 3), (MatchKind.PAN, PAN, 2 + 16 + 3 + 16 + 3)]
    assert expected.find(f"9{PAN}") == [] and expected.find(f"{PAN}0") == []     # part of a longer number


def test_a_pan_that_passes_no_pattern_is_still_found():
    unusual = "9999999999999995"                                   # no brand range, but it is the listed value
    assert [h.value for h in targets.Targets(pans=(unusual,)).find(f"id={unusual};")] == [unusual]


def test_a_listed_track_is_found_as_literal_text_and_so_is_its_pan():
    expected = targets.Targets(pans=(PAN,), tracks=(TRACK2,))
    hits = expected.find(f"swipe {TRACK2} done")
    assert sorted((h.kind.value, h.value) for h in hits) == [("PAN", PAN), ("TRACK", TRACK2)]


def test_hits_are_returned_in_text_order():
    expected = targets.Targets(pans=(PAN, OTHER))
    assert [h.value for h in expected.find(f"{OTHER} {PAN}")] == [OTHER, PAN]


# --- the ledger --------------------------------------------------------------------------------------------------


def test_the_ledger_lists_every_expected_value_found_or_not():
    expected = targets.Targets(pans=(PAN, OTHER), tracks=(TRACK2,))
    ledger = targets.TargetLedger(expected)
    for number in range(5):
        ledger.record(MatchKind.PAN, PAN, f"a.txt:{number}:0")
    entries = ledger.entries()
    assert [(e.kind, e.value, e.count) for e in entries] == [
        (MatchKind.PAN, PAN, 5), (MatchKind.PAN, OTHER, 0), (MatchKind.TRACK, TRACK2, 0)]
    assert entries[0].locations == ["a.txt:0:0", "a.txt:1:0", "a.txt:2:0"]       # the first few only
    assert ledger.found(MatchKind.PAN) == 1 and ledger.total(MatchKind.PAN) == 2
    assert ledger.found(MatchKind.TRACK) == 0 and ledger.total(MatchKind.TRACK) == 1
