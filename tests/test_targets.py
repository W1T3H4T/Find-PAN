"""Report filters (--pan-list, --track-list): loading, filtering and the ledger."""

import pytest

from find_pan import targets
from find_pan.errors import ConfigError
from find_pan.models import Match, MatchKind

PAN = "4556737586899855"
OTHER = "5500000000000004"
TRACK2 = ";4556737586899855=25121010000012345678?"
NL = chr(10)
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


def test_a_track_list_accepts_what_a_configured_track_pattern_matches(tmp_path, compiled_patterns):
    path = write(tmp_path, f"{TRACK1}{NL}{TRACK2}{NL}")
    assert targets.load_track_list(path, compiled_patterns) == (TRACK1, TRACK2)


@pytest.mark.parametrize("bad", ["not a track", ";abc=1?", f"x{TRACK2}", TRACK2[:-1]])
def test_a_track_list_rejects_text_no_configured_track_pattern_matches_whole(tmp_path, compiled_patterns, bad):
    with pytest.raises(ConfigError, match=r"list\.txt:2"):
        targets.load_track_list(write(tmp_path, f"{TRACK2}{NL}{bad}{NL}"), compiled_patterns)


def test_a_track_list_is_checked_against_the_patterns_it_is_given(tmp_path):
    with pytest.raises(ConfigError, match="not track data"):
        targets.load_track_list(write(tmp_path, f"{TRACK2}{NL}"), [])


# --- filtering ---------------------------------------------------------------------------------------------------


def hit(kind, pan=PAN, matched=None, line=3, offset=7, encoding="", path="a.txt"):
    return Match(path, line, offset, kind, "name", "pattern", matched or pan, "source", pan, encoding)


def test_a_pan_list_admits_listed_pans_only_and_tallies_them():
    ledger = targets.TargetLedger(targets.Targets(pans=(PAN,)))
    assert ledger.admit(hit(MatchKind.PAN, PAN))
    assert not ledger.admit(hit(MatchKind.PAN, OTHER))
    assert [(e.value, e.count) for e in ledger.entries()] == [(PAN, 1)]


def test_a_delimited_pan_is_admitted_by_its_compact_digits():
    ledger = targets.TargetLedger(targets.Targets(pans=(PAN,)))
    assert ledger.admit(hit(MatchKind.PAN, PAN, matched="4556-7375-8689-9855"))


def test_a_track_list_admits_listed_tracks_only():
    ledger = targets.TargetLedger(targets.Targets(tracks=(TRACK2,)))
    assert ledger.admit(hit(MatchKind.TRACK, PAN, matched=TRACK2))
    assert not ledger.admit(hit(MatchKind.TRACK, PAN, matched=TRACK1))


def test_each_list_filters_only_its_own_kind():
    pans_only = targets.TargetLedger(targets.Targets(pans=(PAN,)))
    assert pans_only.admit(hit(MatchKind.TRACK, PAN, matched=TRACK2))
    tracks_only = targets.TargetLedger(targets.Targets(tracks=(TRACK2,)))
    assert tracks_only.admit(hit(MatchKind.PAN, OTHER))


@pytest.mark.parametrize("kind", [MatchKind.ANTI_PAN, MatchKind.BAD_LUHN])
def test_anti_pans_and_bad_luhn_matches_are_never_filtered(kind):
    ledger = targets.TargetLedger(targets.Targets(pans=(PAN,), tracks=(TRACK2,)))
    assert ledger.admit(hit(kind, ""))


def test_a_listed_value_that_was_never_matched_is_not_found():
    ledger = targets.TargetLedger(targets.Targets(pans=(PAN, OTHER), tracks=(TRACK2,)))
    ledger.admit(hit(MatchKind.PAN, PAN))
    assert [(e.kind, e.value, e.count) for e in ledger.entries()] == [
        (MatchKind.PAN, PAN, 1), (MatchKind.PAN, OTHER, 0), (MatchKind.TRACK, TRACK2, 0)]
    assert ledger.found(MatchKind.PAN) == 1 and ledger.total(MatchKind.PAN) == 2
    assert ledger.found(MatchKind.TRACK) == 0 and ledger.total(MatchKind.TRACK) == 1


def test_the_count_is_exact_and_only_the_first_locations_are_kept():
    ledger = targets.TargetLedger(targets.Targets(pans=(PAN,)))
    for number in range(5):
        ledger.admit(hit(MatchKind.PAN, PAN, line=number))
    [entry] = ledger.entries()
    assert entry.count == 5 and entry.locations == ["a.txt:0:7", "a.txt:1:7", "a.txt:2:7"]


def test_raw_locations_are_byte_offsets_with_the_encoding():
    ledger = targets.TargetLedger(targets.Targets(pans=(PAN,)))
    ledger.admit(hit(MatchKind.PAN, PAN, line=0, offset=255, encoding="utf-16", path="m.dmp"))
    assert ledger.entries()[0].locations == ["m.dmp@0xFF (utf-16)"]
