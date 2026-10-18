"""--raw, --raw-encodings, --pan-list and --track-list through the command line."""

import csv
import json
import zipfile

import pytest

from find_pan import cli

PAN = "4556737586899855"
OTHER = "4012888888881881"
ABSENT = "5500000000000004"
TRACK2 = ";4556737586899855=25121010000012345678?"
FF = bytes([0xFF])


def run(tmp_path, capsys, *arguments):
    status = cli.main([*arguments, "--log-dir", str(tmp_path / "logs")])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def dump(tmp_path, *parts, name="memory.dmp"):
    path = tmp_path / name
    path.write_bytes(b"".join(parts))
    return str(path)


def list_file(tmp_path, name, *values):
    path = tmp_path / name
    path.write_text("\n".join(values) + "\n", encoding="utf-8")
    return str(path)


# --- options -----------------------------------------------------------------------------------------------------


def test_defaults_leave_raw_mode_and_lists_off():
    settings = cli.parse_args(["--path", "p"])
    assert not settings.raw and settings.pan_list is None and settings.track_list is None
    assert settings.raw_encodings == ("ascii", "utf-16")


def test_the_options_are_parsed():
    settings = cli.parse_args(["--file", "a", "--raw", "--raw-encodings", "ascii",
                               "--pan-list", "p.txt", "--track-list", "t.txt"])
    assert settings.raw and settings.raw_encodings == ("ascii",)
    assert (settings.pan_list, settings.track_list) == ("p.txt", "t.txt")


def test_an_unknown_raw_encoding_is_a_usage_error(capsys):
    with pytest.raises(SystemExit):
        cli.parse_args(["--file", "a", "--raw", "--raw-encodings", "ebcdic"])
    assert "ebcdic" in capsys.readouterr().err


# --- raw scanning ------------------------------------------------------------------------------------------------


def test_a_dump_is_scanned_raw_and_reported_by_byte_offset(tmp_path, capsys):
    path = dump(tmp_path, FF * 40, b" pan=", PAN.encode(), b";", FF * 40,
                (" " + OTHER + " ").encode("utf-16-le"), FF * 8)
    csv_path = tmp_path / "out.csv"
    status, out, _ = run(tmp_path, capsys, "--file", path, "--raw", "--csv", str(csv_path))
    assert status == 0 and "PANs Matched  :        2" in out
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert sorted((row["matched_data"], row["line_number"]) for row in rows) == [(OTHER, "0"), (PAN, "0")]
    assert {row["offset"] for row in rows} == {str(45 + 0), str(40 + 5 + 16 + 1 + 40 + 2)}


def test_raw_scans_binary_data_even_with_skip_binary(tmp_path, capsys):
    path = dump(tmp_path, FF * 200, b" ", PAN.encode(), b" ")
    status, out, _ = run(tmp_path, capsys, "--file", path, "--raw", "--skip-binary")
    assert status == 0 and "PANs Matched  :        1" in out and "Skipped 0 Binary Files" in out


def test_raw_does_not_expand_archives_it_scans_their_bytes(tmp_path, capsys):
    path = tmp_path / "stored.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as handle:
        handle.writestr("card.txt", f"card {PAN}\n")
    status, out, _ = run(tmp_path, capsys, "--file", str(path), "--raw")
    assert status == 0 and "PANs Matched  :        1" in out and "Archives expanded" not in out


def test_raw_applies_to_every_file_under_path(tmp_path, capsys):
    folder = tmp_path / "evidence"
    folder.mkdir()
    (folder / "a.bin").write_bytes(FF * 8 + PAN.encode() + FF * 8)
    (folder / "b.bin").write_bytes(FF * 8 + OTHER.encode() + FF * 8)
    status, out, _ = run(tmp_path, capsys, "--path", str(folder), "--raw")
    assert status == 0 and "PANs Matched  :        2" in out


def test_verbose_shows_the_byte_offset_and_encoding(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", PAN.encode(), b" ", FF * 4)
    _, out, _ = run(tmp_path, capsys, "--file", path, "--raw", "--verbose")
    assert "Location: byte 5 (0x5, ascii)" in out


# --- expected values ---------------------------------------------------------------------------------------------


def test_the_summary_says_which_expected_values_were_found_and_which_were_not(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", PAN.encode(), b" ", FF * 8, b" ", PAN.encode(), b" ", FF * 4)
    pans = list_file(tmp_path, "pans.txt", PAN, ABSENT)
    status, out, _ = run(tmp_path, capsys, "--file", path, "--raw", "--pan-list", pans)
    assert status == 0
    assert "-- Expected Values --" in out
    assert "Expected PANs found  : 1 of 2" in out
    found = next(line for line in out.splitlines() if PAN in line and "FOUND" in line and "NOT" not in line)
    assert "2 times" in found and "memory.dmp@0x5 (ascii)" in found
    assert next(line for line in out.splitlines() if ABSENT in line).endswith("NOT FOUND")


def test_expected_tracks_are_listed_too(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", TRACK2.encode(), b" ", FF * 4)
    tracks = list_file(tmp_path, "tracks.txt", TRACK2)
    _, out, _ = run(tmp_path, capsys, "--file", path, "--raw", "--track-list", tracks)
    assert "Expected TRACKs found: 1 of 1" in out and "1 time" in out


def test_no_expected_section_without_a_list(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", PAN.encode(), b" ", FF * 4)
    _, out, _ = run(tmp_path, capsys, "--file", path, "--raw")
    assert "Expected Values" not in out


def test_lists_also_work_on_ordinary_text_files(tmp_path, capsys):
    text = tmp_path / "log.txt"
    text.write_text(f"first\nthe card {PAN} again {PAN}\n", encoding="utf-8")
    pans = list_file(tmp_path, "pans.txt", PAN, ABSENT)
    _, out, _ = run(tmp_path, capsys, "--file", str(text), "--pan-list", pans)
    found = next(line for line in out.splitlines() if PAN in line and "FOUND" in line and "NOT" not in line)
    assert "2 times" in found and "log.txt:2:9" in found


def test_a_listed_value_no_pattern_recognises_is_reported_as_a_pan(tmp_path, capsys):
    unusual = "9999999999999995"
    text = tmp_path / "log.txt"
    text.write_text(f"id {unusual}\n", encoding="utf-8")
    _, out, _ = run(tmp_path, capsys, "--file", str(text), "--pan-list", list_file(tmp_path, "p.txt", unusual))
    assert "PANs Matched  :        1" in out


def test_mask_applies_to_the_expected_value_report(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", PAN.encode(), b" ", FF * 4)
    status, out, _ = run(tmp_path, capsys, "--file", path, "--raw", "--mask",
                         "--pan-list", list_file(tmp_path, "p.txt", PAN, ABSENT),
                         "--track-list", list_file(tmp_path, "t.txt", TRACK2))
    assert PAN not in out and ABSENT not in out and TRACK2 not in out
    assert "455673******9855" in out and "550000******0004" in out


def test_summary_json_carries_the_expected_values(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", PAN.encode(), b" ", FF * 4)
    summary = tmp_path / "summary.json"
    run(tmp_path, capsys, "--file", path, "--raw", "--summary-json", str(summary),
        "--pan-list", list_file(tmp_path, "p.txt", PAN, ABSENT))
    expected = json.loads(summary.read_text(encoding="utf-8"))["expected"]
    found, absent = expected["pans"]
    assert (found["value"], found["found"]) == (PAN, 1) and found["locations"][0].endswith("memory.dmp@0x5 (ascii)")
    assert absent == {"value": ABSENT, "found": 0, "locations": []}
    assert expected["tracks"] == []


def test_summary_json_has_no_expected_section_without_lists(tmp_path, capsys):
    path = dump(tmp_path, FF * 4, b" ", PAN.encode(), b" ", FF * 4)
    summary = tmp_path / "summary.json"
    run(tmp_path, capsys, "--file", path, "--raw", "--summary-json", str(summary))
    assert "expected" not in json.loads(summary.read_text(encoding="utf-8"))


def test_a_bad_list_file_stops_the_run_with_a_message(tmp_path, capsys):
    path = dump(tmp_path, PAN.encode())
    status, out, err = run(tmp_path, capsys, "--file", path, "--raw", "--pan-list",
                           list_file(tmp_path, "p.txt", PAN, "oops"))
    assert status == 1 and "p.txt:2" in err and "PANs Matched" not in out


def test_a_missing_list_file_stops_the_run_with_a_message(tmp_path, capsys):
    path = dump(tmp_path, PAN.encode())
    status, _, err = run(tmp_path, capsys, "--file", path, "--track-list", str(tmp_path / "nope.txt"))
    assert status == 1 and "cannot read" in err
