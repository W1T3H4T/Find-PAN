"""Tests for find-pan.py --csv output."""

import csv

import pytest


@pytest.fixture
def scan_tree(tmp_path):
    """Return a subdirectory to scan, keeping output files outside of it."""
    tree = tmp_path / "scan"
    tree.mkdir()
    return tree


@pytest.fixture
def make_pan_file(scan_tree):
    """Create a file containing a known Luhn-valid PAN and return its path."""
    target = scan_tree / "sample.txt"
    target.write_text("Card: 4556737586899855\n", encoding="utf-8")
    return target


def test_csv_output_contains_header_and_match(scanner, make_pan_file, tmp_path, monkeypatch):
    csv_file = tmp_path / "matches.csv"
    scanner._Args.path = str(make_pan_file.parent)
    scanner._Args.csv = str(csv_file)

    scanner.main()

    assert csv_file.exists()
    rows = list(csv.reader(csv_file.read_text(encoding="utf-8").splitlines()))
    header = rows[0]
    assert header == ["filename", "line_number", "offset", "pattern_name", "data_type", "matched_data"]

    data_rows = rows[1:]
    assert len(data_rows) == 1
    filename, line_number, offset, pattern_name, data_type, matched_data = data_rows[0]
    assert filename == "sample.txt"
    assert int(line_number) == 1
    assert int(offset) == 6
    assert data_type == "PAN"
    assert matched_data == "4556737586899855"


def test_csv_output_is_ascii_only(scanner, scan_tree, tmp_path, monkeypatch):
    target = scan_tree / "binary-sample.txt"
    target.write_bytes(b"PAN: 4556737586899855\x00\xff\n")
    csv_file = tmp_path / "matches.csv"
    scanner._Args.path = str(scan_tree)
    scanner._Args.csv = str(csv_file)

    scanner.main()

    assert csv_file.exists()
    rows = list(csv.reader(csv_file.read_text(encoding="utf-8").splitlines()))
    _, _, _, _, _, matched_data = rows[1]
    assert matched_data.isascii()


def test_csv_row_uses_filename_not_full_path(scanner, make_pan_file, tmp_path, monkeypatch):
    csv_file = tmp_path / "matches.csv"
    scanner._Args.path = str(make_pan_file.parent)
    scanner._Args.csv = str(csv_file)

    scanner.main()

    rows = list(csv.reader(csv_file.read_text(encoding="utf-8").splitlines()))
    _, _, _, _, _, matched_data = rows[1]
    assert "\x00" not in matched_data
    assert "\xff" not in matched_data
    filename = rows[1][0]
    assert filename == "sample.txt"
    assert not str(tmp_path) in filename


def test_log_output_includes_line_number_and_offset(scanner, make_pan_file, tmp_path, monkeypatch, caplog):
    scanner._Args.path = str(make_pan_file.parent)
    scanner._Args.csv = str(tmp_path / "matches.csv")

    with caplog.at_level("INFO", logger=scanner._DefaultLogObj.name):
        scanner.main()

    pan_messages = [rec for rec in caplog.records if "->" in rec.getMessage() and "PAN" in rec.getMessage()]
    assert len(pan_messages) == 1
    message = pan_messages[0].getMessage()
    assert "sample.txt" in message
    assert ":1:" in message
    assert ":6->" in message
