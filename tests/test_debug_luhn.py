"""Tests for Luhn-failure reporting (--debug / --mask) in find-pan.py."""

import logging

import pytest

VALID_PAN = "4556737586899855"
BAD_PAN = "4556737586899856"   # VALID_PAN with the check digit changed


@pytest.fixture
def scan_file(scanner, compiled_patterns, tmp_path):
    """Scan one file with the given text; return the file path."""

    def scan(text: str):
        target = tmp_path / "sample.txt"
        target.write_text(text, encoding="utf-8")
        scanner.process_file(str(target), compiled_patterns)
        return target

    return scan


def luhn_messages(caplog):
    return [r.getMessage() for r in caplog.records if "Luhn failure" in r.getMessage()]


def test_luhn_failure_counted_and_logged_in_debug(scanner, scan_file, caplog):
    with caplog.at_level(logging.DEBUG, logger=scanner._TraceLogObj.name):
        scan_file(f"Card: {BAD_PAN}\n")

    assert scanner._MatchCount["BAD-LUHN"] >= 1
    assert scanner._MatchCount["PAN"] == 0
    messages = luhn_messages(caplog)
    assert messages
    assert "sample.txt" in messages[0]
    assert "line=1" in messages[0]
    assert "offset=6" in messages[0]
    assert BAD_PAN in messages[0]


def test_luhn_failure_not_logged_without_debug(scanner, scan_file, caplog):
    with caplog.at_level(logging.INFO, logger=scanner._TraceLogObj.name):
        scan_file(f"Card: {BAD_PAN}\n")

    assert scanner._MatchCount["BAD-LUHN"] >= 1
    assert not luhn_messages(caplog)


def test_bad_luhn_does_not_hide_valid_pan_on_same_line(scanner, scan_file):
    scan_file(f"first {BAD_PAN} second {VALID_PAN}\n")

    assert scanner._MatchCount["BAD-LUHN"] >= 1
    assert scanner._MatchCount["PAN"] == 1


def test_mask_off_by_default_logs_full_pan(scanner, scan_file, caplog):
    with caplog.at_level(logging.DEBUG, logger=scanner._TraceLogObj.name):
        scan_file(f"Card: {BAD_PAN}\n")

    assert BAD_PAN in luhn_messages(caplog)[0]


def test_mask_hides_middle_digits(scanner, scan_file, caplog):
    scanner._Args.mask = True
    with caplog.at_level(logging.DEBUG, logger=scanner._TraceLogObj.name):
        scan_file(f"Card: {BAD_PAN}\n")

    message = luhn_messages(caplog)[0]
    assert BAD_PAN not in message
    assert "455673******9856" in message


def test_anti_pan_not_luhn_checked_or_reported(scanner, scan_file, caplog):
    with caplog.at_level(logging.INFO, logger=scanner._DefaultLogObj.name):
        scan_file("Sequential: 123456789012345678\n")

    assert scanner._MatchCount["BAD-LUHN"] == 0
    assert scanner._MatchCount["PAN"] == 0
    assert scanner._MatchCount["ANTI-PAN"] == 1
    assert not [r for r in caplog.records if "ANTI-PAN" in r.getMessage()]


def test_mask_pan_helpers(find_pan):
    assert find_pan.mask_pan("4556737586899856") == "455673******9856"
    assert find_pan.mask_pan("123456789") == "*********"
    assert find_pan.mask_matched_data("4556 7375 8689 9856", "4556737586899856") == "4556 73** **** 9856"
    assert find_pan.mask_matched_data(";4556737586899856=2512", "4556737586899856") == ";****************=****"


def test_trace_file_failure_reports_original_error(scanner, tmp_path, monkeypatch, capsys):
    """An unopenable trace log reports the real error, not a NameError."""
    trace_log = tmp_path / "trace.log"
    monkeypatch.setattr(
        scanner, "set_log_directory_and_filenames",
        lambda: (str(tmp_path / "pan.log"), str(trace_log)),
    )
    real_handler = logging.FileHandler

    def failing_handler(filename, *args, **kwargs):
        if str(filename) == str(trace_log):
            raise PermissionError("denied")
        return real_handler(filename, *args, **kwargs)

    monkeypatch.setattr(scanner.logging, "FileHandler", failing_handler)
    loggers = [logging.getLogger("_TraceLogObj"), logging.getLogger("_DefaultLogObj")]
    try:
        with pytest.raises(SystemExit):
            scanner.setup_custom_loggers()
        output = capsys.readouterr().out
        assert "PermissionError" in output
        assert "denied" in output
    finally:
        for logger in loggers:
            for handler in list(logger.handlers):
                handler.close()
                logger.removeHandler(handler)


def test_multiple_valid_pans_on_one_line_all_reported(scanner, scan_file):
    scan_file(f"a {VALID_PAN} b 4012888888881881 c 5424000000000015\n")

    assert scanner._MatchCount["PAN"] == 3


def test_anti_pan_does_not_suppress_pan_elsewhere_on_line(scanner, scan_file):
    scan_file(f"seq 123456789012345678 card {VALID_PAN}\n")

    assert scanner._MatchCount["ANTI-PAN"] == 1
    assert scanner._MatchCount["PAN"] == 1


def test_multiple_anti_pans_on_one_line_counted(scanner, scan_file):
    scan_file("123456789012345678 and 654321098765432109\n")

    assert scanner._MatchCount["ANTI-PAN"] == 2
    assert scanner._MatchCount["PAN"] == 0


def test_same_bad_number_matched_by_two_patterns_counted_once(scanner, scan_file):
    scan_file(f"{BAD_PAN}\n")

    assert scanner._MatchCount["BAD-LUHN"] == 1


def test_multiple_tracks_on_one_line_reported(scanner, scan_file):
    scan_file(";4556737586899855=25121010000000000000? ;4012888888881881=25121010000000000000?\n")

    assert scanner._MatchCount["TRACK"] == 2
    assert scanner._MatchCount["PAN"] == 0


def test_line_limit_scans_exactly_limit_lines(scanner, scan_file):
    scanner._Args.line_limit = 3
    scan_file((f"card {VALID_PAN}\n") * 6)

    assert scanner._MatchCount["PAN"] == 3


def test_mask_applies_to_csv_and_log(scanner, scan_file, tmp_path, caplog):
    import csv

    csv_path = tmp_path / "masked.csv"
    scanner.open_csv_output(str(csv_path))
    scanner._Args.mask = True
    try:
        with caplog.at_level(logging.INFO, logger=scanner._DefaultLogObj.name):
            scan_file(f"Card: {VALID_PAN}\n")
    finally:
        scanner.close_csv_output()

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert rows[0]["matched_data"] == "455673******9855"
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert VALID_PAN not in logged
    assert "455673******9855" in logged


def test_unmasked_csv_and_log_keep_full_pan(scanner, scan_file, tmp_path, caplog):
    import csv

    csv_path = tmp_path / "plain.csv"
    scanner.open_csv_output(str(csv_path))
    try:
        with caplog.at_level(logging.INFO, logger=scanner._DefaultLogObj.name):
            scan_file(f"Card: {VALID_PAN}\n")
    finally:
        scanner.close_csv_output()

    assert list(csv.DictReader(csv_path.open(encoding="utf-8")))[0]["matched_data"] == VALID_PAN
    assert VALID_PAN in " ".join(r.getMessage() for r in caplog.records)
