"""End-to-end tests: --mask must keep raw card data out of every output."""

import csv
from pathlib import Path

import pytest

from find_pan import cli

PAN_ONE = "4556737586899855"
PAN_TWO = "4012888888881881"
BAD_PAN = "4556737586899856"
TRACK_ONE = f"%B{PAN_ONE}^DOE/JANE^25121010000000?"
TRACK_TWO = f";{PAN_TWO}=25121010000000000?"
ANTI_PAN = "123456789012345678"

INPUT = (
    f"alpha {PAN_ONE} beta {PAN_TWO} gamma\n"
    f"track {TRACK_ONE}  {TRACK_TWO}\n"
    f"seq {ANTI_PAN} end\n"
    f"bad {BAD_PAN}\n"
    f"amex 378282246310005 ;{PAN_TWO}=2512101123? %B{PAN_TWO}^DOE/JOHN^251210112345?\n"
)
RAW_VALUES = [PAN_ONE, PAN_TWO, BAD_PAN, ANTI_PAN, TRACK_ONE, TRACK_TWO]
#   Track fields (expiry, service code, discretionary data) must not survive either.
TRACK_FRAGMENTS = ["=2512101123", "^251210112345"]


@pytest.fixture
def run_scan(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "input.txt").write_text(INPUT, encoding="utf-8")
    logs = tmp_path / "logs"
    csv_path = tmp_path / "out.csv"

    def _run(*flags):
        status = cli.main([
            "--path", str(scan_dir), "--log-dir", str(logs), "--tar-tmp", str(tmp_path / "tar"),
            "--csv", str(csv_path), *flags,
        ])
        captured = capsys.readouterr()
        outputs = {path.name: path.read_text(encoding="utf-8") for path in logs.glob("*.log")}
        outputs["out.csv"] = csv_path.read_text(encoding="utf-8")
        outputs["<stdout+stderr>"] = captured.out + captured.err
        return status, outputs, logs

    return _run


def test_mask_hides_raw_values_in_every_output(run_scan):
    status, outputs, _ = run_scan("--mask", "--debug", "--log-anti-pan")
    assert status == 0
    assert len(outputs) >= 5  # PAN log, trace log, anti-PAN log, CSV, console
    for name, text in outputs.items():
        for raw in RAW_VALUES + TRACK_FRAGMENTS:
            assert raw not in text, f"raw value {raw!r} leaked into {name}"


def test_without_mask_full_values_are_present(run_scan):
    status, outputs, _ = run_scan("--debug", "--log-anti-pan")
    assert status == 0
    csv_text = outputs["out.csv"]
    assert PAN_ONE in csv_text and PAN_TWO in csv_text
    pan_log = next(text for name, text in outputs.items()
                   if name.startswith("Find-PAN-") and "trace" not in name and "anti-pan" not in name)
    assert PAN_ONE in pan_log
    trace_log = next(text for name, text in outputs.items() if "trace" in name)
    assert BAD_PAN in trace_log


def test_findings_are_correct_with_and_without_mask(run_scan):
    for flags in ((), ("--mask",)):
        status, outputs, _ = run_scan(*flags)
        assert status == 0
        rows = list(csv.DictReader(outputs["out.csv"].splitlines()))
        assert [row["data_type"] for row in rows].count("PAN") == 3  # two bare PANs on line 1, the Amex on line 5
        assert [row["data_type"] for row in rows].count("TRACK") == 4  # two tracks on each of lines 2 and 5


def test_log_anti_pan_file_absent_without_flag(run_scan):
    _, outputs, logs = run_scan()
    assert not list(logs.glob("*anti-pan*"))
    assert "Anti-PAN log" not in outputs["<stdout+stderr>"]


def test_log_anti_pan_summary_lines_and_count(run_scan):
    _, outputs, logs = run_scan("--log-anti-pan")
    anti_logs = list(logs.glob("*anti-pan*"))
    assert len(anti_logs) == 1
    assert ANTI_PAN in anti_logs[0].read_text(encoding="utf-8")
    console = outputs["<stdout+stderr>"]
    assert f"Anti-PAN log   : {anti_logs[0]}" in console
    assert "Anti-PANs logged: 1" in console
    assert ANTI_PAN not in outputs["out.csv"]


def test_zero_anti_pans_creates_empty_file_and_count_zero(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    status = cli.main(["--path", str(scan_dir), "--log-dir", str(tmp_path / "logs"),
                       "--tar-tmp", str(tmp_path / "tar"), "--log-anti-pan"])
    assert status == 0
    anti_log = next(Path(tmp_path / "logs").glob("*anti-pan*"))
    assert anti_log.read_text(encoding="utf-8") == ""
    assert "Anti-PANs logged: 0" in capsys.readouterr().out
