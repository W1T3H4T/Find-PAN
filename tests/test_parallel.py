"""Tests for the independent-process scan dispatcher."""

import csv
import json
import subprocess
import sys
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from find_pan.parallel import _merge_summaries, _partition, _print_summary, _read_summaries

ROOT = Path(__file__).resolve().parents[1]
PAN = "4556737586899855"
OTHER = "4012888888881881"


def run_scan(tmp_path, name, *args):
    csv_path = tmp_path / f"{name}.csv"
    summary_path = tmp_path / f"{name}.json"
    command = [sys.executable, str(ROOT / "bin" / "find-pan.py"), *args, "--csv", str(csv_path),
               "--summary-json", str(summary_path), "--log-dir", str(tmp_path / f"{name}-logs")]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = Counter(tuple(row) for row in csv.reader(handle))
    return result, rows, json.loads(summary_path.read_text(encoding="utf-8"))


def test_partition_balances_bytes_without_splitting_files(tmp_path):
    paths = []
    for number, size in enumerate((60, 30, 20, 10)):
        path = tmp_path / str(number)
        path.write_bytes(b"x" * size)
        paths.append(str(path))
    batches = _partition(paths, 2)
    assert sorted(sum(Path(path).stat().st_size for path in batch) for batch in batches) == [60, 60]
    assert sorted(path for batch in batches for path in batch) == sorted(paths)


def test_parallel_matches_serial_csv_and_summary(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "one.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    (data / "two.txt").write_text(f"card {OTHER}\n", encoding="utf-8")
    (data / "memory.dmp").write_bytes(b"\xff" * 32 + b" " + PAN.encode() + b" " + b"\xff" * 32)
    excluded = data / "ignored"
    excluded.mkdir()
    (excluded / "not-scanned.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    targets = tmp_path / "targets.txt"
    targets.write_text(PAN + "\n" + OTHER + "\n", encoding="utf-8")
    arguments = ["--path", str(data), "--exclude-dir", "ignored", "--raw-file", "*.dmp", "--pan-list", str(targets)]
    serial, serial_rows, serial_summary = run_scan(tmp_path, "serial", *arguments)
    parallel, parallel_rows, parallel_summary = run_scan(tmp_path, "parallel", *arguments, "--workers", "2")
    assert serial.returncode == parallel.returncode == 0
    assert serial_rows == parallel_rows
    for key in ("pans", "tracks", "bad_luhn", "anti_pans", "files_scanned", "archives_expanded", "skipped"):
        assert serial_summary[key] == parallel_summary[key]
    assert [entry["found"] for entry in serial_summary["expected"]["pans"]] == [
        entry["found"] for entry in parallel_summary["expected"]["pans"]]
    assert "[worker 1]" in parallel.stdout and "[worker 2]" in parallel.stdout
    assert "Combined Processing Summary" in parallel.stdout


def test_parallel_propagates_missing_file_failure(tmp_path):
    missing = tmp_path / "missing.txt"
    result, _, summary = run_scan(tmp_path, "missing", "--file", str(missing), "--workers", "2")
    assert result.returncode == 1 and summary["exit_status"] == 1
    assert any(item[0] == "NOT-FOUND" for item in summary["skipped"])
    assert "missing.txt" in result.stderr


def test_parallel_preserves_overlapping_explicit_inputs(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    target = data / "one.txt"
    target.write_text(f"card {PAN}\n", encoding="utf-8")
    result, rows, summary = run_scan(tmp_path, "overlap", "--file", str(target), "--path", str(data), "--workers", "2")
    assert result.returncode == 0 and summary["pans"] == 2 and summary["files_scanned"] == 2
    assert sum(rows.values()) == 3


def test_workers_omit_file_list_but_serial_retains_it(tmp_path):
    target = tmp_path / "card.txt"
    target.write_text(f"card {PAN}\n", encoding="utf-8")
    serial, serial_rows, _ = run_scan(tmp_path, "serial-files", "--file", str(target))
    parallel, parallel_rows, summary = run_scan(tmp_path, "parallel-files", "--file", str(target), "--workers", "2")
    assert serial.returncode == parallel.returncode == 0
    assert " --file=[" in serial.stdout
    assert " --file=[" not in parallel.stdout
    assert "[worker 1]" in parallel.stdout and "Combined Processing Summary" in parallel.stdout
    assert summary["pans"] == 1 and serial_rows == parallel_rows


def test_parallel_archive_scanned_by_one_worker(tmp_path):
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("memory.dmp", b"\xff" * 40 + b" " + PAN.encode() + b" " + b"\xff" * 40)
    result, _, summary = run_scan(tmp_path, "archive", "--file", str(archive), "--raw-file", "*.dmp", "--workers", "2")
    if summary["archives_skipped"]:
        pytest.skip("zip extractor is unavailable")
    assert result.returncode == 0 and summary["pans"] == 1 and summary["archives_expanded"] == 1


def test_masked_targets_with_same_display_remain_distinct():
    def summary(counts):
        return {"pans": sum(counts), "tracks": 0, "bad_luhn": 0, "anti_pans": 0, "files_scanned": 1,
                "archives_expanded": 0, "archives_skipped": 0, "skipped": [],
                "expected": {"pans": [{"value": "455673******9855", "found": count,
                                       "locations": [f"file-{index}"] if count else []}
                                      for index, count in enumerate(counts)], "tracks": []}}
    combined = _merge_summaries([summary([1, 0]), summary([0, 2])], 1.0, 0)
    assert [entry["found"] for entry in combined["expected"]["pans"]] == [1, 2]


def test_combined_summary_matches_serial_sections_and_skip_counts(capsys, tmp_path):
    summary = {"pans": 4, "tracks": 2, "bad_luhn": 5, "anti_pans": 3, "files_scanned": 10,
               "archives_expanded": 1, "archives_skipped": 1, "total_time": 5.0, "average_time": 0.5,
               "skipped": [["BINARY", "binary.dat"], ["EXEC", "executable.exe"],
                           ["UNREADABLE", "unreadable"], ["NOT-FOUND", "missing"]],
               "expected": {"pans": [{"value": "masked", "found": 1, "locations": ["test:1:0"]},
                                     {"value": "other", "found": 0, "locations": []}], "tracks": []}}
    _print_summary(summary, str(tmp_path), ["Find-PAN-anti-pan-test.log"])
    output = capsys.readouterr().out
    assert "-- Combined Processing Summary --" in output
    assert "Average time  :    0.500 seconds per file\nTotal time    :    5.000 seconds" in output
    assert "-- Skipped Summary --\nDetected 5 Luhn Check Failures.\nDetected 3 Anti-PANs." in output
    assert "Skipped 2 Files.\nSkipped 1 Executable Files.\nSkipped 1 Binary Files." in output
    assert "Unreadable 1 Files." in output and "Archives skipped (no tool or failed): 1" in output
    assert "Anti-PANs logged: 3" in output and "Find-PAN-anti-pan-test.log" in output
    assert "Expected PANs found  : 1 of 2" in output
    assert "PAN   masked  FOUND  1 time, first at test:1:0" in output
    assert "PAN   other   NOT FOUND" in output and "[NOT-FOUND] missing" in output
    assert "Scan complete." in output


def test_combined_summary_aligns_columns_for_large_values(capsys, tmp_path):
    summary = {"pans": 123456789, "tracks": 2, "bad_luhn": 0, "anti_pans": 0, "files_scanned": 1,
               "archives_expanded": 0, "archives_skipped": 0, "total_time": 5.0, "average_time": 5.0,
               "skipped": [], "expected": {"pans": [{"value": "short", "found": 1, "locations": ["a"]},
                                                     {"value": "longer-value", "found": 0, "locations": []}],
                                             "tracks": []}}
    _print_summary(summary, str(tmp_path), ["Find-PAN-anti-pan-test.log"])
    lines = capsys.readouterr().out.splitlines()
    processing = [line for line in lines if line.startswith(("PANs Matched", "TRACKs Matched", "Total matches",
                                                             "Scanned", "Average time", "Total time"))]
    assert len({line.index(":") for line in processing}) == 1
    assert len({line.index(line.split(":", 1)[1].split()[0], line.index(":") + 1)
                + len(line.split(":", 1)[1].split()[0]) for line in processing}) == 1
    expected = [line for line in lines if line.startswith("PAN   ")]
    assert expected[0].index("FOUND") == expected[1].index("NOT FOUND")
    anti = [line for line in lines if line.startswith(("Anti-PAN log", "Anti-PANs logged"))]
    assert len({line.index(":") for line in anti}) == 1


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_invalid_worker_count_rejected(value):
    result = subprocess.run([sys.executable, str(ROOT / "bin" / "find-pan.py"), "--workers", value],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2


def test_empty_directory_and_more_workers_than_files(tmp_path):
    data = tmp_path / "empty"
    data.mkdir()
    result, _, summary = run_scan(tmp_path, "empty", "--path", str(data), "--workers", "3")
    assert result.returncode == 0 and summary["files_scanned"] == 0


def test_exclude_directory_inside_archive(tmp_path):
    archive = tmp_path / "excluded.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("ignore/one.txt", f"card {PAN}\n")
        handle.writestr("keep/two.txt", f"card {OTHER}\n")
    result, _, summary = run_scan(tmp_path, "exclude-archive", "--file", str(archive),
                                  "--exclude-dir", "ignore", "--workers", "2")
    if summary["archives_skipped"]:
        pytest.skip("zip extractor is unavailable")
    assert result.returncode == 0 and summary["pans"] == 1 and summary["files_scanned"] == 1


def test_missing_or_malformed_worker_outputs_are_failures(tmp_path):
    good = tmp_path / "0"
    bad = tmp_path / "1"
    good.mkdir()
    bad.mkdir()
    (good / "summary.json").write_text(json.dumps({"pans": 1, "tracks": 0, "bad_luhn": 0,
                                                   "anti_pans": 0, "files_scanned": 1,
                                                   "archives_expanded": 0, "archives_skipped": 0,
                                                   "skipped": []}), encoding="utf-8")
    (good / "findings.csv").write_text("header\n", encoding="utf-8")
    (bad / "summary.json").write_text("{broken", encoding="utf-8")
    summaries, csv_dirs, failed = _read_summaries([good, bad], True)
    assert failed and len(summaries) == 1 and csv_dirs == [good]
