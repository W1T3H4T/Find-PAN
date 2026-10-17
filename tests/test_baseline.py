"""Tests for bin/baseline.py: pure functions (create/validate are tested further down)."""

import csv
import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("baseline", ROOT / "bin" / "baseline.py")
baseline = importlib.util.module_from_spec(spec)
sys.modules["baseline"] = baseline
spec.loader.exec_module(baseline)

BaselineError = baseline.BaselineError


@pytest.fixture
def repo(tmp_path):
    """A small fake repository root."""
    root = tmp_path / "repo"
    root.mkdir()
    return root


def write(path: Path, data: bytes | str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    return path


# --- names ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["plain-text", "a.b_c", "X1", "archives"])
def test_validate_name_accepts_good_names(name):
    assert baseline.validate_name(name) == name


@pytest.mark.parametrize("name", ["", "..", "a/b", "a\\b", "/abs", "-x", "a b", ".hidden", "C:\\x", "a..b/c"])
def test_validate_name_rejects_bad_names(name):
    with pytest.raises(BaselineError):
        baseline.validate_name(name)


# --- paths and switches ---------------------------------------------------------------------------------------


def test_to_repo_relative_uses_forward_slashes(repo):
    write(repo / "a" / "b.txt")
    assert baseline.to_repo_relative(str(repo / "a" / "b.txt"), repo) == "a/b.txt"


def test_to_repo_relative_rejects_outside_and_missing(repo, tmp_path):
    outside = write(tmp_path / "outside.txt")
    with pytest.raises(BaselineError, match="outside"):
        baseline.to_repo_relative(str(outside), repo)
    with pytest.raises(BaselineError, match="exist"):
        baseline.to_repo_relative(str(repo / "nope.txt"), repo)


def test_rewrite_args_rewrites_path_file_and_rgx_patterns_and_keeps_other_switches(repo):
    write(repo / "d" / "one.txt")
    write(repo / "two.txt")
    write(repo / "p.json", "{}")
    args = ["--path", str(repo / "d"), "--file", str(repo / "two.txt"), str(repo / "d" / "one.txt"),
            "--rgx-patterns", str(repo / "p.json"), "--mask", "--line-limit", "5"]
    assert baseline.rewrite_find_pan_args(args, repo) == [
        "--path", "d", "--file", "two.txt", "d/one.txt", "--rgx-patterns", "p.json", "--mask", "--line-limit", "5"]


@pytest.mark.parametrize("switch", ["--csv", "--log-dir", "--summary-json", "--version", "--verbose", "--debug"])
def test_rewrite_args_rejects_every_owned_switch(switch, repo):
    with pytest.raises(BaselineError, match="owned|manages|cannot"):
        baseline.rewrite_find_pan_args([switch, "x"] if switch not in ("--version", "--verbose", "--debug") else [switch], repo)


def test_rewrite_args_rejects_an_equals_form_of_an_owned_switch(repo):
    with pytest.raises(BaselineError):
        baseline.rewrite_find_pan_args(["--csv=out.csv"], repo)


# --- enumerating inputs ---------------------------------------------------------------------------------------------


def test_enumerate_is_sorted_by_utf8_bytes_not_walk_order(repo):
    for name in ("B.txt", "a.txt", "\u00e9.txt", "Z/z.txt"):
        write(repo / name)
    listed = baseline.enumerate_inputs(["--path", str(repo)], repo)
    assert listed == ["B.txt", "Z/z.txt", "a.txt", "\u00e9.txt"]


def test_enumerate_skips_symlinks(repo, tmp_path):
    write(repo / "real.txt")
    try:
        os.symlink(repo / "real.txt", repo / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks cannot be created here")
    assert baseline.enumerate_inputs(["--path", str(repo)], repo) == ["real.txt"]


def test_enumerate_lists_an_archive_once_without_its_members(repo):
    write(repo / "bundle.zip", b"PK\x03\x04" + b"\x00" * 30)
    assert baseline.enumerate_inputs(["--path", str(repo)], repo) == ["bundle.zip"]


def test_enumerate_path_and_file_union_is_deduplicated(repo):
    write(repo / "d" / "a.txt")
    write(repo / "b.txt")
    listed = baseline.enumerate_inputs(["--path", str(repo / "d"), "--file", str(repo / "d" / "a.txt"),
                                        str(repo / "b.txt")], repo)
    assert listed == ["b.txt", "d/a.txt"]


# --- hashing ----------------------------------------------------------------------------------------------------------


def test_hash_text_ignores_crlf_but_not_content(repo):
    write(repo / "lf.txt", b"one\ntwo\n")
    write(repo / "crlf.txt", b"one\r\ntwo\r\n")
    write(repo / "changed.txt", b"one\ntwx\n")
    lf = baseline.hash_input("lf.txt", repo)
    assert lf["sha256"] == baseline.hash_input("crlf.txt", repo)["sha256"]
    assert lf["sha256"] != baseline.hash_input("changed.txt", repo)["sha256"]
    assert lf["eol_normalized"] is True and lf["path"] == "lf.txt"


def test_hash_binary_is_raw(repo):
    write(repo / "a.bin", b"ab\x00cd\n")
    write(repo / "b.bin", b"ab\x00cd\r\n")
    a, b = baseline.hash_input("a.bin", repo), baseline.hash_input("b.bin", repo)
    assert a["sha256"] != b["sha256"] and a["eol_normalized"] is False
    assert a["size"] == 6


def test_inputs_manifest_is_sorted_and_complete(repo):
    write(repo / "b.txt", "b")
    write(repo / "a.txt", "a")
    manifest = baseline.inputs_manifest(["--path", str(repo)], repo)
    assert [entry["path"] for entry in manifest] == ["a.txt", "b.txt"]
    assert set(manifest[0]) == {"path", "size", "sha256", "eol_normalized"}


# --- canonical CSV -----------------------------------------------------------------------------------------------------------


def test_canonical_rows_sort_numeric_fields_numerically():
    rows = [("a.txt", "10", "0", "P", "PAN", "x"), ("a.txt", "2", "5", "P", "PAN", "x"),
            ("a.txt", "2", "40", "P", "PAN", "x")]
    assert [row[1:3] for row in baseline.canonical_rows(rows)] == [("2", "5"), ("2", "40"), ("10", "0")]


def test_csv_round_trip_with_commas_quotes_unicode_and_spaces(tmp_path):
    rows = [("na,me \"q\".txt", "3", "0", "Visa, Inc", "PAN", "4556 7375, \"x\" \u00e9\u4e2d"),
            ("\u00e9.txt", "1", "2", "P", "TRACK", ";123=45?")]
    path = tmp_path / "b.csv"
    baseline.write_canonical_csv(rows, path)
    assert baseline.read_rows(path) == baseline.canonical_rows(rows)


def test_write_canonical_csv_uses_lf_and_header(tmp_path):
    path = tmp_path / "b.csv"
    baseline.write_canonical_csv([("a.txt", "1", "0", "P", "PAN", "x")], path)
    raw = path.read_bytes()
    assert b"\r" not in raw
    assert raw.decode("utf-8").splitlines()[0] == "filename,line_number,offset,pattern_name,data_type,matched_data"


def test_read_rows_accepts_find_pan_output_with_crlf(tmp_path):
    path = tmp_path / "x.csv"
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)          # default dialect writes \r\n like find-pan's DictWriter
        writer.writerow(baseline.CSV_FIELDS)
        writer.writerow(["a.txt", "1", "0", "P", "PAN", "x"])
    assert baseline.read_rows(path) == [("a.txt", "1", "0", "P", "PAN", "x")]


# --- diffs ---------------------------------------------------------------------------------------------------------------------


def test_diff_rows_is_a_multiset_difference():
    r1, r2, r3 = ("a", "1", "0", "P", "PAN", "x"), ("a", "2", "0", "P", "PAN", "y"), ("b", "1", "0", "P", "PAN", "z")
    missing, extra = baseline.diff_rows([r1, r1, r2], [r1, r3])
    assert missing == baseline.canonical_rows([r1, r2])
    assert extra == [r3]
    assert baseline.diff_rows([r1], [r1]) == ([], [])


def test_diff_inputs_reports_added_removed_and_changed():
    entry = lambda path, sha: {"path": path, "size": 1, "sha256": sha, "eol_normalized": True}
    before = [entry("a", "1"), entry("b", "2"), entry("c", "3")]
    after = [entry("a", "1"), entry("b", "9"), entry("d", "4")]
    messages = baseline.diff_inputs(before, after)
    assert any("changed" in m and "b" in m for m in messages)
    assert any("removed" in m and "c" in m for m in messages)
    assert any("added" in m and "d" in m for m in messages)
    assert baseline.diff_inputs(before, before) == []


def test_diff_summary_ignores_times_and_reports_changes():
    base = {"pans": 3, "tracks": 0, "bad_luhn": 0, "anti_pans": 1, "files_scanned": 4, "archives_expanded": 0,
            "archives_skipped": 0, "skipped": [["BINARY", "b.bin"], ["BINARY", "a.bin"]],
            "total_time": 1.0, "average_time": 0.1, "exit_status": 0}
    same = {**base, "total_time": 99.0, "average_time": 9.9, "skipped": [["BINARY", "a.bin"], ["BINARY", "b.bin"]]}
    assert baseline.diff_summary(base, same) == []
    changed = {**base, "pans": 2, "skipped": [["BINARY", "a.bin"]]}
    messages = baseline.diff_summary(base, changed)
    assert "pans: baseline 3, now 2" in messages
    assert any(m.startswith("skipped") for m in messages)


def test_format_row():
    row = ("a.txt", "7", "12", "Visa", "PAN", "4556737586899855")
    assert baseline.format_row(row) == "a.txt:7:12  PAN  Visa  4556737586899855"


def test_inputs_may_not_include_the_baseline_directory_itself(repo):
    write(repo / "RegressionTests" / "baseline" / "x" / "baseline.csv")
    write(repo / "RegressionTests" / "a.txt")
    with pytest.raises(BaselineError, match="baseline directory"):
        baseline.enumerate_inputs(["--path", str(repo / "RegressionTests")], repo)
    with pytest.raises(BaselineError, match="baseline directory"):
        baseline.enumerate_inputs(["--file", str(repo / "RegressionTests" / "baseline" / "x" / "baseline.csv")], repo)
    assert baseline.enumerate_inputs(["--file", str(repo / "RegressionTests" / "a.txt")], repo) == ["RegressionTests/a.txt"]
