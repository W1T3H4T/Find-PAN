"""Regression tests for the security review findings fixed together.

1. A deeply nested archive must not end the scan.
2. A line holding very many matches must not take quadratic time.
3. ``--mask`` must mask a PAN written in any of the grouped layouts, wherever it sits in a line.
4. A spreadsheet must not run a CSV cell as a formula.
5. Cleaning up an extraction directory must not change the mode of anything outside it.
"""

import csv
import io
import logging
import os
import random
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from find_pan import archives, cli
from find_pan import scanner as scanner_module
from find_pan.config import extractor_candidates, find_extractor_config_path, load_extractor_config
from find_pan.detectors import MAX_SOURCE_LINE, _Spans, scan_line
from find_pan.logging_setup import Loggers
from find_pan.models import ExtractionLimits, MatchKind, ScanStats
from find_pan.redact import RedactedMatch, Redactor, mask_text
from find_pan.reporting import CsvSink, Reporter, neutralize_formula
from find_pan.settings import Settings

VISA = "4556737586899855"
DINERS = "30569309025904"
ZIP_MAGIC = b"PK\x03\x04"


class Collector:
    def __init__(self):
        self.views = []

    def accepts(self, kind):
        return True

    def emit(self, view):
        self.views.append(view)

    def close(self):
        pass


@pytest.fixture
def build(compiled_patterns):
    loggers = Loggers(pan=logging.getLogger("test.sec.pan"), trace=logging.getLogger("test.sec.trace"))

    def _build(limits=None, **settings):
        sink = Collector()
        reporter = Reporter(Redactor(False), [sink], ScanStats(), loggers.trace, 500)
        scanner = scanner_module.Scanner(
            Settings(**settings), compiled_patterns, reporter, loggers,
            lambda: {}, (lambda: limits) if limits else None)
        return scanner, reporter, sink
    return _build


# --- 1. nested archives ------------------------------------------------------------------------------------------


@pytest.fixture
def endless_archive(monkeypatch):
    """Replace extraction by one that always yields a directory holding one more, different, archive."""
    made = []

    @contextmanager
    def extract(archive_path, extractor_config, logger, archive_type=None, **_):
        directory = tempfile.mkdtemp(prefix="find-pan-test-")
        made.append(directory)
        Path(directory, f"level{len(made)}.zip").write_bytes(ZIP_MAGIC + str(len(made)).encode())
        try:
            yield directory
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    monkeypatch.setattr(scanner_module, "extract_archive", extract)
    return made


def test_archives_nested_deeper_than_the_limit_are_reported_not_expanded(build, tmp_path, endless_archive):
    (tmp_path / "start.zip").write_bytes(ZIP_MAGIC + b"start")
    scanner, reporter, _ = build(limits=ExtractionLimits(max_depth=4))
    scanner.process_file(str(tmp_path / "start.zip"))
    assert len(endless_archive) == 4
    assert reporter.stats.archives_skipped == 1
    assert any("nested more than 4 levels" in problem.message for problem in scanner.problems)
    assert not any(Path(directory).exists() for directory in endless_archive)


def test_the_default_depth_limit_is_ten_and_can_be_configured():
    assert ExtractionLimits().max_depth == 10
    assert extractor_candidates({"posix": [{"command": "x", "args": ["y"], "max_depth": 3}]}, "linux")[0]["max_depth"] == 3


def test_a_scan_does_not_end_when_a_file_cannot_be_processed(build, tmp_path, monkeypatch):
    (tmp_path / "a-bad.txt").write_text(f"{VISA}\n", encoding="utf-8")
    (tmp_path / "b-good.txt").write_text(f"{VISA}\n", encoding="utf-8")
    scanner, reporter, sink = build()
    real = scanner.process_file

    def process(path):
        if path.endswith("a-bad.txt"):
            raise RecursionError("maximum recursion depth exceeded")
        real(path)

    monkeypatch.setattr(scanner, "process_file", process)
    scanner.scan_path(str(tmp_path))
    assert [view.matched_data for view in sink.views if view.kind is MatchKind.PAN] == [VISA]
    assert any("a-bad.txt" in problem.message and "RecursionError" in problem.message for problem in scanner.problems)


def nested_zip(path: Path, levels: int, payload: bytes) -> None:
    data, name = payload, "core.txt"
    for level in range(levels):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr(name, data)
        data, name = buffer.getvalue(), f"level{level}.zip"
    path.write_bytes(data)


def zip_extractor_installed() -> bool:
    entry = load_extractor_config(find_extractor_config_path()).get("zip", {})
    return any(shutil.which(os.path.expandvars(c["command"])) for c in extractor_candidates(entry))


def scan_summary(tmp_path, capsys, *arguments):
    import json
    summary = tmp_path / "summary.json"
    status = cli.main([*arguments, "--summary-json", str(summary), "--log-dir", str(tmp_path / "logs")])
    capsys.readouterr()
    return status, json.loads(summary.read_text(encoding="utf-8"))


def find_pan_temp_directories() -> set:
    return {name for name in os.listdir(tempfile.gettempdir()) if name.startswith("find-pan-")}


@pytest.mark.skipif(not zip_extractor_installed(), reason="no zip extractor is installed")
def test_a_very_deeply_nested_zip_does_not_stop_the_scan_or_leave_files_behind(tmp_path, capsys):
    tree = tmp_path / "tree"
    tree.mkdir()
    nested_zip(tree / "deep.zip", 300, f"{VISA}\n".encode())
    (tree / "zz-plain.txt").write_text(f"{VISA}\n", encoding="utf-8")        # sorts after the archive
    before = find_pan_temp_directories()
    _, summary = scan_summary(tmp_path, capsys, "--path", str(tree))
    assert summary["pans"] == 1                                              # the plain file was reached
    assert any(reason == "ARCHIVE-FAILED" and path.startswith(str(tree).replace("\\", "/"))
               for reason, path in summary["skipped"])
    assert summary["archives_skipped"] >= 1
    assert find_pan_temp_directories() == before


@pytest.mark.skipif(not zip_extractor_installed(), reason="no zip extractor is installed")
def test_a_zip_nested_within_the_limit_is_still_scanned(tmp_path, capsys):
    tree = tmp_path / "tree"
    tree.mkdir()
    nested_zip(tree / "ok.zip", 4, f"{VISA}\n".encode())
    _, summary = scan_summary(tmp_path, capsys, "--path", str(tree))
    assert summary["pans"] == 1 and summary["archives_skipped"] == 0


# --- 2. many matches on one line -----------------------------------------------------------------------------------


def test_spans_agree_with_the_quadratic_reference():
    rng = random.Random(7)
    for _ in range(300):
        spans, reference = _Spans(), []
        for _ in range(60):
            start = rng.randrange(0, 300)
            candidate = (start, start + rng.randrange(1, 25))
            expected = any(candidate[0] < other[1] and other[0] < candidate[1] for other in reference)
            assert spans.overlaps(candidate) is expected
            if not expected:                      # the scanner only ever adds a span that overlaps none
                spans.add(candidate)
                reference.append(candidate)


def timed_scan(patterns, count: int) -> float:
    line = "4111 1111 1111 111 " * count
    started = time.perf_counter()
    found = scan_line("f", 1, line, patterns)
    elapsed = time.perf_counter() - started
    assert len(found) == count
    return elapsed


def test_scan_time_grows_roughly_linearly_with_the_matches_on_a_line(compiled_patterns):
    timed_scan(compiled_patterns, 500)                                       # warm up
    small = min(timed_scan(compiled_patterns, 5_000) for _ in range(2))
    large = min(timed_scan(compiled_patterns, 40_000) for _ in range(2))
    #   Eight times the matches: about 8 times as long when linear, about 64 when quadratic.
    assert large < small * 24, f"{small:.2f}s for 5,000 matches but {large:.2f}s for 40,000"


def test_a_long_line_is_reported_with_only_the_text_around_each_match(compiled_patterns):
    line = ("filler " * 400) + VISA + (" filler" * 400)
    (match,) = [m for m in scan_line("f", 1, line, compiled_patterns) if m.kind is MatchKind.PAN]
    assert VISA in match.source_line and len(match.source_line) < MAX_SOURCE_LINE
    assert line[match.offset:match.offset + len(VISA)] == VISA                # the offset is still in the full line


def test_an_ordinary_line_is_reported_whole(compiled_patterns):
    line = f"card {VISA} expires soon\n"
    (match,) = [m for m in scan_line("f", 1, line, compiled_patterns) if m.kind is MatchKind.PAN]
    assert match.source_line == line


# --- 3. masking ------------------------------------------------------------------------------------------------------

GROUPED = [
    ("diners 4-6-4 spaces", "3056 930902 5904", "305693", "5904"),
    ("diners 4-6-4 hyphens", "3056-930902-5904", "305693", "5904"),
    ("amex 4-6-5", "3782 822463 10005", "378282", "0005"),
    ("visa 4-4-4-4", "4556 7375 8689 9855", "455673", "9855"),
    ("visa dotted", "4556.7375.8689.9855", "455673", "9855"),
    ("thirteen digits", "4222 2222 2222 2", "422222", "2222"),
    ("nineteen digits", "6304 9000 1774 0292 441", "630490", "2441"),
]


@pytest.mark.parametrize("label, text, first, last", GROUPED, ids=[g[0] for g in GROUPED])
def test_grouped_pans_are_masked_in_free_text(label, text, first, last):
    masked = mask_text(f"before {text} after")
    digits = re.sub(r"\D", "", text)
    assert masked.startswith("before ") and masked.endswith(" after")
    #   The first six and last four digits stay, the rest are masked, and the separators are kept.
    assert re.sub(r"[^\d*]", "", masked) == digits[:6] + "*" * (len(digits) - 10) + digits[-4:]
    assert re.sub(r"[\d*]", "#", masked) == re.sub(r"\d", "#", f"before {text} after")


def test_another_pan_in_the_same_line_is_masked_in_the_report(compiled_patterns):
    line = f"card {VISA} other {DINERS[:4]} {DINERS[4:10]} {DINERS[10:]} dotted 4556.7375.8689.9855\n"
    redactor = Redactor(True)
    views = [redactor.apply(m) for m in scan_line("f", 1, line, compiled_patterns) if m.kind is MatchKind.PAN]
    assert views
    for view in views:
        for hidden in (VISA[6:-4], DINERS[6:-4], "73758689"):
            assert hidden not in re.sub(r"\D", "", view.source_line), view.source_line


@pytest.mark.parametrize("text", [
    "host 192.168.100.200 up", "version 1.2.3.4", "built 2026-10-18 12:20:02", "ports 8080 8081",
    "id 1234 5678 90", "code 1234-5678-90", "twenty 1234 5678 9012 3456 7890",
])
def test_ordinary_grouped_numbers_are_left_alone(text):
    assert mask_text(text) == text


# --- 4. CSV injection ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["=HYPERLINK(1,1).txt", "+1+1.txt", "-2+3.txt", "@SUM(1).txt"])
def test_formula_cells_are_made_plain_text(value):
    assert neutralize_formula(value) == "'" + value


@pytest.mark.parametrize("value", ["plain.txt", "4556737586899855", "a=b", "", "%B4556^X^1?", ";4556=1?"])
def test_other_cells_are_unchanged(value):
    assert neutralize_formula(value) == value


def test_a_csv_row_for_a_formula_file_name_cannot_run_as_a_formula(tmp_path):
    path = tmp_path / "out.csv"
    sink = CsvSink(str(path))
    sink.emit(RedactedMatch("/data/=HYPERLINK(1,1).txt", 3, 0, MatchKind.PAN, "VISA", "p", VISA, VISA, VISA))
    sink.close()
    with open(path, newline="", encoding="utf-8") as handle:
        (row,) = list(csv.DictReader(handle))
    assert row["filename"] == "'=HYPERLINK(1,1).txt"
    assert row["matched_data"] == VISA
    assert not any(cell[:1] in "=+-@" for cell in row.values())


def test_a_scan_writes_no_formula_cell_to_the_csv(tmp_path, capsys):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "=cmd.txt").write_text(f"{VISA}\n", encoding="utf-8")
    out = tmp_path / "out.csv"
    cli.main(["--path", str(tree), "--csv", str(out), "--log-dir", str(tmp_path / "logs")])
    capsys.readouterr()
    with open(out, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["filename"] for row in rows] == ["'=cmd.txt"]


# --- 5. cleaning up an extraction directory --------------------------------------------------------------------------


def test_the_cleanup_handler_never_changes_the_mode_of_anything_outside_the_tree(tmp_path, monkeypatch):
    root = tmp_path / "find-pan-x"
    (root / "inner").mkdir(parents=True)
    changed = []
    monkeypatch.setattr(archives.os, "chmod", lambda path, mode, **kwargs: changed.append(Path(path)))
    handler = archives._make_writable_and_retry(str(root))
    handler(lambda path: None, str(root), None)                              # the root itself failed
    handler(lambda path: None, str(root / "inner"), None)
    outside = {tmp_path, tmp_path.parent}
    assert not outside & set(changed), changed
    assert all(path == root or root in path.parents for path in changed)


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a user who is not root")
def test_removing_a_tree_does_not_change_the_target_of_a_link_inside_it(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    victim.chmod(0o644)
    root = tmp_path / "find-pan-tree"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "file.txt").write_text("x", encoding="utf-8")
    os.symlink(victim, locked / "link")
    locked.chmod(0o555)                                                      # unlink must fail until it is repaired
    archives._remove_tree(str(root))
    assert not root.exists()
    assert victim.exists() and stat.S_IMODE(victim.stat().st_mode) == 0o644


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a user who is not root")
def test_read_only_extracted_directories_are_still_removed(tmp_path):
    root = tmp_path / "find-pan-tree"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "f").write_text("x", encoding="utf-8")
    (root / "a" / "b").chmod(0o555)
    (root / "a").chmod(0o500)
    before = stat.S_IMODE(tmp_path.stat().st_mode)
    archives._remove_tree(str(root))
    assert not root.exists()
    assert stat.S_IMODE(tmp_path.stat().st_mode) == before
