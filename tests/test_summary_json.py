"""Tests for --summary-json and the stable display paths of archive members."""

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from find_pan import cli, filetypes
from find_pan import scanner as scanner_module
from find_pan.logging_setup import Loggers
from find_pan.models import ScanStats
from find_pan.redact import Redactor
from find_pan.reporting import CsvSink, Reporter
from find_pan.settings import Settings

PAN = "4556737586899855"
ZIP_MAGIC = b"PK\x03\x04" + b"\x00" * 40


def run_cli(tmp_path, *arguments):
    summary = tmp_path / "summary.json"
    status = cli.main([*arguments, "--log-dir", str(tmp_path / "logs"), "--summary-json", str(summary)])
    return status, json.loads(summary.read_text(encoding="utf-8")), summary


def test_summary_json_written_with_counts_and_exit_status(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    status, data, _ = run_cli(tmp_path, "--path", str(scan_dir))
    assert status == 0
    assert data["pans"] == 1 and data["tracks"] == 0 and data["files_scanned"] == 1
    assert data["bad_luhn"] == 0 and data["anti_pans"] == 0
    assert data["archives_expanded"] == 0 and data["archives_skipped"] == 0
    assert data["skipped"] == [] and data["exit_status"] == 0
    assert isinstance(data["total_time"], float) and isinstance(data["average_time"], float)


def test_summary_json_written_when_a_file_entry_is_missing(tmp_path, capsys):
    missing = tmp_path / "sub" / "missing.txt"
    status, data, _ = run_cli(tmp_path, "--file", str(missing))
    assert status == 1 and data["exit_status"] == 1
    assert data["skipped"] == [["NOT-FOUND", missing.as_posix()]]


def test_summary_json_is_valid_when_nothing_is_found(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_text("nothing here\n", encoding="utf-8")
    status, data, summary = run_cli(tmp_path, "--path", str(scan_dir))
    assert status == 0 and data["pans"] == 0
    assert b"\r\n" not in summary.read_bytes()


def test_summary_json_option_is_documented_in_help():
    assert "--summary-json" in cli.build_parser().format_help()


def test_summary_json_is_written_with_the_default_off(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    cli.main(["--path", str(scan_dir), "--log-dir", str(tmp_path / "logs")])
    assert not (tmp_path / "summary.json").exists()


# --- display paths ----------------------------------------------------------------------------------------


@pytest.fixture
def build(compiled_patterns, monkeypatch):
    monkeypatch.setattr(filetypes, "is_executable", lambda *a, **k: False)
    loggers = Loggers(pan=logging.getLogger("test.sj.pan"), trace=logging.getLogger("test.sj.trace"))

    def _build(sinks=()):
        reporter = Reporter(Redactor(False), list(sinks), ScanStats(), loggers.trace, 500)
        scanner = scanner_module.Scanner(Settings(skip_binary=True), compiled_patterns, reporter, loggers,
                                         lambda: {"zip": {}})
        return scanner, reporter

    return _build


def fake_extractor(monkeypatch, directories):
    """Replace extract_archive: yield the directory registered for the archive's file name."""
    @contextmanager
    def fake(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        yield str(directories[Path(archive_path).name])

    monkeypatch.setattr(scanner_module, "extract_archive", fake)


def binary_blob(path: Path):
    path.write_bytes(b"abc\x00def" + b"x" * 40)


def test_display_path_of_a_top_level_file_uses_forward_slashes(build, tmp_path):
    scanner, reporter = build()
    scanner.scan_files([os.path.join(str(tmp_path), "sub", "missing.txt")])
    assert reporter.summary_data()["skipped"] == [["NOT-FOUND", (tmp_path / "sub" / "missing.txt").as_posix()]]


def test_display_path_of_an_extracted_member_is_archive_bang_member(build, tmp_path, monkeypatch):
    extracted = tmp_path / "extracted"
    (extracted / "inner").mkdir(parents=True)
    binary_blob(extracted / "inner" / "blob.bin")
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(ZIP_MAGIC)
    fake_extractor(monkeypatch, {"bundle.zip": extracted})
    scanner, reporter = build()
    scanner.process_file(str(archive))
    assert reporter.summary_data()["skipped"] == [["BINARY", f"{archive.as_posix()}!/inner/blob.bin"]]


def test_display_path_of_a_nested_archive_chains(build, tmp_path, monkeypatch):
    outer_dir, inner_dir = tmp_path / "outer_dir", tmp_path / "inner_dir"
    outer_dir.mkdir()
    inner_dir.mkdir()
    (outer_dir / "inner.zip").write_bytes(ZIP_MAGIC + b"inner")
    binary_blob(inner_dir / "blob.bin")
    outer = tmp_path / "outer.zip"
    outer.write_bytes(ZIP_MAGIC)
    fake_extractor(monkeypatch, {"outer.zip": outer_dir, "inner.zip": inner_dir})
    scanner, reporter = build()
    scanner.process_file(str(outer))
    assert reporter.summary_data()["skipped"] == [["BINARY", f"{outer.as_posix()}!/inner.zip!/blob.bin"]]


def test_a_failing_member_archive_is_shown_with_its_display_path(build, tmp_path, monkeypatch):
    from find_pan.errors import ExtractorError

    outer_dir = tmp_path / "outer_dir"
    outer_dir.mkdir()
    (outer_dir / "bad.zip").write_bytes(ZIP_MAGIC + b"bad")
    outer = tmp_path / "outer.zip"
    outer.write_bytes(ZIP_MAGIC)

    @contextmanager
    def fake(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        if Path(archive_path).name == "bad.zip":
            raise ExtractorError("Extractor failed")
        yield str(outer_dir)

    monkeypatch.setattr(scanner_module, "extract_archive", fake)
    scanner, reporter = build()
    scanner.process_file(str(outer))
    assert reporter.summary_data()["skipped"] == [["ARCHIVE-FAILED", f"{outer.as_posix()}!/bad.zip"]]
    assert reporter.summary_data()["archives_skipped"] == 1


def test_csv_filename_column_is_unchanged_for_members(build, tmp_path, monkeypatch):
    extracted = tmp_path / "extracted"
    (extracted / "deep").mkdir(parents=True)
    (extracted / "deep" / "card.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(ZIP_MAGIC)
    fake_extractor(monkeypatch, {"bundle.zip": extracted})
    csv_path = tmp_path / "out.csv"
    sink = CsvSink(str(csv_path))
    scanner, _ = build(sinks=[sink])
    scanner.process_file(str(archive))
    sink.close()
    assert csv_path.read_text(encoding="utf-8").splitlines()[1].startswith("card.txt,1,")
