"""Tests for find_pan.scanner."""

import builtins
import logging
from contextlib import contextmanager

import pytest

from find_pan import scanner as scanner_module
from find_pan.errors import ExtractorError
from find_pan.logging_setup import Loggers
from find_pan.models import MatchKind, ScanStats
from find_pan.redact import Redactor
from find_pan.reporting import Reporter
from find_pan.settings import Settings

VALID_PAN = "4556737586899855"
SECOND_PAN = "4012888888881881"


class Collector:
    """A sink that keeps every redacted match it is given."""

    def __init__(self):
        self.views = []

    def accepts(self, kind):
        return True

    def emit(self, view):
        self.views.append(view)

    def close(self):
        pass


@pytest.fixture
def loggers():
    return Loggers(pan=logging.getLogger("test.scan.pan"), trace=logging.getLogger("test.scan.trace"))


@pytest.fixture
def build(compiled_patterns, loggers):
    def _build(**settings):
        sink = Collector()
        reporter = Reporter(Redactor(False), [sink], ScanStats(), loggers.trace, 500)
        scanner = scanner_module.Scanner(Settings(**settings), compiled_patterns, reporter, loggers)
        return scanner, reporter, sink
    return _build


def kinds(sink, kind):
    return [view for view in sink.views if view.kind is kind]


def test_scan_file_reports_each_hit_once(build, tmp_path):
    target = tmp_path / "a.txt"
    target.write_text(f"one {VALID_PAN}\ntwo {SECOND_PAN} and {VALID_PAN}\n", encoding="utf-8")
    scanner, reporter, sink = build()
    scanner.scan_file(str(target))
    assert len(kinds(sink, MatchKind.PAN)) == 3
    assert reporter.stats.files == 1


def test_line_limit_scans_exactly_limit_lines(build, tmp_path):
    target = tmp_path / "a.txt"
    target.write_text(f"card {VALID_PAN}\n" * 6, encoding="utf-8")
    scanner, _, sink = build(line_limit=3)
    scanner.scan_file(str(target))
    assert len(kinds(sink, MatchKind.PAN)) == 3


def test_empty_file_and_no_trailing_newline_and_invalid_utf8(build, tmp_path):
    (tmp_path / "empty.txt").write_bytes(b"")
    (tmp_path / "nonl.txt").write_bytes(f"card {VALID_PAN}".encode())
    (tmp_path / "bad.txt").write_bytes(b"\xfe\xfd caf\xe9 " + VALID_PAN.encode() + b"\n")
    scanner, reporter, sink = build()
    scanner.scan_directory(str(tmp_path))
    assert reporter.stats.files == 3
    assert len(kinds(sink, MatchKind.PAN)) == 2


def test_binary_file_skipped_when_skip_binary_and_counted(build, tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module, "skip_reason", lambda *a, **k: scanner_module.SkipReason.BINARY)
    target = tmp_path / "a.bin"
    target.write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    scanner, reporter, sink = build(skip_binary=True)
    scanner.scan_file(str(target))
    assert sink.views == []
    assert reporter.stats.skipped_files == 1 and reporter.stats.binary == 1
    assert reporter.stats.files == 0


def test_unreadable_file_is_skipped_and_scan_continues(build, tmp_path, monkeypatch):
    bad = tmp_path / "bad.txt"
    good = tmp_path / "good.txt"
    bad.write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    good.write_text(f"card {SECOND_PAN}\n", encoding="utf-8")
    real_open = builtins.open

    def flaky_open(path, *args, **kwargs):
        if str(path).endswith("bad.txt"):
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)
    scanner, reporter, sink = build()
    scanner.scan_directory(str(tmp_path))
    assert [view.pan for view in kinds(sink, MatchKind.PAN)] == [SECOND_PAN]
    assert reporter.stats.skipped_files == 1


def test_scan_directory_walks_nested_directories(build, tmp_path):
    nested = tmp_path / "x" / "y"
    nested.mkdir(parents=True)
    (tmp_path / "top.txt").write_text(f"{VALID_PAN}\n", encoding="utf-8")
    (nested / "deep.txt").write_text(f"{SECOND_PAN}\n", encoding="utf-8")
    scanner, _, sink = build()
    scanner.scan_path(str(tmp_path))
    assert {view.pan for view in kinds(sink, MatchKind.PAN)} == {VALID_PAN, SECOND_PAN}


def test_scan_archive_scans_extracted_files_and_cleans_up(build, tmp_path, monkeypatch):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "safe.txt").write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    state = {}

    @contextmanager
    def fake_extract(archive_path, extractor_config, tar_tmp, logger, **kwargs):
        state["args"] = (archive_path, extractor_config, tar_tmp)
        yield str(extracted)
        state["cleaned"] = True

    monkeypatch.setattr(scanner_module, "extract_archive", fake_extract)
    scanner, _, sink = build(tar_tmp=str(tmp_path / "tmp"))
    scanner.extractor_config = {"tar": {}}
    scanner.scan_archive(str(tmp_path / "a.tar"))
    assert len(kinds(sink, MatchKind.PAN)) == 1
    assert state["cleaned"] and state["args"][2] == str(tmp_path / "tmp")


def test_scan_archive_extractor_error_is_logged_not_raised(build, tmp_path, monkeypatch, caplog):
    @contextmanager
    def failing_extract(*args, **kwargs):
        raise ExtractorError("Extractor failed for x")
        yield  # pragma: no cover

    monkeypatch.setattr(scanner_module, "extract_archive", failing_extract)
    scanner, _, sink = build()
    with caplog.at_level(logging.ERROR, logger="test.scan.pan"):
        scanner.scan_archive(str(tmp_path / "a.tar"))
    assert "Extractor failed for x" in caplog.text
    assert sink.views == []
