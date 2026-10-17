"""Tests for the scanner's single file processor: classify, then skip / expand / scan."""

import logging
import shutil
import zipfile
from contextlib import contextmanager

import pytest

from find_pan import scanner as scanner_module
from find_pan.errors import ConfigError, ExtractorError, ExtractorUnavailable
from find_pan.logging_setup import Loggers
from find_pan.models import MatchKind, ScanStats
from find_pan.redact import Redactor
from find_pan.reporting import Reporter
from find_pan.settings import Settings

VALID_PAN = "4556737586899855"
SECOND_PAN = "4012888888881881"
ZIP_MAGIC = b"PK\x03\x04" + b"\x00" * 40


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
    loggers = Loggers(pan=logging.getLogger("test.dispatch.pan"), trace=logging.getLogger("test.dispatch.trace"))

    def _build(load_extractors=None, **settings):
        sink = Collector()
        reporter = Reporter(Redactor(False), [sink], ScanStats(), loggers.trace, 500)
        scanner = scanner_module.Scanner(Settings(**settings), compiled_patterns, reporter, loggers, load_extractors)
        return scanner, reporter, sink

    return _build


def pans(sink):
    return [view.pan for view in sink.views if view.kind is MatchKind.PAN]


def fake_extractor(monkeypatch, directory_for, calls=None):
    """Replace extract_archive: yield a prepared directory (or raise) chosen by archive path."""

    @contextmanager
    def fake_extract(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        if calls is not None:
            calls.append((archive_path, archive_type))
        directory = directory_for(archive_path)
        if isinstance(directory, Exception):
            raise directory
        yield str(directory)

    monkeypatch.setattr(scanner_module, "extract_archive", fake_extract)


def zip_stub(path):
    path.write_bytes(ZIP_MAGIC)
    return path


def folder_with(tmp_path, name, **files):
    directory = tmp_path / name
    directory.mkdir()
    for filename, text in files.items():
        (directory / filename).write_text(text, encoding="utf-8")
    return directory


def test_archive_is_detected_by_content_expanded_and_its_members_scanned(build, tmp_path, monkeypatch):
    archive = zip_stub(tmp_path / "blob_without_extension")
    inner = folder_with(tmp_path, "inner", **{"m.txt": f"card {VALID_PAN}\n"})
    calls = []
    fake_extractor(monkeypatch, lambda path: inner, calls)
    scanner, reporter, sink = build(load_extractors=lambda: {"zip": {}})
    scanner.process_file(str(archive))
    assert calls == [(str(archive), "zip")]
    assert pans(sink) == [VALID_PAN]
    assert reporter.stats.archives_expanded == 1


def test_nested_archives_expand_through_the_same_processor(build, tmp_path, monkeypatch):
    outer = zip_stub(tmp_path / "outer.zip")
    middle = folder_with(tmp_path, "middle")
    (middle / "inner.zip").write_bytes(ZIP_MAGIC + b"inner")   # differs from the outer archive
    deepest = folder_with(tmp_path, "deepest", **{"deep.txt": f"card {SECOND_PAN}\n"})
    fake_extractor(monkeypatch, lambda path: middle if path.endswith("outer.zip") else deepest)
    scanner, reporter, sink = build(load_extractors=lambda: {"zip": {}})
    scanner.process_file(str(outer))
    assert pans(sink) == [SECOND_PAN]
    assert reporter.stats.archives_expanded == 2


def test_text_file_with_archive_extension_is_scanned_as_text(build, tmp_path, caplog):
    target = tmp_path / "notes.zip"
    target.write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    scanner, reporter, sink = build()
    with caplog.at_level(logging.INFO, logger="test.dispatch.pan"):
        scanner.process_file(str(target))
    assert pans(sink) == [VALID_PAN]
    assert reporter.stats.archives_expanded == 0
    assert "extension suggests" in caplog.text


def test_directory_scan_expands_archives(build, tmp_path, monkeypatch):
    scan_dir = folder_with(tmp_path, "scan", **{"plain.txt": f"card {VALID_PAN}\n"})
    zip_stub(scan_dir / "bundle.zip")
    inner = folder_with(tmp_path, "inner", **{"m.txt": f"card {SECOND_PAN}\n"})
    fake_extractor(monkeypatch, lambda path: inner)
    scanner, reporter, sink = build(load_extractors=lambda: {"zip": {}})
    scanner.scan_path(str(scan_dir))
    assert sorted(pans(sink)) == sorted([VALID_PAN, SECOND_PAN])
    assert reporter.stats.archives_expanded == 1


def test_scan_files_processes_every_file_in_order(build, tmp_path):
    expected = [VALID_PAN, SECOND_PAN, "5424000000000015"]
    paths = []
    for index, pan in enumerate(expected):
        path = tmp_path / f"f{index}.txt"
        path.write_text(f"card {pan}\n", encoding="utf-8")
        paths.append(str(path))
    scanner, reporter, sink = build()
    scanner.scan_files(paths)
    assert pans(sink) == expected
    assert reporter.stats.files == 3


def test_missing_and_directory_entries_are_reported_but_processing_continues(build, tmp_path):
    good = tmp_path / "good.txt"
    good.write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    folder = tmp_path / "folder"
    folder.mkdir()
    scanner, reporter, sink = build()
    scanner.scan_files([str(tmp_path / "missing.txt"), str(folder), str(good)])
    assert pans(sink) == [VALID_PAN]
    assert reporter.stats.failures == 2
    assert [problem.severity for problem in scanner.problems] == ["error", "error"]
    assert "missing.txt" in scanner.problems[0].message and "folder" in scanner.problems[1].message


def test_missing_tool_is_a_warning_and_the_archive_is_skipped(build, tmp_path, monkeypatch):
    archive = zip_stub(tmp_path / "a.zip")
    fake_extractor(monkeypatch, lambda path: ExtractorUnavailable("Extractor command not found: unzip"))
    scanner, reporter, _ = build(load_extractors=lambda: {"zip": {}})
    scanner.process_file(str(archive))
    assert [problem.severity for problem in scanner.problems] == ["warning"]
    assert "unzip" in scanner.problems[0].message
    assert reporter.stats.archives_skipped == 1
    assert reporter.stats.failures == 0
    assert reporter.stats.archives_expanded == 0


def test_failing_tool_is_an_error_and_the_archive_is_skipped(build, tmp_path, monkeypatch):
    archive = zip_stub(tmp_path / "a.zip")
    fake_extractor(monkeypatch, lambda path: ExtractorError("Extractor failed for a.zip"))
    scanner, reporter, _ = build(load_extractors=lambda: {"zip": {}})
    scanner.process_file(str(archive))
    assert [problem.severity for problem in scanner.problems] == ["error"]
    assert reporter.stats.failures == 1 and reporter.stats.archives_skipped == 1


def test_extractor_config_loaded_lazily_and_once(build, tmp_path, monkeypatch):
    loads = []
    (tmp_path / "plain.txt").write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    scanner, _, _ = build(load_extractors=lambda: loads.append(1) or {"zip": {}})
    scanner.process_file(str(tmp_path / "plain.txt"))
    assert loads == []
    inner = folder_with(tmp_path, "inner")
    fake_extractor(monkeypatch, lambda path: inner)
    scanner.process_file(str(zip_stub(tmp_path / "one.zip")))
    scanner.process_file(str(zip_stub(tmp_path / "two.zip")))
    assert loads == [1]


def test_unloadable_extractor_config_skips_archives_with_a_warning(build, tmp_path):
    def broken():
        raise ConfigError("Invalid extractor configuration")

    scanner, reporter, _ = build(load_extractors=broken)
    scanner.process_file(str(zip_stub(tmp_path / "a.zip")))
    assert reporter.stats.archives_skipped == 1
    assert {problem.severity for problem in scanner.problems} == {"warning"}
    assert any("extractors unavailable" in problem.message for problem in scanner.problems)


@pytest.mark.skipif(shutil.which("unzip") is None, reason="needs a local unzip")
def test_real_tool_expands_a_zip_and_scans_its_members(build, tmp_path):
    archive = tmp_path / "real.dat"          # unhelpful extension: content decides
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("inner.txt", f"card {VALID_PAN}\n")
    config = {"zip": {"command": "unzip", "args": ["-o", "{archive}", "-d", "{tempdir}"]}}
    scanner, reporter, sink = build(load_extractors=lambda: config)
    scanner.process_file(str(archive))
    assert pans(sink) == [VALID_PAN]
    assert reporter.stats.archives_expanded == 1


@pytest.mark.skipif(shutil.which("tar") is None, reason="needs a local tar")
def test_real_tar_expands_a_tar_with_the_default_arguments(build, tmp_path):
    """Regression: GNU tar on Windows failed on drive-letter paths ('Cannot connect to C')."""
    import tarfile

    member = tmp_path / "member.txt"
    member.write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    archive = tmp_path / "real.tar"
    with tarfile.open(archive, "w") as handle:
        handle.add(member, arcname="member.txt")
    config = {"tar": {"command": "tar", "args": ["-xf", "{archive}", "-C", "{tempdir}"]}}
    scanner, reporter, sink = build(load_extractors=lambda: config)
    scanner.process_file(str(archive))
    assert pans(sink) == [VALID_PAN]
    assert reporter.stats.archives_expanded == 1 and not scanner.problems
