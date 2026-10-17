"""Hardening tests for automatic archive extraction of untrusted input."""

import logging
import os
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from find_pan import archives
from find_pan import scanner as scanner_module
from find_pan.errors import ExtractorError
from find_pan.logging_setup import Loggers
from find_pan.models import MatchKind, ScanStats, SkipReason
from find_pan.redact import Redactor
from find_pan.reporting import Reporter
from find_pan.settings import Settings

LOGGER = logging.getLogger("test.hardening")
VALID_PAN = "4556737586899855"
ZIP_BYTES = b"PK\x03\x04" + b"\x00" * 40


class Runner:
    def __init__(self, effect=None):
        self.effect, self.commands = effect, []

    def __call__(self, cmd, check, capture_output, text):
        self.commands.append(cmd)
        if self.effect:
            self.effect(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture(autouse=True)
def system_temp(tmp_path, monkeypatch):
    root = tmp_path / "system-temp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def build(compiled_patterns):
    loggers = Loggers(pan=logging.getLogger("test.hardening.pan"), trace=logging.getLogger("test.hardening.trace"))

    def _build(mask=False, **kwargs):
        views = []

        class Collector:
            def accepts(self, kind):
                return True

            def emit(self, view):
                views.append(view)

            def close(self):
                pass

        reporter = Reporter(Redactor(mask), [Collector()], ScanStats(), loggers.trace, 500)
        scanner = scanner_module.Scanner(Settings(), compiled_patterns, reporter, loggers, kwargs.get("load"))
        return scanner, reporter, views

    return _build


# --- partial extraction ------------------------------------------------------------------


def test_partial_extraction_exposes_extracted_members_then_reports_failure(tmp_path):
    """A tool that warns after extracting (e.g. a '../' member) must not hide the good members."""
    def effect(cmd):
        (Path(cmd[-1]) / "good.txt").write_text("hello", encoding="utf-8")
        raise subprocess.CalledProcessError(1, cmd, stderr="warning: stripped leading '../'")

    config = {"tar": {"command": "fake", "args": ["{archive}", "{tempdir}"]}}
    seen = {}
    with pytest.raises(ExtractorError, match="partial"):
        with archives.extract_archive(str(tmp_path / "a.tar"), config, LOGGER, runner=Runner(effect)) as directory:
            seen["files"] = sorted(path.name for path in Path(directory).iterdir())
    assert seen["files"] == ["good.txt"]


def test_failure_with_nothing_extracted_raises_before_yielding(tmp_path):
    def effect(cmd):
        raise subprocess.CalledProcessError(2, cmd, stderr="broken")

    config = {"tar": {"command": "fake", "args": ["{archive}", "{tempdir}"]}}
    entered = []
    with pytest.raises(ExtractorError, match="Extractor failed"):
        with archives.extract_archive(str(tmp_path / "a.tar"), config, LOGGER, runner=Runner(effect)):
            entered.append(True)
    assert not entered


def test_tool_stderr_in_the_message_is_truncated(tmp_path):
    def effect(cmd):
        raise subprocess.CalledProcessError(2, cmd, stderr="x" * 10_000)

    config = {"tar": {"command": "fake", "args": ["{archive}", "{tempdir}"]}}
    with pytest.raises(ExtractorError) as info:
        with archives.extract_archive(str(tmp_path / "a.tar"), config, LOGGER, runner=Runner(effect)):
            pass
    assert len(str(info.value)) < 2000


def test_scanner_scans_members_of_a_partially_extracted_archive_and_reports_the_failure(build, tmp_path, monkeypatch):
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "good.txt").write_text(f"card {VALID_PAN}\n", encoding="utf-8")

    @contextmanager
    def partial(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        yield str(inner)
        raise ExtractorError("Extractor failed for x (partial extraction: the extracted members were scanned)")

    monkeypatch.setattr(scanner_module, "extract_archive", partial)
    archive = tmp_path / "a.zip"
    archive.write_bytes(ZIP_BYTES)
    scanner, reporter, views = build(load=lambda: {"zip": {}})
    scanner.process_file(str(archive))
    assert [v.pan for v in views if v.kind is MatchKind.PAN] == [VALID_PAN]
    assert reporter.stats.failures == 1
    assert [p.severity for p in scanner.problems] == ["error"]


# --- option-like names --------------------------------------------------------------------


def test_relative_archive_path_is_passed_to_the_tool_as_an_absolute_path(tmp_path, monkeypatch):
    """A relative name such as '-evil.zip' must never reach the tool looking like an option."""
    monkeypatch.chdir(tmp_path)
    runner = Runner()
    config = {"zip": {"command": "unzip", "args": ["{archive}", "-d", "{tempdir}"]}}
    with archives.extract_archive("-evil.zip", config, LOGGER, archive_type="zip", runner=runner):
        pass
    passed = runner.commands[0][1]
    assert not passed.startswith("-")
    assert os.path.isabs(passed)


# --- recursive archives ----------------------------------------------------------------------


def test_archive_containing_itself_is_detected_and_does_not_recurse(build, tmp_path, monkeypatch):
    again = tmp_path / "again"
    again.mkdir()
    (again / "copy.zip").write_bytes(ZIP_BYTES)          # byte-identical copy of the outer archive

    @contextmanager
    def quine(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        yield str(again)

    monkeypatch.setattr(scanner_module, "extract_archive", quine)
    outer = tmp_path / "outer.zip"
    outer.write_bytes(ZIP_BYTES)
    scanner, reporter, _ = build(load=lambda: {"zip": {}})
    scanner.process_file(str(outer))                      # must return, not raise RecursionError
    assert reporter.stats.archives_expanded == 1
    assert reporter.stats.failures == 1
    assert any("contains itself" in problem.message for problem in scanner.problems)


def test_same_archive_in_two_branches_is_not_mistaken_for_a_cycle(build, tmp_path, monkeypatch):
    """Only an archive inside its own expansion is a cycle; siblings may be identical."""
    both = tmp_path / "both"
    both.mkdir()
    (both / "one.zip").write_bytes(ZIP_BYTES + b"A")
    (both / "two.zip").write_bytes(ZIP_BYTES + b"A")
    empty = tmp_path / "empty"
    empty.mkdir()

    @contextmanager
    def fake(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        yield str(both) if archive_path.endswith("top.zip") else str(empty)

    monkeypatch.setattr(scanner_module, "extract_archive", fake)
    top = tmp_path / "top.zip"
    top.write_bytes(ZIP_BYTES + b"TOP")
    scanner, reporter, _ = build(load=lambda: {"zip": {}})
    scanner.process_file(str(top))
    assert reporter.stats.archives_expanded == 3
    assert reporter.stats.failures == 0


# --- symlinks inside extracted trees -------------------------------------------------------------


def test_symlinks_inside_an_extracted_tree_are_not_followed(build, tmp_path, monkeypatch):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "link.txt").write_text(f"card {VALID_PAN}\n", encoding="utf-8")   # stands in for a symlink
    real_islink = os.path.islink
    monkeypatch.setattr(scanner_module.os.path, "islink",
                        lambda path: path.endswith("link.txt") or real_islink(path))

    @contextmanager
    def fake(archive_path, extractor_config, logger, archive_type=None, **kwargs):
        yield str(extracted)

    monkeypatch.setattr(scanner_module, "extract_archive", fake)
    archive = tmp_path / "a.zip"
    archive.write_bytes(ZIP_BYTES)
    scanner, reporter, views = build(load=lambda: {"zip": {}})
    scanner.process_file(str(archive))
    assert views == []                                    # the link target was never read
    assert reporter.stats.failures == 0


def test_symlinks_are_still_followed_in_a_plain_path_scan(build, tmp_path, monkeypatch):
    """--path is the user's own tree; only extracted trees are untrusted."""
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "link.txt").write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    monkeypatch.setattr(scanner_module.os.path, "islink", lambda path: True)
    scanner, _, views = build()
    scanner.scan_path(str(scan_dir))
    assert [v.pan for v in views if v.kind is MatchKind.PAN] == [VALID_PAN]


# --- messages shown to the user ----------------------------------------------------------------------


def test_control_characters_cannot_inject_log_lines_or_escape_sequences():
    reporter = Reporter(Redactor(False), [], ScanStats(), LOGGER, 500)
    reporter.skip("/tmp/evil\n[INFO] fake line\x1b[2J", SkipReason.BINARY, "detail\r\nmore")
    text = "\n".join(reporter.summary_lines("/logs"))
    assert "\x1b" not in text and "\r" not in text
    listed = [line for line in text.splitlines() if line.startswith("[BINARY]")]
    assert len(listed) == 1 and "fake line" in listed[0]   # still one line


def test_masking_also_applies_to_paths_and_details_in_skip_output(caplog):
    reporter = Reporter(Redactor(True), [], ScanStats(), logging.getLogger("test.hardening.skip"), 500)
    with caplog.at_level(logging.INFO, logger="test.hardening.skip"):
        reporter.skip(f"/data/{VALID_PAN}.zip", SkipReason.ARCHIVE_FAILED, f"member {VALID_PAN}")
    shown = caplog.text + "\n".join(reporter.summary_lines("/logs"))
    assert VALID_PAN not in shown
    assert "455673******9855" in shown


def test_reporter_clean_is_available_to_the_scanner():
    reporter = Reporter(Redactor(True), [], ScanStats(), LOGGER, 500)
    assert reporter.clean(f"a\nb {VALID_PAN}") == "a?b 455673******9855"
