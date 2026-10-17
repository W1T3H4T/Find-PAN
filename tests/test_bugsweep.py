"""Tests for the bug sweep: appended logs, one open per file, the binary heuristic, a cached
libmagic, the timestamp bound and the exception-test hook."""

import builtins
import logging
import sys
import types
from datetime import datetime
from pathlib import Path

import pytest

from find_pan import cli, detectors, filetypes, logging_setup
from find_pan import scanner as scanner_module
from find_pan.logging_setup import Loggers
from find_pan.models import MatchKind, ScanStats
from find_pan.redact import Redactor
from find_pan.reporting import Reporter
from find_pan.settings import Settings

VALID_PAN = "4556737586899855"


# --- timestamps in the future are not anti-PAN timestamps ----------------------------


def test_timestamp_in_the_current_year_is_valid():
    year = datetime.now().year
    assert detectors.valid_timestamp(f"{year}0101000000")


def test_timestamp_in_the_next_year_is_rejected():
    assert not detectors.valid_timestamp(f"{datetime.now().year + 1}0101000000")


def test_far_future_and_ancient_timestamps_are_rejected():
    assert not detectors.valid_timestamp("20991231235959")
    assert not detectors.valid_timestamp("18991231235959")


# --- the binary heuristic -------------------------------------------------------------


def test_nul_byte_alone_makes_a_file_binary():
    assert filetypes.looks_binary(b"abc\x00def" + b"x" * 100)


def test_plain_text_and_latin1_text_are_not_binary():
    assert not filetypes.looks_binary(b"plain text\nwith lines\n" * 20)
    assert not filetypes.looks_binary("café crème\n".encode("latin-1") * 20)
    assert not filetypes.looks_binary(b"")


def test_utf16_text_with_a_bom_is_not_binary():
    text = "card 4556737586899855\n".encode("utf-16")      # starts with a BOM, contains NULs
    assert not filetypes.looks_binary(text)


def test_control_character_heavy_data_without_nul_is_binary():
    assert filetypes.looks_binary(bytes(range(1, 9)) * 100)


def test_the_last_bytes_of_the_sample_count_too():
    assert filetypes.looks_binary(b"x" * 1000 + b"\x00")


# --- libmagic is constructed once -----------------------------------------------------------


def install_counting_magic(monkeypatch, mime="text/plain"):
    created = []

    class Magic:
        def __init__(self, *args, **kwargs):
            created.append(1)

        def from_file(self, path):
            return mime

        def from_buffer(self, buffer):
            return mime

    module = types.ModuleType("magic")
    module.Magic = Magic
    monkeypatch.setitem(sys.modules, "magic", module)
    return created


def test_magic_is_constructed_once_for_many_files(tmp_path, monkeypatch):
    created = install_counting_magic(monkeypatch)
    logger = logging.getLogger("test.sweep")
    for index in range(5):
        path = tmp_path / f"f{index}.txt"
        path.write_text("hello\n", encoding="utf-8")
        filetypes.is_executable(str(path), logger)
    assert len(created) == 1


def test_magic_buffer_is_used_when_a_head_is_supplied(tmp_path, monkeypatch):
    install_counting_magic(monkeypatch, mime="application/x-dosexec")
    path = tmp_path / "prog.exe"                 # never opened: the buffer is enough
    assert filetypes.is_executable(str(path), logging.getLogger("test.sweep"), head=b"MZ" + b"\x00" * 60)


# --- each file is opened once ------------------------------------------------------------------


@pytest.fixture
def build(compiled_patterns):
    loggers = Loggers(pan=logging.getLogger("test.sweep.pan"), trace=logging.getLogger("test.sweep.trace"))

    def _build(**settings):
        views = []

        class Collector:
            def accepts(self, kind):
                return True

            def emit(self, view):
                views.append(view)

            def close(self):
                pass

        reporter = Reporter(Redactor(False), [Collector()], ScanStats(), loggers.trace, 500)
        return scanner_module.Scanner(Settings(**settings), compiled_patterns, reporter, loggers), reporter, views

    return _build


def test_a_text_file_is_opened_exactly_once(build, tmp_path, monkeypatch):
    install_counting_magic(monkeypatch)
    target = tmp_path / "a.txt"
    target.write_text(f"card {VALID_PAN}\n", encoding="utf-8")
    opened = []
    real_open = builtins.open

    def counting_open(path, *args, **kwargs):
        if str(path) == str(target):
            opened.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)
    scanner, _, views = build(skip_binary=True)
    scanner.process_file(str(target))
    assert len(opened) == 1
    assert [view.pan for view in views if view.kind is MatchKind.PAN] == [VALID_PAN]


def test_a_file_that_is_utf16_text_is_still_scanned_not_skipped(build, tmp_path, monkeypatch):
    install_counting_magic(monkeypatch)
    target = tmp_path / "utf16.txt"
    target.write_bytes(f"card {VALID_PAN}\n".encode("utf-8"))
    scanner, reporter, views = build(skip_binary=True)
    scanner.process_file(str(target))
    assert reporter.stats.binary == 0 and len(views) == 1


def test_a_nul_containing_file_is_skipped_as_binary_with_skip_binary(build, tmp_path, monkeypatch):
    install_counting_magic(monkeypatch)
    target = tmp_path / "blob.bin"
    target.write_bytes(b"abc\x00def" + b"x" * 50)
    scanner, reporter, _ = build(skip_binary=True)
    scanner.process_file(str(target))
    assert reporter.stats.binary == 1 and reporter.stats.files == 0


# --- earlier runs' logs are kept ------------------------------------------------------------------


def test_logs_from_an_earlier_run_the_same_day_are_kept(tmp_path):
    settings = Settings(log_dir=str(tmp_path / "logs"))
    first = logging_setup.build_loggers(settings)
    first.pan.info("evidence from run one")
    first.trace.info("trace from run one")
    second = logging_setup.build_loggers(settings)
    second.pan.info("run two")
    for logger in (second.pan, second.trace):
        for handler in logger.handlers:
            handler.flush()
    pan_text = (tmp_path / "logs" / logging_setup.generate_logfile_name("Find-PAN")).read_text(encoding="utf-8")
    trace_text = (tmp_path / "logs" / logging_setup.generate_logfile_name("Find-PAN-trace")).read_text(encoding="utf-8")
    assert "evidence from run one" in pan_text and "run two" in pan_text
    assert "trace from run one" in trace_text


def test_anti_pan_log_is_appended_too(tmp_path):
    settings = Settings(log_dir=str(tmp_path / "logs"), log_anti_pan=True)
    logging_setup.build_loggers(settings).anti_pan.info("first")
    second = logging_setup.build_loggers(settings)
    second.anti_pan.info("second")
    for handler in second.anti_pan.handlers:
        handler.flush()
    text = Path(second.anti_pan_path).read_text(encoding="utf-8")
    assert "first" in text and "second" in text


def test_each_run_writes_a_start_marker(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    for _ in range(2):
        assert cli.main(["--path", str(scan_dir), "--log-dir", str(tmp_path / "logs")]) == 0
    capsys.readouterr()
    pan_log = (tmp_path / "logs" / logging_setup.generate_logfile_name("Find-PAN")).read_text(encoding="utf-8")
    assert pan_log.count("Find-PAN run started") == 2


# --- --exception-test is not a user-facing flag -----------------------------------------------------------


def test_exception_test_is_not_an_advertised_option(capsys):
    with pytest.raises(SystemExit) as info:
        cli.parse_args(["--exception-test"])
    assert info.value.code == 2
    assert "exception-test" not in cli.build_parser().format_help()


def test_exception_handler_can_still_be_exercised_through_the_environment(monkeypatch, capsys):
    monkeypatch.setenv("FIND_PAN_EXCEPTION_TEST", "1")
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 1
    assert "Exception Information:" in capsys.readouterr().out


def test_environment_variable_off_by_default(monkeypatch, capsys):
    monkeypatch.delenv("FIND_PAN_EXCEPTION_TEST", raising=False)
    assert cli.main(["--version"]) == 0
