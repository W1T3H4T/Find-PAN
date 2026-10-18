"""Tests for find_pan.logging_setup."""

import logging
import re
from pathlib import Path

import pytest

from find_pan import logging_setup
from find_pan.errors import LoggingSetupError
from find_pan.settings import Settings


@pytest.fixture(autouse=True)
def _clean_loggers():
    yield
    for name in ("_TraceLogObj", "_DefaultLogObj", "_AntiPanLogObj"):
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)


def make_settings(tmp_path, **overrides):
    values = dict(log_dir=str(tmp_path / "logs"))
    values.update(overrides)
    return Settings(**values)


def test_generate_logfile_name_uses_basename_and_date():
    assert re.fullmatch(r"Find-PAN-\d{2}[A-Z][a-z]{2}\d{4}\.log", logging_setup.generate_logfile_name("Find-PAN"))


def test_creates_log_directory(tmp_path):
    logging_setup.build_loggers(make_settings(tmp_path))
    assert (tmp_path / "logs").is_dir()




def test_creates_the_pan_and_trace_files(tmp_path):
    logging_setup.build_loggers(make_settings(tmp_path))
    logs = tmp_path / "logs"
    assert (logs / logging_setup.generate_logfile_name("Find-PAN")).exists()
    assert (logs / logging_setup.generate_logfile_name("Find-PAN-trace")).exists()


def test_debug_sets_trace_level_debug_else_info(tmp_path):
    assert logging_setup.build_loggers(make_settings(tmp_path)).trace.level == logging.INFO
    assert logging_setup.build_loggers(make_settings(tmp_path, debug=True)).trace.level == logging.DEBUG


def test_verbose_adds_console_handler_to_pan_logger(tmp_path):
    quiet = logging_setup.build_loggers(make_settings(tmp_path))
    quiet_streams = [h for h in quiet.pan.handlers if type(h) is logging.StreamHandler]
    loud = logging_setup.build_loggers(make_settings(tmp_path, verbose=True))
    loud_streams = [h for h in loud.pan.handlers if type(h) is logging.StreamHandler]
    assert not quiet_streams and len(loud_streams) == 1


def test_repeated_build_does_not_duplicate_handlers(tmp_path):
    settings = make_settings(tmp_path)
    logging_setup.build_loggers(settings)
    loggers = logging_setup.build_loggers(settings)
    assert len(loggers.pan.handlers) == 1
    assert len(loggers.trace.handlers) == 2  # console + file


def test_anti_pan_logger_absent_by_default_and_no_file(tmp_path):
    loggers = logging_setup.build_loggers(make_settings(tmp_path))
    assert loggers.anti_pan is None and loggers.anti_pan_path is None
    assert not list((tmp_path / "logs").glob("*anti-pan*"))


def test_anti_pan_logger_and_file_named_with_anti_pan_when_flag_set(tmp_path):
    loggers = logging_setup.build_loggers(make_settings(tmp_path, log_anti_pan=True))
    assert loggers.anti_pan is not None
    assert "anti-pan" in Path(loggers.anti_pan_path).name
    assert Path(loggers.anti_pan_path).parent == tmp_path / "logs"
    assert Path(loggers.anti_pan_path).exists()


def test_unwritable_log_dir_raises_logging_setup_error(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("file", encoding="utf-8")
    with pytest.raises(LoggingSetupError):
        logging_setup.build_loggers(Settings(log_dir=str(blocker)))


def test_log_files_are_written_as_utf8(tmp_path):
    """Final-review finding 3: U+FFFD from undecodable input must not be dropped on Windows."""
    loggers = logging_setup.build_loggers(make_settings(tmp_path, log_anti_pan=True))
    text = "finding with replacement char �"
    for logger in (loggers.pan, loggers.trace, loggers.anti_pan):
        logger.info(text)
        for handler in logger.handlers:
            handler.flush()
    logs = tmp_path / "logs"
    for log_file in logs.glob("*.log"):
        assert text in log_file.read_text(encoding="utf-8"), log_file.name


def _console_text(tmp_path, capsys, **settings):
    from find_pan import reporting
    from find_pan.models import Match, MatchKind
    from find_pan.redact import Redactor

    loggers = logging_setup.build_loggers(make_settings(tmp_path, **settings))
    match = Match("/data/a.txt", 3, 6, MatchKind.PAN, "VISA", "4[0-9]{15}", "4556737586899855",
                  "Card: 4556737586899855\n", "4556737586899855")
    reporting.LogSink(loggers.pan).emit(Redactor(False).apply(match))
    out = capsys.readouterr().out
    for handler in list(loggers.pan.handlers):
        handler.close()
    return out, (tmp_path / "logs")


def test_verbose_console_puts_each_class_of_item_on_its_own_line(tmp_path, capsys):
    out, _ = _console_text(tmp_path, capsys, verbose=True)
    lines = out.rstrip("\n").splitlines()
    assert lines[0].endswith("[INFO]: PAN match: VISA")
    assert [line.strip() for line in lines[1:]] == [
        "File    : /data/a.txt",
        "Location: line 3, offset 6",
        "Pattern : 4[0-9]{15}",
        "Data    : Card: 4556737586899855",
    ]


def test_verbose_console_separates_matches_with_one_empty_line(tmp_path, capsys):
    out, _ = _console_text(tmp_path, capsys, verbose=True)
    assert out.endswith("\n\n") and not out.endswith("\n\n\n")


def test_pan_log_file_keeps_the_single_line_format(tmp_path, capsys):
    _, logs = _console_text(tmp_path, capsys, verbose=True)
    text = next(logs.glob("Find-PAN-[0-9]*.log")).read_text(encoding="utf-8")
    assert "/data/a.txt:3:6->VISA (PAN), 4[0-9]{15}: Card: 4556737586899855" in text
    assert "File    :" not in text
