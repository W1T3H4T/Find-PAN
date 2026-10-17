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
    values = dict(log_dir=str(tmp_path / "logs"), tar_tmp=str(tmp_path / "tar-tmp"))
    values.update(overrides)
    return Settings(**values)


def test_generate_logfile_name_uses_basename_and_date():
    assert re.fullmatch(r"Find-PAN-\d{2}[A-Z][a-z]{2}\d{4}\.log", logging_setup.generate_logfile_name("Find-PAN"))


def test_creates_log_and_tar_tmp_directories(tmp_path):
    logging_setup.build_loggers(make_settings(tmp_path))
    assert (tmp_path / "logs").is_dir()
    assert (tmp_path / "tar-tmp").is_dir()


def test_creates_pan_and_trace_files_and_removes_prior_ones(tmp_path):
    settings = make_settings(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    pan_name = logging_setup.generate_logfile_name("Find-PAN")
    (logs / pan_name).write_text("stale", encoding="utf-8")

    loggers = logging_setup.build_loggers(settings)
    loggers.pan.info("fresh")
    for handler in loggers.pan.handlers:
        handler.flush()

    assert "stale" not in (logs / pan_name).read_text(encoding="utf-8")
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
        logging_setup.build_loggers(Settings(log_dir=str(blocker), tar_tmp=str(tmp_path / "t")))


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
