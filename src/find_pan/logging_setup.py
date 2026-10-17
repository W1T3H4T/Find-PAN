"""Builds the PAN, trace and (optional) anti-PAN loggers from ``Settings``."""

import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime

from find_pan.errors import LoggingSetupError
from find_pan.settings import Settings

_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s"
TRACE_LOGGER_NAME = "_TraceLogObj"
PAN_LOGGER_NAME = "_DefaultLogObj"
ANTI_PAN_LOGGER_NAME = "_AntiPanLogObj"


@dataclass
class Loggers:
    """The loggers a scan writes to."""

    pan: logging.Logger
    trace: logging.Logger
    anti_pan: logging.Logger | None = None
    anti_pan_path: str | None = None


def generate_logfile_name(basename: str) -> str:
    """Return ``<basename>-<DDMonYYYY>.log``."""
    return f"{basename}-{datetime.now().strftime('%d%b%Y')}.log"


def _fresh_logger(name: str, level: int) -> logging.Logger:
    """Return the named logger with no handlers, so repeated builds never stack."""
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    logger.setLevel(level)
    return logger


def _add_file_handler(logger: logging.Logger, path: str, level: int) -> None:
    #   Append, never delete: a second run on the same day must not destroy the
    #   audit trail of the first.  UTF-8 so U+FFFD from undecodable input never
    #   drops a finding on Windows.
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(handler)


def build_loggers(settings: Settings) -> Loggers:
    """Create the log directories and loggers.

    Log files from earlier runs the same day are appended to, not replaced.  The anti-PAN logger and
    its file exist only when ``settings.log_anti_pan`` is set.

    Raises ``LoggingSetupError`` when a directory or log file cannot be created.
    """
    try:
        os.makedirs(settings.log_dir, exist_ok=True)

        formatter = logging.Formatter(_FORMAT)
        trace_level = logging.DEBUG if settings.debug else logging.INFO

        trace = _fresh_logger(TRACE_LOGGER_NAME, trace_level)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(trace_level)
        console.setFormatter(formatter)
        trace.addHandler(console)
        _add_file_handler(
            trace,
            os.path.join(settings.log_dir, generate_logfile_name("Find-PAN-trace")),
            trace_level,
        )

        pan = _fresh_logger(PAN_LOGGER_NAME, logging.DEBUG)
        _add_file_handler(
            pan, os.path.join(settings.log_dir, generate_logfile_name("Find-PAN")), logging.DEBUG
        )
        if settings.verbose:
            pan_console = logging.StreamHandler(sys.stdout)
            pan_console.setLevel(logging.DEBUG)
            pan_console.setFormatter(formatter)
            pan.addHandler(pan_console)

        anti_pan = None
        anti_pan_path = None
        if settings.log_anti_pan:
            anti_pan = _fresh_logger(ANTI_PAN_LOGGER_NAME, logging.INFO)
            anti_pan_path = os.path.join(
                settings.log_dir, generate_logfile_name("Find-PAN-anti-pan")
            )
            _add_file_handler(anti_pan, anti_pan_path, logging.INFO)
    except OSError as error:
        raise LoggingSetupError(f"Cannot set up logging in '{settings.log_dir}': {error}") from error

    return Loggers(pan=pan, trace=trace, anti_pan=anti_pan, anti_pan_path=anti_pan_path)
