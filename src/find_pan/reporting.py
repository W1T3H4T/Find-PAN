"""Reporting: counts matches, redacts them once, and fans them out to sinks.

Sinks only ever receive a ``RedactedMatch``.  Which sink shows which kind of
match is decided by the sink's ``accepts`` method, not by callers.
"""

import csv
import logging
import os
from typing import Protocol

from find_pan.errors import ConfigError
from find_pan.models import MatchKind, ScanStats, SkipReason
from find_pan.redact import RedactedMatch, Redactor

CSV_FIELDS = ["filename", "line_number", "offset", "pattern_name", "data_type", "matched_data"]
_LOG_FORMAT = "%s:%s:%s->%s (%s), %s: %s"


def sanitize_for_ascii(value: str) -> str:
    """Return an ASCII-only form of *value*; other characters become ``?``."""
    return "".join(char if 32 <= ord(char) <= 126 else "?" for char in value)


class Sink(Protocol):
    """Where redacted matches go."""

    def accepts(self, kind: MatchKind) -> bool: ...

    def emit(self, view: RedactedMatch) -> None: ...

    def close(self) -> None: ...


def _log_line(logger: logging.Logger, view: RedactedMatch) -> None:
    logger.info(
        _LOG_FORMAT, view.file_path, view.line_number, view.offset,
        view.pattern_name, view.kind.value, view.pattern, view.source_line,
    )


class LogSink:
    """Writes PAN and TRACK findings to the PAN log."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def accepts(self, kind: MatchKind) -> bool:
        return kind in (MatchKind.PAN, MatchKind.TRACK)

    def emit(self, view: RedactedMatch) -> None:
        _log_line(self._logger, view)

    def close(self) -> None:
        """Nothing to release; the logger owns its handlers."""


class CsvSink:
    """Writes PAN and TRACK findings to a CSV file, flushing every row."""

    def __init__(self, path: str) -> None:
        try:
            self._file = open(path, "w", newline="", encoding="utf-8")
        except OSError as error:
            raise ConfigError(f"Cannot open CSV output '{path}': {error}") from error
        self._writer = csv.DictWriter(self._file, fieldnames=CSV_FIELDS)
        self._writer.writeheader()
        self._file.flush()

    def accepts(self, kind: MatchKind) -> bool:
        return kind in (MatchKind.PAN, MatchKind.TRACK)

    def emit(self, view: RedactedMatch) -> None:
        self._writer.writerow({
            "filename": sanitize_for_ascii(os.path.basename(view.file_path)),
            "line_number": view.line_number,
            "offset": view.offset,
            "pattern_name": sanitize_for_ascii(view.pattern_name),
            "data_type": sanitize_for_ascii(view.kind.value),
            "matched_data": sanitize_for_ascii(view.matched_data),
        })
        self._file.flush()

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()


class TraceSink:
    """Writes Luhn failures to the trace log at DEBUG level."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def accepts(self, kind: MatchKind) -> bool:
        return kind is MatchKind.BAD_LUHN

    def emit(self, view: RedactedMatch) -> None:
        self._logger.debug(
            "Luhn failure: file=%s line=%s offset=%s pattern=%s extracted=%s matched=%s",
            view.file_path, view.line_number, view.offset, view.pattern_name,
            view.pan, view.matched_data,
        )

    def close(self) -> None:
        """Nothing to release; the logger owns its handlers."""


class AntiPanSink:
    """Writes anti-PAN hits to their own log (only built with --log-anti-pan)."""

    def __init__(self, logger: logging.Logger, path: str) -> None:
        self._logger = logger
        self.path = path
        self.entries = 0

    def accepts(self, kind: MatchKind) -> bool:
        return kind is MatchKind.ANTI_PAN

    def emit(self, view: RedactedMatch) -> None:
        _log_line(self._logger, view)
        self.entries += 1

    def close(self) -> None:
        """Nothing to release; the logger owns its handlers."""


class Reporter:
    """Single entry point for everything the scanner finds or skips."""

    def __init__(
        self,
        redactor: Redactor,
        sinks: list,
        stats: ScanStats,
        trace_logger: logging.Logger,
        report_delta: int,
    ) -> None:
        self.redactor = redactor
        self.sinks = sinks
        self.stats = stats
        self._trace = trace_logger
        self._report_delta = report_delta
        self._closed = False

    def report(self, match) -> None:
        """Count *match*, redact it once, and emit it to the sinks that accept it."""
        self.stats.record(match.kind)
        view = self.redactor.apply(match)
        for sink in self.sinks:
            if sink.accepts(match.kind):
                sink.emit(view)

    def file_started(self) -> None:
        """Count a file about to be scanned and log periodic progress."""
        self.stats.file_scanned()
        if self.stats.files % self._report_delta == 0:
            self._trace.info(
                "Scanned %s files; matched %s PANs, %s TRACKs, %s Files Skipped",
                self.stats.files,
                self.stats.count(MatchKind.PAN),
                self.stats.count(MatchKind.TRACK),
                self.stats.skipped_files,
            )

    def skip(self, path: str, reason: SkipReason) -> None:
        """Record that *path* was not scanned."""
        self._trace.debug("Skipped %s (%s)", path, reason.value)
        self.stats.skipped(reason)

    def summary_lines(self, log_dir: str) -> list[str]:
        """Return the end-of-run summary, one string per line."""
        stats = self.stats
        pans = stats.count(MatchKind.PAN)
        tracks = stats.count(MatchKind.TRACK)
        lines = [
            "",
            "-- Processing Summary --",
            f"PANs Matched  : {pans:8d}",
            f"TRACKs Matched: {tracks:8d}",
            f"Total matches : {pans + tracks:8d}",
            f"Scanned       : {stats.files:8d} Files.",
            f"Average time  : {stats.average_time:8.3f} seconds per file",
            f"Total time    : {stats.total_time:8.3f} seconds",
            "",
            "-- Skipped Summary --",
            f"Detected {stats.count(MatchKind.BAD_LUHN)} Luhn Check Failures.",
            f"Detected {stats.count(MatchKind.ANTI_PAN)} Anti-PANs.",
        ]
        for sink in self.sinks:
            if isinstance(sink, AntiPanSink):
                lines.append(f"Anti-PAN log   : {sink.path}")
                lines.append(f"Anti-PANs logged: {sink.entries}")
        lines += [
            f"Skipped {stats.skipped_files} Files.",
            f"Skipped {stats.executable} Executable Files.",
            f"Skipped {stats.binary} Binary Files.",
        ]
        if stats.unreadable:
            lines.append(f"Unreadable {stats.unreadable} Files.")
        lines += [
            "",
            "Scan complete.",
            "",
            f"Log files are located in: {log_dir}",
        ]
        return lines

    def close(self) -> None:
        """Close every sink; re-raise the first failure after all were attempted."""
        if self._closed:
            return
        self._closed = True
        first_error = None
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as error:  # pylint: disable=broad-exception-caught
                first_error = first_error or error
        if first_error is not None:
            raise first_error
