"""Walks paths and feeds every file through one processor.

``Scanner.process_file`` is the single entry point for every file, whether it
came from ``--file``, a ``--path`` walk, or the inside of an expanded archive.
It classifies the file by content, then skips it, expands it (archives), or
scans it as text.
"""

import os
from dataclasses import dataclass
from typing import Callable, Iterable

from find_pan.archives import extract_archive
from find_pan.detectors import scan_line
from find_pan.errors import ConfigError, ExtractorUnavailable, ExtractorError
from find_pan.filetypes import FileKind, classify
from find_pan.logging_setup import Loggers
from find_pan.models import SkipReason
from find_pan.reporting import Reporter
from find_pan.settings import Settings


@dataclass(frozen=True)
class Problem:
    """Something the user should be told about on stderr (the scan continues)."""

    severity: str   # "warning" or "error"
    message: str


class Scanner:
    """Scans paths, reporting results through a ``Reporter``.

    *load_extractors* returns the archive-extractor configuration.  It is
    called lazily, once, the first time an archive is met, so runs without
    archives never touch that configuration.
    """

    def __init__(
        self,
        settings: Settings,
        patterns: list,
        reporter: Reporter,
        loggers: Loggers,
        load_extractors: Callable[[], dict] | None = None,
    ) -> None:
        self.settings = settings
        self.patterns = patterns
        self.reporter = reporter
        self.loggers = loggers
        self.problems: list[Problem] = []
        self._load_extractors = load_extractors
        self._extractors: dict | None = None

    # -- entry points ------------------------------------------------------

    def scan_files(self, paths: Iterable[str]) -> None:
        """Process each ``--file`` entry; bad entries are reported and skipped."""
        for path in paths:
            if not os.path.exists(path):
                self._skip(path, SkipReason.NOT_FOUND, "no such file", "error")
            elif not os.path.isfile(path):
                self._skip(path, SkipReason.NOT_A_FILE, "not a file (directories need --path)", "error")
            else:
                self.process_file(path)

    def scan_path(self, path: str) -> None:
        """Walk a directory tree, processing every file in it."""
        self.loggers.trace.info("Filesystem Scan")
        self._walk(path)

    # -- the single file processor ------------------------------------------

    def process_file(self, file_path: str) -> None:
        """Classify *file_path* by content and skip, expand or scan it."""
        if not os.path.isfile(file_path):
            return
        try:
            classification = classify(
                file_path, self.settings.skip_binary, self.loggers.trace, self.settings.verbose
            )
        except OSError as error:
            self._skip(file_path, SkipReason.UNREADABLE, str(error))
            return

        if classification.note:
            self.loggers.pan.info("%s: %s", file_path, classification.note)

        if classification.kind is FileKind.ARCHIVE:
            self._expand(file_path, classification.archive_type)
        elif classification.kind is FileKind.EXECUTABLE:
            self._skip(file_path, SkipReason.EXECUTABLE)
        elif classification.kind is FileKind.BINARY:
            self._skip(file_path, SkipReason.BINARY)
        else:
            self._scan_text(file_path)

    # -- helpers -------------------------------------------------------------

    def _walk(self, directory: str) -> None:
        self.loggers.trace.info("Scanning directory '%s' ...", directory)
        for root, _, files in os.walk(directory):
            self.loggers.pan.info("Scanning directory '%s' ...", root)
            for name in files:
                self.process_file(os.path.join(root, name))

    def _scan_text(self, file_path: str) -> None:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                self.loggers.pan.info("Scanning %s", os.path.basename(file_path))
                self.reporter.file_started()
                limit = self.settings.line_limit
                for line_number, line in enumerate(handle, 1):
                    if limit > 0 and line_number > limit:
                        break
                    for match in scan_line(file_path, line_number, line, self.patterns):
                        self.reporter.report(match)
        except OSError as error:
            self.loggers.trace.warning("Skipping file due to error: %s - %s", file_path, error)
            self._skip(file_path, SkipReason.UNREADABLE, str(error))

    def _extractors_config(self) -> dict:
        if self._extractors is None:
            try:
                self._extractors = self._load_extractors() if self._load_extractors else {}
            except (ConfigError, FileNotFoundError, ValueError, OSError) as error:
                self.problems.append(Problem("warning", f"Archive extractors unavailable: {error}"))
                self._extractors = {}
        return self._extractors

    def _expand(self, archive_path: str, archive_type: str | None) -> None:
        try:
            with extract_archive(
                archive_path,
                self._extractors_config(),
                self.loggers.trace,
                archive_type=archive_type,
                verbose=self.settings.verbose,
            ) as directory:
                self.reporter.archive_expanded()
                self._walk(directory)
        except ExtractorUnavailable as error:
            self._skip(archive_path, SkipReason.ARCHIVE_NO_TOOL, str(error), "warning")
        except ExtractorError as error:
            self._skip(archive_path, SkipReason.ARCHIVE_FAILED, str(error), "error")

    def _skip(self, path: str, reason: SkipReason, detail: str = "", severity: str | None = None) -> None:
        self.reporter.skip(path, reason, detail)
        if severity is not None:
            self.problems.append(Problem(severity, f"{path}: {detail}" if detail else path))
