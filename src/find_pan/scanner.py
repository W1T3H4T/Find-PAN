"""Walks directories and archives and feeds every line to the detectors."""

import os

from find_pan.archives import extract_archive
from find_pan.detectors import scan_line
from find_pan.errors import ExtractorError
from find_pan.filetypes import skip_reason
from find_pan.logging_setup import Loggers
from find_pan.models import SkipReason
from find_pan.reporting import Reporter
from find_pan.settings import Settings


class Scanner:
    """Scans paths and archives, reporting results through a ``Reporter``."""

    def __init__(
        self,
        settings: Settings,
        patterns: list,
        reporter: Reporter,
        loggers: Loggers,
        extractor_config: dict | None = None,
    ) -> None:
        self.settings = settings
        self.patterns = patterns
        self.reporter = reporter
        self.loggers = loggers
        self.extractor_config = extractor_config or {}
        #   Messages for archives that could not be extracted; the caller reports them.
        self.extraction_errors: list[str] = []

    def scan_path(self, path: str) -> None:
        """Scan a directory tree."""
        self.loggers.trace.info("Filesystem Scan")
        self.scan_directory(path)

    def scan_directory(self, directory: str) -> None:
        self.loggers.trace.info("Scanning directory '%s' ...", directory)
        for root, _, files in os.walk(directory):
            self.loggers.pan.info("Scanning directory '%s' ...", root)
            for name in files:
                self.scan_file(os.path.join(root, name))

    def scan_file(self, file_path: str) -> None:
        """Scan one file, honoring --skip-binary and --line-limit."""
        if not os.path.isfile(file_path):
            return

        reason = skip_reason(
            file_path, self.settings.skip_binary, self.loggers.trace, self.settings.verbose
        )
        if reason is not None:
            self.loggers.pan.info("Binary file skipped: %s", file_path)
            self.reporter.skip(file_path, reason)
            return

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
            self.reporter.skip(file_path, SkipReason.UNREADABLE)

    def scan_archive(self, archive_path: str) -> None:
        """Extract *archive_path* with an external tool and scan its contents."""
        try:
            with extract_archive(
                archive_path,
                self.extractor_config,
                self.settings.tar_tmp,
                self.loggers.trace,
                verbose=self.settings.verbose,
            ) as directory:
                self.scan_directory(directory)
        except ExtractorError as error:
            self.loggers.pan.error("%s", error)
            self.extraction_errors.append(str(error))
