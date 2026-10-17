"""Walks paths and feeds every file through one processor.

``Scanner.process_file`` is the single entry point for every file, whether it
came from ``--file``, a ``--path`` walk, or the inside of an expanded archive.
It classifies the file by content, then skips it, expands it (archives), or
scans it as text.
"""

import hashlib
import io
import os
from dataclasses import dataclass
from typing import Callable, Iterable

from find_pan.archives import extract_archive
from find_pan.detectors import scan_line
from find_pan.errors import ConfigError, ExtractorUnavailable, ExtractorError
from find_pan.filetypes import FileClassification, FileKind, classify_head
from find_pan.logging_setup import Loggers
from find_pan.models import ExtractionLimits, SkipReason
from find_pan.reporting import Reporter
from find_pan.settings import Settings

#   Bytes read from the start of a file to classify it.
_SAMPLE_BYTES = 1024


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
        load_limits: Callable[[], ExtractionLimits] | None = None,
    ) -> None:
        self.settings = settings
        self.patterns = patterns
        self.reporter = reporter
        self.loggers = loggers
        self.problems: list[Problem] = []
        self._load_extractors = load_extractors
        self._extractors: dict | None = None
        self._load_limits = load_limits
        self._limits: ExtractionLimits | None = None
        #   Content digests of the archives currently being expanded (outermost first).
        self._expanding: list[str] = []
        #   (extraction directory, display path of its archive), outermost first.
        self._extractions: list[tuple[str, str]] = []

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
            #   One open serves classification and the text scan, so the file cannot
            #   change in between and no second open can fail differently.
            with open(file_path, "rb") as raw:
                head = raw.read(_SAMPLE_BYTES)
                classification = classify_head(
                    head, file_path, self.settings.skip_binary, self.loggers.trace, self.settings.verbose
                )
                if classification.kind is FileKind.TEXT:
                    self._note(file_path, classification)
                    raw.seek(0)
                    self._scan_text(file_path, io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
                    return
        except OSError as error:
            self._skip(file_path, SkipReason.UNREADABLE, str(error))
            return

        self._note(file_path, classification)
        if classification.kind is FileKind.ARCHIVE:
            self._expand(file_path, classification.archive_type)
        elif classification.kind is FileKind.EXECUTABLE:
            self._skip(file_path, SkipReason.EXECUTABLE)
        elif classification.kind is FileKind.BINARY:
            self._skip(file_path, SkipReason.BINARY)

    # -- helpers -------------------------------------------------------------

    def _walk(self, directory: str, extracted: bool = False) -> None:
        """Process every file under *directory*.

        Inside an extracted tree symbolic links are never followed: a hostile
        archive could point one at a file outside the extraction directory.
        """
        self.loggers.trace.info("Scanning directory '%s' ...", directory)
        for root, _, files in os.walk(directory):
            self.loggers.pan.info("Scanning directory '%s' ...", root)
            for name in files:
                path = os.path.join(root, name)
                if extracted and os.path.islink(path):
                    self._skip(path, SkipReason.SYMLINK, "symbolic link inside an archive is not followed")
                    continue
                self.process_file(path)

    def _note(self, file_path: str, classification: FileClassification) -> None:
        if classification.note:
            self.loggers.pan.info("%s: %s", file_path, classification.note)

    def _scan_text(self, file_path: str, handle) -> None:
        try:
            with handle:
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

    def _limits_config(self) -> ExtractionLimits:
        if self._limits is None:
            try:
                self._limits = self._load_limits() if self._load_limits else ExtractionLimits()
            except (ConfigError, FileNotFoundError, ValueError, OSError) as error:
                self.problems.append(Problem("warning", f"Extraction limits unavailable, using defaults: {error}"))
                self._limits = ExtractionLimits()
        return self._limits

    @staticmethod
    def _digest(path: str) -> str:
        sha = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                sha.update(block)
        return sha.hexdigest()

    def _expand(self, archive_path: str, archive_type: str | None) -> None:
        try:
            digest = self._digest(archive_path)
        except OSError as error:
            self._skip(archive_path, SkipReason.UNREADABLE, str(error))
            return
        if digest in self._expanding:
            #   An archive found inside its own expansion would recurse forever.
            self._skip(archive_path, SkipReason.ARCHIVE_FAILED,
                       "archive contains itself (recursive archive)", "error")
            return
        self._expanding.append(digest)
        try:
            self._expand_unchecked(archive_path, archive_type)
        finally:
            self._expanding.pop()

    def _expand_unchecked(self, archive_path: str, archive_type: str | None) -> None:
        try:
            with extract_archive(
                archive_path,
                self._extractors_config(),
                self.loggers.trace,
                archive_type=archive_type,
                verbose=self.settings.verbose,
                limits=self._limits_config(),
            ) as directory:
                self.reporter.archive_expanded()
                self._extractions.append((directory, self.display_path(archive_path)))
                try:
                    self._walk(directory, extracted=True)
                finally:
                    self._extractions.pop()
        except ExtractorUnavailable as error:
            self._skip(archive_path, SkipReason.ARCHIVE_NO_TOOL, str(error), "warning")
        except ExtractorError as error:
            self._skip(archive_path, SkipReason.ARCHIVE_FAILED, str(error), "error")

    def display_path(self, path: str) -> str:
        """Return a stable, platform-independent name for *path*.

        A file inside an extracted archive is shown as ``<archive>!/<member>`` (chained for
        nested archives) instead of its random temporary location; separators are ``/``.
        """
        for directory, prefix in reversed(self._extractions):
            if path.startswith(directory + os.sep):
                return f"{prefix}!/{path[len(directory) + 1:].replace(os.sep, '/')}"
        return path.replace(os.sep, "/")

    def _skip(self, path: str, reason: SkipReason, detail: str = "", severity: str | None = None) -> None:
        path = self.display_path(path)
        self.reporter.skip(path, reason, detail)
        if severity is not None:
            message = f"{path}: {detail}" if detail else path
            self.problems.append(Problem(severity, self.reporter.clean(message)))
