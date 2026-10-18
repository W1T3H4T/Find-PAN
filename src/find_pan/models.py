"""Plain data types shared by the scanner, reporter and sinks."""

import time
from dataclasses import dataclass
from enum import Enum


class MatchKind(str, Enum):
    """What a match turned out to be."""

    PAN = "PAN"
    TRACK = "TRACK"
    ANTI_PAN = "ANTI-PAN"
    BAD_LUHN = "BAD-LUHN"


class SkipReason(str, Enum):
    """Why a file was not scanned."""

    BINARY = "BINARY"
    EXECUTABLE = "EXEC"
    UNREADABLE = "UNREADABLE"
    NOT_FOUND = "NOT-FOUND"
    NOT_A_FILE = "NOT-A-FILE"
    ARCHIVE_NO_TOOL = "ARCHIVE-NO-TOOL"
    ARCHIVE_FAILED = "ARCHIVE-FAILED"
    SYMLINK = "SYMLINK"


@dataclass(frozen=True)
class Match:
    """One raw (unredacted) detection on a line."""

    file_path: str
    line_number: int
    offset: int
    kind: MatchKind
    pattern_name: str
    pattern: str
    matched_data: str
    source_line: str
    pan: str
    #   Raw scans only: how the bytes were read ("ascii", "utf-16le", ...); then offset is a byte offset.
    encoding: str = ""


@dataclass(frozen=True)
class ExtractionLimits:
    """Bounds placed on one external extraction (decompression-bomb protection).

    The defaults are generous so ordinary archives never reach them; they can
    be raised or lowered in ``find-pan-conf.yaml``, globally or per extractor.
    """

    max_extracted_bytes: int = 10 * 1024 * 1024 * 1024
    max_files: int = 100_000
    timeout_seconds: int = 600
    min_free_bytes: int = 1024 * 1024 * 1024
    #   Archives nested inside archives, counting the outermost one; deeper ones are reported, not expanded.
    max_depth: int = 10


class ScanStats:
    """Counters and timing for one scan."""

    def __init__(self) -> None:
        self._kinds: dict[MatchKind, int] = {kind: 0 for kind in MatchKind}
        self.files = 0
        self.skipped_files = 0
        self.binary = 0
        self.executable = 0
        self.unreadable = 0
        self.archives_expanded = 0
        self._skip_reasons: dict[SkipReason, int] = {reason: 0 for reason in SkipReason}
        self._started = 0.0
        self._stopped = 0.0

    def count(self, kind: MatchKind) -> int:
        return self._kinds[kind]

    def record(self, kind: MatchKind) -> None:
        self._kinds[kind] += 1

    def file_scanned(self) -> None:
        self.files += 1

    def skipped(self, reason: SkipReason) -> None:
        """Record a file that was not (fully) scanned.

        Binary and executable files count as skipped.  Unreadable files are
        counted separately: one that fails to open was never scanned, and one
        that fails mid-read stays counted as scanned.
        """
        self._skip_reasons[reason] += 1
        if reason is SkipReason.UNREADABLE:
            self.unreadable += 1
        elif reason is SkipReason.BINARY:
            self.skipped_files += 1
            self.binary += 1
        elif reason is SkipReason.EXECUTABLE:
            self.skipped_files += 1
            self.executable += 1

    def archive_expanded(self) -> None:
        self.archives_expanded += 1

    @property
    def archives_skipped(self) -> int:
        """Archives that were not expanded (no tool available, or the tool failed)."""
        return (self._skip_reasons[SkipReason.ARCHIVE_NO_TOOL]
                + self._skip_reasons[SkipReason.ARCHIVE_FAILED])

    @property
    def failures(self) -> int:
        """Skips that mean requested content was never scanned (they make the run fail)."""
        return sum(self._skip_reasons[reason] for reason in (
            SkipReason.ARCHIVE_FAILED, SkipReason.NOT_FOUND, SkipReason.NOT_A_FILE))

    def start(self) -> None:
        self._started = time.time()
        self._stopped = self._started

    def stop(self) -> None:
        self._stopped = time.time()

    @property
    def total_time(self) -> float:
        return self._stopped - self._started

    @property
    def average_time(self) -> float:
        return self.total_time / self.files if self.files > 0 else 0
