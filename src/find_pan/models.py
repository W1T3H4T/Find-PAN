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


class ScanStats:
    """Counters and timing for one scan."""

    def __init__(self) -> None:
        self._kinds: dict[MatchKind, int] = {kind: 0 for kind in MatchKind}
        self.files = 0
        self.skipped_files = 0
        self.binary = 0
        self.executable = 0
        self._started = 0.0
        self._stopped = 0.0

    def count(self, kind: MatchKind) -> int:
        return self._kinds[kind]

    def record(self, kind: MatchKind) -> None:
        self._kinds[kind] += 1

    def file_scanned(self) -> None:
        self.files += 1

    def skipped(self, reason: SkipReason) -> None:
        self.skipped_files += 1
        if reason is SkipReason.BINARY:
            self.binary += 1
        elif reason is SkipReason.EXECUTABLE:
            self.executable += 1

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
