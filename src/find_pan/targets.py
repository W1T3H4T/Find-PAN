"""Report filters: the PAN and track data an inspector wants reported (``--pan-list``, ``--track-list``).

The lists are not a source of PAN or track data.  Only what the configured patterns accepted can ever be
reported; with a list, a PAN or track that is not on it is dropped, and the end of the run says which listed
values were found (how often, and where first) and which were not.
"""

import re
from dataclasses import dataclass

from find_pan.detectors import TRACK_CATEGORY
from find_pan.errors import ConfigError
from find_pan.models import MatchKind

#   How many locations are remembered per value; the count is exact.
MAX_LOCATIONS = 3


def _read_values(path: str) -> list[tuple[int, str]]:
    """Return ``(line number, text)`` for every value line: blank lines and ``#`` comments are dropped."""
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigError(f"cannot read list file '{path}': {error}") from error
    values = [(number, line.strip()) for number, line in enumerate(lines, 1)
              if line.strip() and not line.strip().startswith("#")]
    if not values:
        raise ConfigError(f"list file '{path}' has no values")
    return values


def load_pan_list(path: str) -> tuple[str, ...]:
    """Read PANs, one per line (spaces and dashes allowed); duplicates are dropped, order is kept."""
    pans: dict[str, None] = {}
    for number, text in _read_values(path):
        digits = re.sub(r"[ -]", "", text)
        if not re.fullmatch(r"[0-9]{12,19}", digits):
            raise ConfigError(f"{path}:{number}: not a PAN (12 to 19 digits expected): {text!r}")
        pans[digits] = None
    return tuple(pans)


def load_track_list(path: str, patterns: list) -> tuple[str, ...]:
    """Read track 1 or track 2 strings, one per line; duplicates are dropped, order is kept.

    A line must be whole track data by one of the configured TRACK patterns.
    """
    tracks: dict[str, None] = {}
    track_patterns = [compiled for category, _, compiled in patterns if category == TRACK_CATEGORY]
    for number, text in _read_values(path):
        if not any(compiled.fullmatch(text) for compiled in track_patterns):
            raise ConfigError(f"{path}:{number}: not track data by any configured TRACK pattern")
        tracks[text] = None
    return tuple(tracks)


@dataclass(frozen=True)
class Targets:
    """The listed values; an empty tuple means that kind is not filtered."""

    pans: tuple[str, ...] = ()
    tracks: tuple[str, ...] = ()


@dataclass
class LedgerEntry:
    """What was seen of one listed value."""

    kind: MatchKind
    value: str
    count: int = 0
    locations: list = None

    def __post_init__(self) -> None:
        self.locations = [] if self.locations is None else self.locations


class TargetLedger:
    """Tallies, per listed value, how often it was found and where first."""

    def __init__(self, targets: Targets) -> None:
        self._entries = {(MatchKind.PAN, value): LedgerEntry(MatchKind.PAN, value) for value in targets.pans}
        self._entries.update({(MatchKind.TRACK, value): LedgerEntry(MatchKind.TRACK, value)
                              for value in targets.tracks})

class TargetLedger:
    """Filters matches by the lists and tallies, per listed value, how often it was found and where first."""

    def __init__(self, targets: Targets) -> None:
        self._entries = {(MatchKind.PAN, value): LedgerEntry(MatchKind.PAN, value) for value in targets.pans}
        self._entries.update({(MatchKind.TRACK, value): LedgerEntry(MatchKind.TRACK, value)
                              for value in targets.tracks})
        self._filtered = {MatchKind.PAN: bool(targets.pans), MatchKind.TRACK: bool(targets.tracks)}

    def admit(self, match) -> bool:
        """Whether *match* may be reported; a listed PAN or track that is admitted is tallied.

        Only accepted PAN and TRACK matches are filtered, each by its own list.
        """
        if match.kind not in (MatchKind.PAN, MatchKind.TRACK):
            return True
        value = match.pan if match.kind is MatchKind.PAN else match.matched_data
        entry = self._entries.get((match.kind, value))
        if entry is None:
            return not self._filtered[match.kind]
        entry.count += 1
        if len(entry.locations) < MAX_LOCATIONS:
            entry.locations.append(_location(match))
        return True

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries.values())

    def total(self, kind: MatchKind) -> int:
        return sum(entry.kind is kind for entry in self._entries.values())

    def found(self, kind: MatchKind) -> int:
        return sum(entry.kind is kind and entry.count > 0 for entry in self._entries.values())


def _location(match) -> str:
    """Where a match was found: ``file:line:column`` in text, ``file@0xOFFSET (encoding)`` in raw scans."""
    if match.encoding:
        return f"{match.file_path}@0x{match.offset:X} ({match.encoding})"
    return f"{match.file_path}:{match.line_number}:{match.offset}"
