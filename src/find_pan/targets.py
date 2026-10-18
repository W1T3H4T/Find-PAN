"""Expected values: PAN and track data an inspector wants to find (or confirm is absent).

``--pan-list`` and ``--track-list`` name files holding the values.  Every occurrence of a listed value is
counted wherever it is found, whether or not a configured pattern would have recognised it, and the end of
the run lists each value as found (how often, and where first) or not found.
"""

import re
from dataclasses import dataclass

from find_pan.detectors import extract_pan
from find_pan.errors import ConfigError
from find_pan.models import Match, MatchKind

#   How many locations are remembered per value; the count is exact.
MAX_LOCATIONS = 3

_PAN_RUN = re.compile(r"(?<![0-9])[0-9]{12,19}(?![0-9])")
_TRACK = re.compile(r"%[BM][0-9]{12,19}\^[^^]*\^[0-9]*\??|;[0-9]{12,19}=[0-9]*\??")


@dataclass(frozen=True)
class TargetHit:
    """One occurrence of a listed value in a piece of text."""

    kind: MatchKind
    value: str
    start: int
    end: int


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


def load_track_list(path: str) -> tuple[str, ...]:
    """Read track 1 or track 2 strings, one per line; duplicates are dropped, order is kept."""
    tracks: dict[str, None] = {}
    for number, text in _read_values(path):
        if not _TRACK.fullmatch(text):
            raise ConfigError(f"{path}:{number}: not track 1 (%B...^...^...?) or track 2 (;...=...?) data")
        tracks[text] = None
    return tuple(tracks)


class Targets:
    """The listed values, and a way to find them in text."""

    def __init__(self, pans: tuple[str, ...] = (), tracks: tuple[str, ...] = ()) -> None:
        self.pans = tuple(pans)
        self.tracks = tuple(tracks)
        self._pan_set = frozenset(self.pans)
        ordered = sorted(self.tracks, key=len, reverse=True)
        self._track_regex = re.compile("|".join(re.escape(track) for track in ordered)) if ordered else None

    def find(self, text: str) -> list[TargetHit]:
        """Return every occurrence of a listed value in *text*, in text order.

        A PAN counts only between non-digits, so it is never taken from the middle of a longer number.  A
        listed PAN inside listed track data is found too: the PAN is present either way.
        """
        hits = []
        if self._pan_set:
            for found in _PAN_RUN.finditer(text):
                if found.group(0) in self._pan_set:
                    hits.append(TargetHit(MatchKind.PAN, found.group(0), found.start(), found.end()))
        if self._track_regex:
            for found in self._track_regex.finditer(text):
                hits.append(TargetHit(MatchKind.TRACK, found.group(0), found.start(), found.end()))
        return sorted(hits, key=lambda hit: hit.start)


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

    def record(self, kind: MatchKind, value: str, location: str) -> None:
        entry = self._entries[(kind, value)]
        entry.count += 1
        if len(entry.locations) < MAX_LOCATIONS:
            entry.locations.append(location)

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries.values())

    def total(self, kind: MatchKind) -> int:
        return sum(entry.kind is kind for entry in self._entries.values())

    def found(self, kind: MatchKind) -> int:
        return sum(entry.kind is kind and entry.count > 0 for entry in self._entries.values())


def report_hits(targets: Targets, reporter, text: str, matches: list, file_path: str, line_number: int,
                place, encoding: str = "", context=None) -> None:
    """Tally the listed values found in *text* and report those no pattern already reported.

    *place(index)* turns a position in *text* into ``(reported offset, location label)``, or ``None`` for a
    position that belongs to a neighbouring chunk.  A hit overlapping a PAN or track that the patterns
    accepted is only tallied: it is already in the results.  Any other hit is reported as a PAN or TRACK
    named "Expected PAN" or "Expected TRACK", since the inspector said it is one.
    """
    covered = [(m.offset, m.offset + len(m.matched_data)) for m in matches
               if m.kind in (MatchKind.PAN, MatchKind.TRACK)]
    for hit in targets.find(text):
        placed = place(hit.start)
        if placed is None:
            continue
        offset, location = placed
        reporter.expected.record(hit.kind, hit.value, location)
        if any(start < hit.end and hit.start < end for start, end in covered):
            continue
        pan = hit.value if hit.kind is MatchKind.PAN else extract_pan(hit.value)
        reporter.report(Match(
            file_path, line_number, offset, hit.kind, f"Expected {hit.kind.value}",
            "--pan-list" if hit.kind is MatchKind.PAN else "--track-list", hit.value,
            context(hit) if context else text, pan, encoding,
        ))
