"""Pure detection logic: Luhn validation and per-line pattern scanning.

Nothing here logs, counts or prints; callers decide what to do with the
returned ``Match`` records.
"""

import re
from dataclasses import dataclass
from datetime import datetime

from find_pan.models import Match, MatchKind

ANTI_PAN_CATEGORY = "Anti-PAN Pattern"
PAN_CATEGORY = "PAN Pattern"
TRACK_CATEGORY = "TRACK Pattern"
#   Finds PANs written in groups ("4556-7375-8689-9855"); these entries only locate candidates, they never match.
DELIMITED_CATEGORY = "Delimited PAN Pattern"
_SEPARATORS = " -"


def luhn_check(number: str) -> bool:
    """Return whether *number* passes the Luhn check.

    An empty or all-zero string has a zero checksum but is never a PAN, so it
    is rejected.  Non-digit characters raise ``ValueError``.
    """
    if not str(number).strip("0"):
        return False
    checksum = 0
    for index, digit in enumerate(int(char) for char in reversed(str(number))):
        value = digit if index % 2 == 0 else 2 * digit
        checksum += value if value < 10 else value - 9
    return checksum % 10 == 0


def valid_timestamp(value: str) -> bool:
    """Return whether *value* is a plausible ``YYYYMMDDHHMMSS`` timestamp."""
    if not re.fullmatch(r"[0-9]{14}", value):
        return False
    try:
        timestamp = datetime.strptime(value, "%Y%m%d%H%M%S")
    except ValueError:
        return False
    return 1900 <= timestamp.year <= datetime.now().year


def extract_pan(matched_data: str) -> str:
    """Return the PAN digits of a regex match, stripping track framing."""
    if matched_data.startswith(("%B", "%M")):
        return re.sub(r"\D", "", matched_data[2:].split("^")[0])
    if matched_data.startswith(";"):
        return re.sub(r"\D", "", matched_data[1:].split("=")[0])
    return re.sub(r"\D", "", matched_data)




@dataclass(frozen=True)
class Normalized:
    """A line with its delimited PANs compacted, and where each character came from.

    ``text[i]`` was read at ``line[positions[i]]``; ``positions`` is ``None`` when nothing was compacted.
    """

    text: str
    positions: tuple[int, ...] | None = None

    def start(self, index: int) -> int:
        """The original position of the normalized position *index*."""
        return index if self.positions is None else self.positions[index]

    def end(self, index: int) -> int:
        """The original position just past the normalized end *index*."""
        if self.positions is None or index == 0:
            return index
        return self.positions[index - 1] + 1


def normalize(line: str, patterns: list[tuple[str, str, re.Pattern]]) -> Normalized:
    """Remove the spaces and hyphens of every delimited PAN candidate on *line*.

    Candidates come only from the configured ``Delimited PAN Pattern`` entries; where they overlap the
    longest from the leftmost start wins.  Nothing else on the line changes.
    """
    spans = sorted(
        (found.span() for category, _, compiled in patterns if category == DELIMITED_CATEGORY
         for found in compiled.finditer(line)),
        key=lambda span: (span[0], span[0] - span[1]),
    )
    text: list[str] = []
    positions: list[int] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        text.append(line[cursor:start])
        positions.extend(range(cursor, start))
        for index in range(start, end):
            if line[index] not in _SEPARATORS:
                text.append(line[index])
                positions.append(index)
        cursor = end
    if cursor == 0 and not spans:
        return Normalized(line)
    text.append(line[cursor:])
    positions.extend(range(cursor, len(line)))
    return Normalized("".join(text), tuple(positions))


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(span[0] < other[1] and other[0] < span[1] for other in spans)


def scan_line(
    file_path: str,
    line_number: int,
    line: str,
    patterns: list[tuple[str, str, re.Pattern]],
) -> list[Match]:
    """Return every anti-PAN, PAN, TRACK and bad-Luhn match on *line*.

    Delimited PANs are compacted first (:func:`normalize`); the anti-PAN and PAN patterns then run on the
    compacted text and TRACK patterns on the original, and every result is reported against the original
    line.  Anti-PAN matches exclude only their own span, so other numbers on the same line are still
    examined.  A candidate overlapping an anti-PAN or an accepted match is skipped, so nothing PAN-like is
    taken from accepted track data.  A Luhn failure never hides a later candidate, and a bad number matched
    by several patterns is reported once.
    """
    normalized = normalize(line, patterns)
    matches: list[Match] = []
    excluded: list[tuple[int, int]] = []
    failed: list[tuple[int, int]] = []

    def original(found: re.Match, text_is_normalized: bool) -> tuple[int, int]:
        if not text_is_normalized:
            return found.span()
        return normalized.start(found.start()), max(normalized.start(found.start()), normalized.end(found.end()))

    for category, pattern_name, compiled in patterns:
        if category != ANTI_PAN_CATEGORY:
            continue
        for found in compiled.finditer(normalized.text):
            if pattern_name == "Timestamp" and not valid_timestamp(found.group(0)):
                continue
            span = original(found, True)
            if _overlaps(span, excluded):
                continue
            excluded.append(span)
            matches.append(Match(
                file_path, line_number, span[0], MatchKind.ANTI_PAN,
                pattern_name, compiled.pattern, line[span[0]:span[1]], line, "",
            ))

    for category, pattern_name, compiled in patterns:
        if category in (ANTI_PAN_CATEGORY, DELIMITED_CATEGORY):
            continue
        if category not in (PAN_CATEGORY, TRACK_CATEGORY):
            raise ValueError(
                f"Unexpected pattern category {category!r}: "
                f"{file_path}:{line_number} ->{pattern_name}={compiled.pattern}"
            )
        accepted_kind = MatchKind.PAN if category == PAN_CATEGORY else MatchKind.TRACK
        is_pan = category == PAN_CATEGORY
        for found in compiled.finditer(normalized.text if is_pan else line):
            span = original(found, is_pan)
            if _overlaps(span, excluded):
                continue
            pan = extract_pan(found.group(0))
            if pan and luhn_check(pan):
                excluded.append(span)
                kind = accepted_kind
            else:
                if _overlaps(span, failed):
                    continue
                failed.append(span)
                kind = MatchKind.BAD_LUHN
            matches.append(Match(
                file_path, line_number, span[0], kind,
                pattern_name, compiled.pattern, line[span[0]:span[1]], line, pan,
            ))
    return matches
