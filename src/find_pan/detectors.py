"""Pure detection logic: Luhn validation and per-line pattern scanning.

Nothing here logs, counts or prints; callers decide what to do with the
returned ``Match`` records.
"""

import re
from datetime import datetime

from find_pan.models import Match, MatchKind

ANTI_PAN_CATEGORY = "Anti-PAN Pattern"
PAN_CATEGORY = "PAN Pattern"
TRACK_CATEGORY = "TRACK Pattern"


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


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(span[0] < other[1] and other[0] < span[1] for other in spans)


def scan_line(
    file_path: str,
    line_number: int,
    line: str,
    patterns: list[tuple[str, str, re.Pattern]],
) -> list[Match]:
    """Return every anti-PAN, PAN, TRACK and bad-Luhn match on *line*.

    Anti-PAN matches exclude only their own span, so other numbers on the same
    line are still examined.  A candidate overlapping an anti-PAN or an
    accepted match is skipped.  A Luhn failure never hides a later candidate,
    and a bad number matched by several patterns is reported once.
    """
    matches: list[Match] = []
    excluded: list[tuple[int, int]] = []
    failed: list[tuple[int, int]] = []

    for category, pattern_name, compiled in patterns:
        if category != ANTI_PAN_CATEGORY:
            continue
        for found in compiled.finditer(line):
            if pattern_name == "Timestamp" and not valid_timestamp(found.group(0)):
                continue
            span = found.span()
            if _overlaps(span, excluded):
                continue
            excluded.append(span)
            matches.append(Match(
                file_path, line_number, found.start(), MatchKind.ANTI_PAN,
                pattern_name, compiled.pattern, found.group(0), line, "",
            ))

    for category, pattern_name, compiled in patterns:
        if category == ANTI_PAN_CATEGORY:
            continue
        if category not in (PAN_CATEGORY, TRACK_CATEGORY):
            raise ValueError(
                f"Unexpected pattern category {category!r}: "
                f"{file_path}:{line_number} ->{pattern_name}={compiled.pattern}"
            )
        accepted_kind = MatchKind.PAN if category == PAN_CATEGORY else MatchKind.TRACK
        for found in compiled.finditer(line):
            span = found.span()
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
                file_path, line_number, found.start(), kind,
                pattern_name, compiled.pattern, found.group(0), line, pan,
            ))
    return matches
