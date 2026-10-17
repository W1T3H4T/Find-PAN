"""Redaction: the one place output rules are applied.

Every sink receives a ``RedactedMatch``; none of them ever sees the raw
``Match``.  A new output rule is added here and applies everywhere.
"""

import re
from dataclasses import dataclass, replace

from find_pan.models import Match, MatchKind

#   Digits kept at each end of a masked PAN.
_KEEP_FIRST = 6
_KEEP_LAST = 4
_LONG_DIGIT_RUN = re.compile(r"(?<!\d)\d{12,19}(?!\d)")
#   Cards written with single spaces or dashes: 4-4-4-4(-3) and the Amex 4-6-5 layout.
_SEPARATED_CARD = re.compile(
    r"(?<![\d-])(?:\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{4}([ -])\d{6}\2\d{5})(?![\d-])"
)
#   Track 1 (%B<pan>^<name>^<data>?) and Track 2 (;<pan>=<data>?) shapes.
_TRACK_SHAPE = re.compile(r"%[BM]\d{12,19}\^[^^\n]*\^\d*\??|;\d{12,19}=\d*\??")


def mask_pan(pan: str) -> str:
    """Keep the first 6 (BIN) and last 4 digits of *pan*; mask the rest."""
    if len(pan) <= _KEEP_FIRST + _KEEP_LAST:
        return "*" * len(pan)
    return pan[:_KEEP_FIRST] + "*" * (len(pan) - _KEEP_FIRST - _KEEP_LAST) + pan[-_KEEP_LAST:]


def mask_matched_data(matched: str, pan: str) -> str:
    """Mask the digits of *matched*, keeping separators.

    A plain PAN (digits possibly separated) is masked in place.  Anything else,
    such as track data, carries more sensitive fields, so every digit is masked.
    """
    if re.sub(r"\D", "", matched) != pan:
        return re.sub(r"\d", "*", matched)
    keep_digits = len(pan) > _KEEP_FIRST + _KEEP_LAST
    masked = []
    seen = 0
    for char in matched:
        if char.isdigit():
            keep = keep_digits and (seen < _KEEP_FIRST or seen >= len(pan) - _KEEP_LAST)
            masked.append(char if keep else "*")
            seen += 1
        else:
            masked.append(char)
    return "".join(masked)


def mask_text(text: str) -> str:
    """Mask track data and PAN-length (12-19 digit) runs in free text.

    Track-shaped text is masked completely (digits only), whatever its length,
    because expiry, service code and discretionary data are sensitive too.
    """
    text = _TRACK_SHAPE.sub(lambda found: re.sub(r"\d", "*", found.group(0)), text)
    text = _SEPARATED_CARD.sub(
        lambda found: mask_matched_data(found.group(0), re.sub(r"\D", "", found.group(0))), text
    )
    return _LONG_DIGIT_RUN.sub(lambda found: mask_pan(found.group(0)), text)


@dataclass(frozen=True)
class RedactedMatch:
    """A ``Match`` whose sensitive fields are safe to write to any sink."""

    file_path: str
    line_number: int
    offset: int
    kind: MatchKind
    pattern_name: str
    pattern: str
    matched_data: str
    source_line: str
    pan: str


class Redactor:
    """Turns a raw ``Match`` into a ``RedactedMatch``."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def apply(self, match: Match) -> RedactedMatch:
        if not self.enabled:
            return RedactedMatch(**vars(match))
        matched = mask_matched_data(match.matched_data, match.pan)
        line = match.source_line.replace(match.matched_data, matched)
        return replace(
            RedactedMatch(**vars(match)),
            matched_data=matched,
            source_line=mask_text(line),
            pan=mask_pan(match.pan),
        )
