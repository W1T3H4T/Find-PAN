"""Raw scanning: PAN and track data in files that are not text, such as memory dumps.

A dump has no lines.  The bytes are read in overlapping chunks and each chunk is turned into text the
ordinary line scanner can work on: every byte (or, for UTF-16, every two-byte unit) that is not printable
ASCII becomes a line break, so each printable run is one "line".  The detection rules, Luhn check, anti-PAN
patterns, redaction and sinks are the ones used for text files.

Reported locations are absolute byte offsets with the encoding the bytes were read as.  Each encoding
reports only what it can read: ASCII digits are not UTF-16 text, and UTF-16 digits (a NUL between every
pair) are not ASCII runs.
"""

import re
from dataclasses import replace
from typing import Sequence

from find_pan.detectors import scan_line

CHUNK_SIZE = 8 * 1024 * 1024
#   Bytes read before and after each chunk so that a match on a boundary is seen whole.  A track record
#   is under 100 characters, 200 bytes as UTF-16, so this is ample.
OVERLAP = 512
ENCODINGS = ("ascii", "utf-16")
DEFAULT_ENCODINGS = ENCODINGS
#   Characters of context kept either side of a match.
CONTEXT = 40

#   Shortest text that can hold a PAN; shorter printable runs are not scanned.
_PRINTABLE_RUN = re.compile(r"[ -~]{12,}")
_NON_PRINTABLE = re.compile(r"[^ -~]")
_ASCII_TABLE = bytes(byte if 0x20 <= byte <= 0x7E else 0x0A for byte in range(256))
#   A UTF-16 high byte of 0xD8-0xDF starts a surrogate pair, which would decode as one character from two
#   units and break the index-to-offset mapping; it is replaced so every unit decodes to exactly one character.
_NO_SURROGATES = bytes(0x01 if 0xD8 <= byte <= 0xDF else byte for byte in range(256))
#   UTF-16 text is read as little-endian two-byte units at both byte alignments.  That covers UTF-16LE (the
#   characters sit at one alignment) and UTF-16BE (the same text with the NUL first, at the other alignment); the
#   two cannot be told apart from the bytes alone, so there is a single "utf-16" encoding and no duplicates.


def _views(window: bytes, encodings: Sequence[str]):
    """Yield ``(encoding, text, first, step)``: text[i] was read at window byte ``first + step * i``."""
    for encoding in encodings:
        if encoding == "ascii":
            yield encoding, window.translate(_ASCII_TABLE).decode("ascii"), 0, 1
            continue
        for alignment in (0, 1):
            units = (len(window) - alignment) // 2
            body = bytearray(window[alignment:alignment + 2 * units])
            body[1::2] = body[1::2].translate(_NO_SURROGATES)
            yield encoding, _NON_PRINTABLE.sub("\n", body.decode("utf-16-le")), alignment, 2


class RawScanner:
    """Scans files as raw bytes, reporting through a ``Reporter``."""

    def __init__(self, patterns: list, reporter,
                 encodings: Sequence[str] = DEFAULT_ENCODINGS, chunk_size: int = CHUNK_SIZE,
                 overlap: int = OVERLAP) -> None:
        unknown = [name for name in encodings if name not in ENCODINGS]
        if unknown:
            raise ValueError(f"unknown raw encoding(s): {', '.join(unknown)}")
        self.patterns = patterns
        self.reporter = reporter
        self.encodings = tuple(encodings)
        self.chunk_size = chunk_size - chunk_size % 2          # even, so UTF-16 alignment is the same in every chunk
        self.overlap = overlap + overlap % 2

    def scan_file(self, file_path: str, label: str | None = None) -> None:
        """Scan *file_path*; *label* (default: the path) names it in the results."""
        label = label or file_path
        self.reporter.file_started()
        with open(file_path, "rb") as handle:
            start = 0
            while True:
                handle.seek(max(0, start - self.overlap))
                window = handle.read(start - max(0, start - self.overlap) + self.chunk_size + self.overlap)
                if not window:
                    break
                base = max(0, start - self.overlap)
                last = len(window) <= start - base + self.chunk_size
                self._scan_window(label, window, base, start, None if last else start + self.chunk_size)
                if last:
                    break
                start += self.chunk_size

    def _scan_window(self, file_path: str, window: bytes, base: int, low: int, high: int | None) -> None:
        """Scan *window* (read from file offset *base*), reporting only offsets in ``[low, high)``."""
        for encoding, text, first, step in _views(window, self.encodings):
            for run in _PRINTABLE_RUN.finditer(text):
                segment = run.group(0)

                def place(index, run_start=run.start(), first=first, step=step):
                    offset = base + first + step * (run_start + index)
                    return (offset, f"{file_path}@0x{offset:X} ({encoding})") if low <= offset < (
                        float("inf") if high is None else high) else None

                def context(start, end, segment=segment):
                    return segment[max(0, start - CONTEXT):end + CONTEXT]

                matches = scan_line(file_path, 0, segment, self.patterns)
                for match in matches:
                    placed = place(match.offset)
                    if placed is None:
                        continue
                    end = match.offset + len(match.matched_data)
                    self.reporter.report(replace(
                        match, offset=placed[0], encoding=encoding,
                        source_line=context(match.offset, end),
                    ))
