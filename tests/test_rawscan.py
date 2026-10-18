"""Raw scanning: chunks, UTF-16 text and byte offsets in files that are not line-oriented (memory dumps)."""

import logging

import pytest

from find_pan import rawscan, targets
from find_pan.models import MatchKind, ScanStats
from find_pan.redact import Redactor
from find_pan.reporting import Reporter

PAN = "4556737586899855"
SECOND = "4012888888881881"
TRACK2 = ";4556737586899855=25121010000012345678?"
FF = bytes([0xFF])                      # a byte that is not printable text in any encoding


class Collector:
    def __init__(self):
        self.views = []

    def accepts(self, kind):
        return True

    def emit(self, view):
        self.views.append(view)

    def close(self):
        pass


def make(patterns, mask=False, expected=None, **options):
    sink = Collector()
    reporter = Reporter(Redactor(mask), [sink], ScanStats(), logging.getLogger("test.raw"), 500)
    ledger = None
    if expected is not None:
        ledger = targets.TargetLedger(expected)
        reporter.expected = ledger
    scanner = rawscan.RawScanner(patterns, reporter, expected, **options)
    return scanner, sink, ledger


def scan(patterns, tmp_path, data, **options):
    path = tmp_path / "dump.bin"
    path.write_bytes(data)
    scanner, sink, ledger = make(patterns, **options)
    scanner.scan_file(str(path))
    return [v for v in sink.views if v.kind is MatchKind.PAN], sink, ledger


def junk(length):
    return bytes((index * 37 + 11) % 256 for index in range(length)).replace(PAN.encode(), b"")


def test_ascii_text_in_binary_data_is_found_with_its_absolute_byte_offset(compiled_patterns, tmp_path):
    data = b"\x00\x01\xff" * 100 + b" card " + PAN.encode() + b" \x00\x00"
    found, _, _ = scan(compiled_patterns, tmp_path, data)
    assert [(v.pan, v.offset, v.line_number, v.encoding) for v in found] == [
        (PAN, data.index(PAN.encode()), 0, "ascii")]


@pytest.mark.parametrize("alignment", [0, 1])
@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
def test_utf16_text_is_found_in_either_byte_order_at_either_alignment(compiled_patterns, tmp_path, alignment, codec):
    wide = ("card " + PAN + " ").encode(codec)
    data = FF * alignment + bytes([1, 2]) * 50 + wide + bytes([3, 4]) * 50
    found, _, _ = scan(compiled_patterns, tmp_path, data)
    assert [(v.pan, v.encoding) for v in found] == [(PAN, "utf-16")]
    assert found[0].offset == data.index(b"4")                    # the byte holding the first digit


def test_utf16_is_not_scanned_when_only_ascii_is_asked_for(compiled_patterns, tmp_path):
    data = FF * 8 + (" " + PAN + " ").encode("utf-16-le") + FF * 8 + SECOND.encode()
    found, _, _ = scan(compiled_patterns, tmp_path, data, encodings=("ascii",))
    assert [(v.pan, v.encoding) for v in found] == [(SECOND, "ascii")]


def test_each_encoding_reports_only_what_it_can_read(compiled_patterns, tmp_path):
    """ASCII digits are not also seen as UTF-16, and wide digits are not also seen as ASCII."""
    data = FF * 4 + PAN.encode() + FF * 4 + (" " + SECOND + " ").encode("utf-16-le") + FF * 4
    found, _, _ = scan(compiled_patterns, tmp_path, data)
    assert sorted((v.pan, v.encoding) for v in found) == sorted([(PAN, "ascii"), (SECOND, "utf-16")])


def test_a_pan_interrupted_by_a_non_printable_byte_is_not_reported(compiled_patterns, tmp_path):
    data = b"\xff" * 8 + PAN[:8].encode() + b"\x00" + PAN[8:].encode() + b"\xff" * 8
    assert scan(compiled_patterns, tmp_path, data)[0] == []


@pytest.mark.parametrize("shift", range(-3, 4))
def test_a_pan_across_a_chunk_boundary_is_found_once(compiled_patterns, tmp_path, shift):
    chunk = 4096
    position = chunk - 8 + shift                       # the PAN straddles (or sits next to) the boundary
    data = bytearray(b"\xff" * (3 * chunk))
    data[position:position + 16] = PAN.encode()
    found, _, _ = scan(compiled_patterns, tmp_path, bytes(data), chunk_size=chunk, overlap=64)
    assert [(v.pan, v.offset) for v in found] == [(PAN, position)]


def test_a_truncated_tail_of_a_pan_at_a_chunk_start_is_not_reported_as_a_shorter_number(compiled_patterns, tmp_path):
    """The chunk after the boundary must still see the digits before it, or the tail looks like a number."""
    chunk = 4096
    data = bytearray(b"\xff" * (3 * chunk))
    start = chunk - 3                                   # 3 digits before the boundary, 13 after
    data[start:start + 16] = PAN.encode()
    found, _, _ = scan(compiled_patterns, tmp_path, bytes(data), chunk_size=chunk, overlap=64)
    assert [(v.pan, v.offset) for v in found] == [(PAN, start)]


def test_offsets_are_absolute_across_many_chunks(compiled_patterns, tmp_path):
    chunk = 1024
    data = bytearray(b"\xff" * (10 * chunk))
    places = [5, 3 * chunk + 100, 7 * chunk - 20, 10 * chunk - 40]
    for place in places:
        data[place:place + 16] = PAN.encode()
    found, _, _ = scan(compiled_patterns, tmp_path, bytes(data), chunk_size=chunk, overlap=64)
    assert [v.offset for v in found] == places


def test_utf16_matches_across_a_chunk_boundary_are_found_once(compiled_patterns, tmp_path):
    chunk = 2048
    wide = (" " + PAN + " ").encode("utf-16-le")
    data = bytearray(b"\xff" * (3 * chunk))
    start = chunk - 12
    data[start:start + len(wide)] = wide
    found, _, _ = scan(compiled_patterns, tmp_path, bytes(data), chunk_size=chunk, overlap=128)
    assert [(v.pan, v.offset) for v in found] == [(PAN, start + 2)]


def test_the_file_is_counted_once_however_many_chunks_it_has(compiled_patterns, tmp_path):
    path = tmp_path / "dump.bin"
    path.write_bytes(b"\xff" * 5000 + PAN.encode())
    scanner, sink, _ = make(compiled_patterns, chunk_size=1024, overlap=64)
    scanner.scan_file(str(path))
    assert scanner.reporter.stats.files == 1


def test_masking_applies_to_raw_matches_and_their_context(compiled_patterns, tmp_path):
    found, _, _ = scan(compiled_patterns, tmp_path, b"\xff" * 4 + b"pan=" + PAN.encode() + b";\xff" * 4, mask=True)
    assert found[0].pan == "455673******9855" and PAN not in found[0].source_line
    assert "455673******9855" in found[0].source_line


def test_context_around_a_match_is_short(compiled_patterns, tmp_path):
    data = b"\xff" + b"x" * 5000 + b" " + PAN.encode() + b" " + b"y" * 5000 + b"\xff"
    found, _, _ = scan(compiled_patterns, tmp_path, data)
    assert PAN in found[0].source_line and len(found[0].source_line) < 120


# --- expected values ---------------------------------------------------------------------------------------------


def test_expected_pans_are_tallied_in_both_encodings_with_locations(compiled_patterns, tmp_path):
    expected = targets.Targets(pans=(PAN, SECOND))
    wide = (" " + PAN + " ").encode("utf-16-le")
    data = b"\xff" * 8 + PAN.encode() + b"\xff" * 8 + wide + b"\xff" * 8
    _, _, ledger = scan(compiled_patterns, tmp_path, data, expected=expected)
    pan_entry, second_entry = ledger.entries()
    assert pan_entry.count == 2 and second_entry.count == 0
    assert "dump.bin@0x8 (ascii)" in pan_entry.locations[0]


def test_an_expected_pan_that_no_pattern_matches_is_still_reported_as_a_pan(compiled_patterns, tmp_path):
    unusual = "9999999999999995"
    found, _, ledger = scan(compiled_patterns, tmp_path, b"\xff" * 4 + unusual.encode() + b"\xff" * 4,
                            expected=targets.Targets(pans=(unusual,)))
    assert [(v.pan, v.pattern_name) for v in found] == [(unusual, "Expected PAN")]
    assert ledger.entries()[0].count == 1


def test_an_expected_pan_that_a_pattern_also_matches_is_reported_once(compiled_patterns, tmp_path):
    found, _, ledger = scan(compiled_patterns, tmp_path, b"\xff" * 4 + PAN.encode() + b"\xff" * 4,
                            expected=targets.Targets(pans=(PAN,)))
    assert len(found) == 1 and found[0].pattern_name != "Expected PAN"
    assert ledger.entries()[0].count == 1


def test_an_expected_track_is_tallied_and_reported_once(compiled_patterns, tmp_path):
    expected = targets.Targets(tracks=(TRACK2,))
    path = tmp_path / "dump.bin"
    path.write_bytes(b"\xff" * 6 + TRACK2.encode() + b"\xff" * 6)
    scanner, sink, ledger = make(compiled_patterns, expected=expected)
    scanner.scan_file(str(path))
    tracks = [v for v in sink.views if v.kind is MatchKind.TRACK]
    assert len(tracks) == 1 and ledger.entries()[0].count == 1


def test_hits_in_the_overlap_are_tallied_once(compiled_patterns, tmp_path):
    chunk = 1024
    data = bytearray(b"\xff" * (4 * chunk))
    data[chunk - 8:chunk + 8] = PAN.encode()
    _, _, ledger = scan(compiled_patterns, tmp_path, bytes(data), chunk_size=chunk, overlap=64,
                        expected=targets.Targets(pans=(PAN,)))
    assert ledger.entries()[0].count == 1


def test_the_default_chunk_is_large_and_the_overlap_covers_the_longest_match():
    assert rawscan.CHUNK_SIZE >= 1024 * 1024 and rawscan.OVERLAP >= 256
    assert set(rawscan.ENCODINGS) == {"ascii", "utf-16"}
