"""Tests for find_pan.reporting: Reporter and sinks."""

import csv
import logging

import pytest

from find_pan import reporting
from find_pan.errors import ConfigError
from find_pan.models import Match, MatchKind, ScanStats, SkipReason
from find_pan.redact import Redactor

PAN = "4556737586899855"


def make_match(kind=MatchKind.PAN, matched=PAN, pan=PAN, line=None, path="/data/sample.txt"):
    return Match(path, 3, 6, kind, "VISA", "pattern", matched, line or f"Card: {matched}\n", pan)


class FakeSink:
    def __init__(self, kinds):
        self.kinds = set(kinds)
        self.views = []
        self.closed = False

    def accepts(self, kind):
        return kind in self.kinds

    def emit(self, view):
        self.views.append(view)

    def close(self):
        self.closed = True


def make_reporter(sinks, mask=False, report_delta=500, logger=None):
    return reporting.Reporter(
        Redactor(mask), sinks, ScanStats(), logger or logging.getLogger("test.trace"), report_delta
    )


def test_report_redacts_once_and_fans_out():
    first, second = FakeSink({MatchKind.PAN}), FakeSink({MatchKind.PAN})
    make_reporter([first, second], mask=True).report(make_match())
    assert len(first.views) == len(second.views) == 1
    assert first.views[0] is second.views[0]


def test_sinks_only_receive_redacted_views():
    sink = FakeSink({MatchKind.PAN})
    make_reporter([sink], mask=True).report(make_match())
    view = sink.views[0]
    assert PAN not in (view.matched_data, view.source_line, view.pan)


def test_sink_not_called_for_unaccepted_kind():
    sink = FakeSink({MatchKind.PAN})
    make_reporter([sink]).report(make_match(kind=MatchKind.TRACK))
    assert sink.views == []


def test_counts_all_kinds_even_when_no_sink_accepts():
    reporter = make_reporter([])
    for kind in MatchKind:
        reporter.report(make_match(kind=kind))
    assert all(reporter.stats.count(kind) == 1 for kind in MatchKind)


def test_log_sink_accepts_only_pan_and_track(caplog):
    sink = reporting.LogSink(logging.getLogger("test.pan"))
    assert sink.accepts(MatchKind.PAN) and sink.accepts(MatchKind.TRACK)
    assert not sink.accepts(MatchKind.BAD_LUHN)
    assert not sink.accepts(MatchKind.ANTI_PAN)


def test_log_sink_line_format(caplog):
    reporter = make_reporter([reporting.LogSink(logging.getLogger("test.pan"))])
    with caplog.at_level(logging.INFO, logger="test.pan"):
        reporter.report(make_match())
    message = caplog.records[0].getMessage()
    assert message.startswith("/data/sample.txt:3:6->VISA (PAN), pattern: Card: ")
    assert PAN in message


def test_csv_sink_writes_header_and_row_and_flushes(tmp_path):
    path = tmp_path / "out.csv"
    sink = reporting.CsvSink(str(path))
    reporter = make_reporter([sink])
    reporter.report(make_match())
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))  # before close()
    assert rows[0] == ["filename", "line_number", "offset", "pattern_name", "data_type", "matched_data"]
    assert rows[1] == ["sample.txt", "3", "6", "VISA", "PAN", PAN]
    sink.close()


def test_csv_sink_unwritable_path_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        reporting.CsvSink(str(tmp_path))  # a directory cannot be opened for writing


def test_csv_sanitizes_non_ascii(tmp_path):
    path = tmp_path / "out.csv"
    sink = reporting.CsvSink(str(path))
    make_reporter([sink]).report(make_match(matched="ab\x00cd\xffef" + PAN))
    sink.close()
    assert path.read_text(encoding="utf-8").isascii()


def test_csv_sink_masks_when_redactor_enabled(tmp_path):
    path = tmp_path / "out.csv"
    sink = reporting.CsvSink(str(path))
    make_reporter([sink], mask=True).report(make_match())
    sink.close()
    assert PAN not in path.read_text(encoding="utf-8")


def test_csv_and_log_sinks_ignore_bad_luhn_and_anti_pan(tmp_path):
    sinks = [reporting.CsvSink(str(tmp_path / "o.csv")), reporting.LogSink(logging.getLogger("test.pan"))]
    for sink in sinks:
        assert not sink.accepts(MatchKind.BAD_LUHN)
        assert not sink.accepts(MatchKind.ANTI_PAN)
        sink.close()


def test_trace_sink_logs_bad_luhn_at_debug(caplog):
    reporter = make_reporter([reporting.TraceSink(logging.getLogger("test.trace2"))])
    with caplog.at_level(logging.DEBUG, logger="test.trace2"):
        reporter.report(make_match(kind=MatchKind.BAD_LUHN))
    record = caplog.records[0]
    assert record.levelno == logging.DEBUG
    assert "Luhn failure" in record.getMessage() and PAN in record.getMessage()


def test_trace_sink_masks_under_mask(caplog):
    reporter = make_reporter([reporting.TraceSink(logging.getLogger("test.trace2"))], mask=True)
    with caplog.at_level(logging.DEBUG, logger="test.trace2"):
        reporter.report(make_match(kind=MatchKind.BAD_LUHN))
    assert PAN not in caplog.records[0].getMessage()
    assert "455673******9855" in caplog.records[0].getMessage()


def test_anti_pan_sink_counts_entries_and_accepts_only_anti_pans(caplog):
    sink = reporting.AntiPanSink(logging.getLogger("test.anti"), "/logs/anti.log")
    reporter = make_reporter([sink])
    with caplog.at_level(logging.INFO, logger="test.anti"):
        reporter.report(make_match(kind=MatchKind.ANTI_PAN, matched="123456789012345678", pan=""))
        reporter.report(make_match())
    assert sink.entries == 1
    assert sink.path == "/logs/anti.log"
    assert len(caplog.records) == 1
    assert "(ANTI-PAN)" in caplog.records[0].getMessage()


def test_summary_without_anti_pan_sink_has_no_anti_pan_log_lines():
    text = "\n".join(make_reporter([]).summary_lines("/logs"))
    assert "Anti-PAN log" not in text and "Anti-PANs logged" not in text
    assert "Detected 0 Anti-PANs." in text
    assert "Log files are located in: /logs" in text


def test_summary_with_anti_pan_sink_shows_path_and_count_including_zero():
    sink = reporting.AntiPanSink(logging.getLogger("test.anti"), "/logs/Find-PAN-anti-pan.log")
    reporter = make_reporter([sink])
    zero = "\n".join(reporter.summary_lines("/logs"))
    assert "Anti-PAN log   : /logs/Find-PAN-anti-pan.log" in zero
    assert "Anti-PANs logged: 0" in zero
    reporter.report(make_match(kind=MatchKind.ANTI_PAN, matched="123456789012345678", pan=""))
    assert "Anti-PANs logged: 1" in "\n".join(reporter.summary_lines("/logs"))


def test_summary_reports_true_file_count_and_totals():
    reporter = make_reporter([])
    reporter.file_started()
    reporter.file_started()
    reporter.report(make_match())
    reporter.report(make_match(kind=MatchKind.TRACK))
    reporter.skip("/x", SkipReason.BINARY)
    text = "\n".join(reporter.summary_lines("/logs"))
    assert "Scanned       :        2 Files." in text
    assert "Total matches :        2" in text
    assert "Skipped 1 Files." in text and "Skipped 1 Binary Files." in text


def test_progress_logged_every_report_delta_files(caplog):
    reporter = make_reporter([], report_delta=2, logger=logging.getLogger("test.progress"))
    with caplog.at_level(logging.INFO, logger="test.progress"):
        for _ in range(5):
            reporter.file_started()
    assert len([r for r in caplog.records if "Scanned" in r.getMessage()]) == 2


def test_close_closes_all_sinks_even_if_one_fails():
    class Boom(FakeSink):
        def close(self):
            raise OSError("boom")

    good = FakeSink(set())
    reporter = make_reporter([Boom(set()), good])
    with pytest.raises(OSError):
        reporter.close()
    assert good.closed


def test_unreadable_files_have_own_counter_and_summary_line():
    """Deferred minor 4: unreadable files are not folded into 'Skipped N Files'."""
    reporter = make_reporter([])
    reporter.skip("/x", SkipReason.UNREADABLE)
    reporter.skip("/y", SkipReason.BINARY)
    text = "\n".join(reporter.summary_lines("/logs"))
    assert "Skipped 1 Files." in text            # binary only
    assert "Skipped 1 Binary Files." in text
    assert "Unreadable 1 Files." in text


def test_no_unreadable_line_when_none_unreadable():
    assert "Unreadable" not in "\n".join(make_reporter([]).summary_lines("/logs"))


def test_close_is_idempotent():
    sink = FakeSink(set())
    reporter = make_reporter([sink])
    reporter.close()
    reporter.close()
    assert sink.closed
