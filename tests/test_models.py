"""Tests for the find_pan settings, errors, models and version modules."""

import dataclasses

import pytest

from find_pan import errors, models, settings, version


def test_settings_defaults_and_frozen():
    defaults = settings.Settings()
    assert defaults.path is None
    assert defaults.files == ()
    assert not hasattr(defaults, "archive") and not hasattr(defaults, "tar_tmp")
    assert defaults.log_dir == ""
    assert defaults.rgx_patterns is None
    assert defaults.line_limit == 0
    assert defaults.report_delta == 500
    assert defaults.csv is None
    assert not any([defaults.rgx_prefix, defaults.skip_binary, defaults.verbose,
                    defaults.debug, defaults.mask, defaults.log_anti_pan,
                    defaults.exception_test])
    with pytest.raises(dataclasses.FrozenInstanceError):
        defaults.mask = True


def test_match_kind_values():
    assert models.MatchKind.ANTI_PAN.value == "ANTI-PAN"
    assert models.MatchKind.BAD_LUHN.value == "BAD-LUHN"


def test_stats_record_counts_per_kind():
    stats = models.ScanStats()
    stats.record(models.MatchKind.PAN)
    stats.record(models.MatchKind.PAN)
    stats.record(models.MatchKind.TRACK)
    assert stats.count(models.MatchKind.PAN) == 2
    assert stats.count(models.MatchKind.TRACK) == 1
    assert stats.count(models.MatchKind.ANTI_PAN) == 0


def test_stats_skip_updates_skipped_and_reason_counters():
    stats = models.ScanStats()
    stats.skipped(models.SkipReason.BINARY)
    stats.skipped(models.SkipReason.EXECUTABLE)
    assert stats.skipped_files == 2
    assert stats.binary == 1
    assert stats.executable == 1


def test_stats_average_time_zero_without_files():
    stats = models.ScanStats()
    stats.start()
    stats.stop()
    assert stats.average_time == 0
    stats.file_scanned()
    assert stats.files == 1
    assert stats.average_time == stats.total_time


def test_format_version():
    assert version.format_version("find-pan") == f"find-pan v{version.__version__}"


def test_errors_share_base():
    for name in ("ConfigError", "LoggingSetupError", "ExtractorError"):
        assert issubclass(getattr(errors, name), errors.FindPanError)


def test_stats_archive_and_new_skip_reasons():
    stats = models.ScanStats()
    stats.archive_expanded()
    stats.skipped(models.SkipReason.ARCHIVE_NO_TOOL)
    stats.skipped(models.SkipReason.ARCHIVE_FAILED)
    stats.skipped(models.SkipReason.NOT_FOUND)
    stats.skipped(models.SkipReason.NOT_A_FILE)
    assert stats.archives_expanded == 1
    assert stats.archives_skipped == 2
    assert stats.skipped_files == 0          # binary + executable only, as before
    assert stats.failures == 3               # ARCHIVE_FAILED, NOT_FOUND, NOT_A_FILE


def test_extractor_unavailable_is_an_extractor_error():
    assert issubclass(errors.ExtractorUnavailable, errors.ExtractorError)
