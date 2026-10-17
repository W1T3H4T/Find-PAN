"""Tests for extraction limits: size, file count, time and free space.

The "tools" here are real child processes (the current Python interpreter)
that misbehave the way a decompression bomb would, so the watchdog is tested
against actual subprocess behavior.
"""

import logging
import subprocess
import sys
import time
from pathlib import Path

import pytest

from find_pan import archives, config
from find_pan.errors import ConfigError, ExtractorError
from find_pan.models import ExtractionLimits

LOGGER = logging.getLogger("test.limits")
MB = 1024 * 1024

#   A child that writes 1 MB files forever into the directory given as argv[1].
WRITER = (
    "import sys, os, itertools\n"
    "d = sys.argv[1]\n"
    "blob = b'x' * (1 << 20)\n"
    "for i in itertools.count():\n"
    "    open(os.path.join(d, f'big{i}.bin'), 'wb').write(blob)\n"
)
#   A child that creates empty files forever.
FILER = (
    "import sys, os, itertools\n"
    "d = sys.argv[1]\n"
    "for i in itertools.count():\n"
    "    open(os.path.join(d, f'f{i}'), 'wb').close()\n"
)
SLEEPER = "import time; time.sleep(60)"
#   Spawns a grandchild that keeps writing, then waits: killing only the parent would leave it running.
FAMILY = (
    "import subprocess, sys\n"
    "subprocess.Popen([sys.executable, '-c', " + repr(WRITER) + ", sys.argv[1]])\n"
    "import time; time.sleep(60)\n"
)


def limits(**overrides):
    values = dict(max_extracted_bytes=5 * MB, max_files=100_000, timeout_seconds=60, min_free_bytes=0)
    values.update(overrides)
    return ExtractionLimits(**values)


def run(script, directory, **overrides):
    return archives.run_limited([sys.executable, "-c", script, str(directory)], directory, limits(**overrides))


def test_defaults_match_the_documented_values():
    defaults = ExtractionLimits()
    assert defaults.max_extracted_bytes == 10 * 1024 * MB
    assert defaults.max_files == 100_000
    assert defaults.timeout_seconds == 600
    assert defaults.min_free_bytes == 1024 * MB


def test_tool_that_writes_too_much_is_stopped(tmp_path):
    with pytest.raises(archives.LimitExceeded, match="exceeded 5 MB"):
        run(WRITER, tmp_path, max_extracted_bytes=5 * MB)
    total = sum(path.stat().st_size for path in tmp_path.iterdir())
    assert total < 5 * MB + 40 * MB          # stopped soon after the cap, not unbounded


def test_tool_that_creates_too_many_files_is_stopped(tmp_path):
    with pytest.raises(archives.LimitExceeded, match="files"):
        run(FILER, tmp_path, max_extracted_bytes=10_000 * MB, max_files=50)
    assert len(list(tmp_path.iterdir())) < 5_000


def test_hung_tool_is_stopped_by_the_timeout(tmp_path):
    started = time.monotonic()
    with pytest.raises(archives.LimitExceeded, match="time"):
        run(SLEEPER, tmp_path, timeout_seconds=1)
    assert time.monotonic() - started < 15


def test_low_free_disk_space_stops_the_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(archives.shutil, "disk_usage", lambda path: (100, 100, 10))
    with pytest.raises(archives.LimitExceeded, match="free"):
        run(SLEEPER, tmp_path, min_free_bytes=1024 * MB)


def test_extraction_is_refused_up_front_when_space_is_already_low(tmp_path, monkeypatch):
    monkeypatch.setattr(archives.shutil, "disk_usage", lambda path: (100, 100, 10))
    with pytest.raises(archives.LimitExceeded, match="free"):
        run("print('never runs')", tmp_path, min_free_bytes=1024 * MB)


def test_killing_the_tool_also_kills_its_children(tmp_path):
    with pytest.raises(archives.LimitExceeded):
        run(FAMILY, tmp_path, max_extracted_bytes=5 * MB)
    before = sum(path.stat().st_size for path in tmp_path.iterdir())
    time.sleep(1.0)
    after = sum(path.stat().st_size for path in tmp_path.iterdir())
    assert after == before                    # the grandchild is gone


def test_well_behaved_tool_is_unaffected(tmp_path):
    result = run("open(__import__('sys').argv[1] + '/ok.txt', 'w').write('hi')", tmp_path)
    assert (tmp_path / "ok.txt").read_text() == "hi"
    assert result.returncode == 0


def test_failing_tool_still_raises_called_process_error_with_stderr(tmp_path):
    script = "import sys; sys.stderr.write('boom'); sys.exit(3)"
    with pytest.raises(subprocess.CalledProcessError) as info:
        run(script, tmp_path)
    assert info.value.returncode == 3 and "boom" in info.value.stderr


def test_noisy_tool_output_cannot_deadlock_the_watchdog(tmp_path):
    script = "import sys; sys.stdout.write('x' * 5_000_000); sys.stderr.write('y' * 5_000_000)"
    result = run(script, tmp_path)           # would hang if pipes were not drained
    assert result.returncode == 0


# --- integration with extract_archive --------------------------------------------------------------


def extractor_entry(script, **extra):
    entry = {"command": sys.executable, "args": ["-c", script, "{tempdir}"]}
    entry.update(extra)
    return {"tar": entry}


def test_extract_archive_reports_a_limit_hit_and_exposes_the_partial_members(tmp_path):
    seen = {}
    with pytest.raises(ExtractorError, match="exceeded"):
        with archives.extract_archive(str(tmp_path / "a.tar"), extractor_entry(WRITER), LOGGER,
                                      limits=limits(max_extracted_bytes=3 * MB)) as directory:
            seen["count"] = len(list(Path(directory).iterdir()))
    assert seen["count"] >= 1                # what was extracted before the stop is still scanned


def test_per_extractor_limits_override_the_global_ones(tmp_path):
    entry = extractor_entry(FILER, max_files=20)
    with pytest.raises(ExtractorError, match="files"):
        with archives.extract_archive(str(tmp_path / "a.tar"), entry, LOGGER,
                                      limits=limits(max_files=1_000_000, max_extracted_bytes=10_000 * MB)):
            pass


def test_nothing_is_left_on_disk_after_a_limit_hit(tmp_path, monkeypatch):
    import tempfile

    root = tmp_path / "system-temp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    with pytest.raises(ExtractorError):
        with archives.extract_archive(str(tmp_path / "a.tar"), extractor_entry(WRITER), LOGGER,
                                      limits=limits(max_extracted_bytes=3 * MB)):
            pass
    assert list(root.iterdir()) == []


# --- configuration -----------------------------------------------------------------------------------


def write_config(tmp_path, text):
    path = tmp_path / "conf.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_limits_default_when_the_section_is_absent(tmp_path):
    path = write_config(tmp_path, "extractors: {}\n")
    assert config.load_extraction_limits(path) == ExtractionLimits()


def test_limits_can_be_overridden_in_the_yaml(tmp_path):
    path = write_config(tmp_path, "limits:\n  max_files: 7\n  timeout_seconds: 12\nextractors: {}\n")
    loaded = config.load_extraction_limits(path)
    assert loaded.max_files == 7 and loaded.timeout_seconds == 12
    assert loaded.max_extracted_bytes == ExtractionLimits().max_extracted_bytes


@pytest.mark.parametrize("text", [
    "limits:\n  max_files: 0\n",
    "limits:\n  max_files: many\n",
    "limits:\n  surprise: 1\n",
    "limits: 5\n",
])
def test_invalid_limits_are_a_config_error(tmp_path, text):
    with pytest.raises(ConfigError):
        config.load_extraction_limits(write_config(tmp_path, text))


def test_generated_config_documents_the_default_limits(tmp_path):
    path = tmp_path / "conf.yaml"
    config.build_extractor_config(str(path))
    assert config.load_extraction_limits(str(path)) == ExtractionLimits()
    assert "limits:" in path.read_text(encoding="utf-8")


# --- adaptive polling: the closer a cap, the faster the watchdog looks ---------------------------------


def test_first_poll_is_immediate_so_a_fast_writer_is_seen_early():
    assert archives._next_poll_delay(limits(), None, 0.0, 0, 0) == archives._MIN_POLL_SECONDS


def test_far_from_every_cap_the_normal_rate_is_used():
    previous = (0.0, 1000, 5)
    defaults = ExtractionLimits()
    assert archives._next_poll_delay(defaults, previous, 1.0, 1000, 5) == archives._POLL_SECONDS
    assert archives._next_poll_delay(defaults, previous, 1.0, 2000, 6) == archives._POLL_SECONDS


def test_an_idle_tool_near_a_cap_is_still_polled_fast_because_it_may_burst():
    """Regression: an idle tool that started writing 50 ms later wrote 150 MB inside one 100 ms sleep."""
    previous = (0.0, 0, 0)
    delay = archives._next_poll_delay(limits(max_extracted_bytes=5 * MB), previous, 0.007, 0, 0)
    assert delay < 0.02


def test_a_fast_writer_near_the_byte_cap_is_polled_much_faster():
    previous = (0.0, 0, 0)
    # 1 GB/s towards a 5 MB cap with 1 MB left: the cap is ~1 ms away
    delay = archives._next_poll_delay(limits(max_extracted_bytes=5 * MB), previous, 0.004, 4 * MB, 1)
    assert archives._MIN_POLL_SECONDS <= delay < 0.02


def test_a_fast_file_creator_near_the_count_cap_is_polled_much_faster():
    previous = (0.0, 0, 0)
    delay = archives._next_poll_delay(limits(max_files=1000), previous, 1.0, 0, 900)
    assert archives._MIN_POLL_SECONDS <= delay < 0.1


def test_the_delay_never_drops_below_the_floor():
    previous = (0.0, 0, 0)
    delay = archives._next_poll_delay(limits(max_extracted_bytes=5 * MB), previous, 0.001, 5 * MB - 1, 1)
    assert delay == archives._MIN_POLL_SECONDS
