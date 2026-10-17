"""Tests for find_pan.archives.extract_archive."""

import gzip
import logging
import subprocess
from pathlib import Path

import pytest

from find_pan import archives
from find_pan.errors import ExtractorError

LOGGER = logging.getLogger("test.archives")


def tar_config(**overrides):
    entry = {"command": "tar", "args": ["{archive}", "{tempdir}"], "copy_archive_to_tempdir": False}
    entry.update(overrides)
    return {"tar": entry}


class Runner:
    """Records the command and optionally runs a side effect inside the temp dir."""

    def __init__(self, effect=None, error=None):
        self.effect, self.error, self.commands = effect, error, []

    def __call__(self, cmd, check, capture_output, text):
        self.commands.append(cmd)
        if self.error:
            raise self.error
        if self.effect:
            self.effect(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_extract_archive_yields_dir_and_removes_it(tmp_path):
    def effect(cmd):
        (Path(cmd[-1]) / "safe.txt").write_text("hello", encoding="utf-8")

    runner = Runner(effect)
    with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="fake"),
                                  str(tmp_path / "tmp"), LOGGER, runner=runner) as directory:
        assert (Path(directory) / "safe.txt").read_text(encoding="utf-8") == "hello"
        kept = directory
    assert not Path(kept).exists()
    assert runner.commands[0][-2:] == [str(tmp_path / "a.tar"), kept]


def test_extract_archive_formats_args_with_archive_and_tempdir(tmp_path):
    runner = Runner()
    config = tar_config(command="fake", args=["-x", "{archive}", "-C", "{tempdir}"])
    with archives.extract_archive(str(tmp_path / "a.tar"), config, str(tmp_path / "tmp"),
                                  LOGGER, runner=runner) as directory:
        assert runner.commands[0][1:] == ["-x", str(tmp_path / "a.tar"), "-C", directory]


def test_extract_archive_copies_archive_when_configured(tmp_path):
    gz_path = tmp_path / "dump.gz"
    with gzip.open(gz_path, "wb") as handle:
        handle.write(b"data")
    runner = Runner()
    config = {"gzip": {"command": "gzip", "args": ["-d", "{archive}"], "copy_archive_to_tempdir": True}}
    with archives.extract_archive(str(gz_path), config, str(tmp_path / "tmp"), LOGGER,
                                  runner=runner) as directory:
        copied = Path(runner.commands[0][-1])
        assert copied.name == "dump.gz" and copied.parent == Path(directory)
        assert copied.exists()
    assert not copied.parent.exists()


def test_extract_archive_removes_dir_when_runner_fails(tmp_path):
    seen = {}

    def effect(cmd):
        seen["dir"] = cmd[-1]
        raise subprocess.CalledProcessError(2, cmd, stderr="broken archive")

    runner = Runner(effect)
    with pytest.raises(ExtractorError, match="Extractor failed.*broken archive"):
        with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="fake"),
                                      str(tmp_path / "tmp"), LOGGER, runner=runner):
            pass
    assert not Path(seen["dir"]).exists()


def test_unsupported_type_raises_extractor_error(tmp_path):
    with pytest.raises(ExtractorError, match="Unsupported archive type"):
        with archives.extract_archive(str(tmp_path / "data.rar"), {}, str(tmp_path), LOGGER):
            pass


def test_missing_extractor_raises_extractor_error(tmp_path):
    with pytest.raises(ExtractorError, match="No extractor configured"):
        with archives.extract_archive(str(tmp_path / "a.zip"), {"tar": {}}, str(tmp_path), LOGGER):
            pass


def test_incomplete_extractor_raises_extractor_error(tmp_path):
    with pytest.raises(ExtractorError, match="Incomplete extractor configuration"):
        with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(args=[]), str(tmp_path), LOGGER):
            pass


def test_missing_command_raises_extractor_error(tmp_path, monkeypatch):
    monkeypatch.setattr(archives.shutil, "which", lambda command: None)
    runner = Runner(error=FileNotFoundError("nope"))
    with pytest.raises(ExtractorError, match="Extractor command not found"):
        with archives.extract_archive(str(tmp_path / "a.tar"), tar_config(command="not-installed"),
                                      str(tmp_path / "tmp"), LOGGER, runner=runner):
            pass


def test_copy_failure_raises_extractor_error(tmp_path):
    config = {"gzip": {"command": "gzip", "args": ["-d", "{archive}"], "copy_archive_to_tempdir": True}}
    with pytest.raises(ExtractorError, match="Cannot copy"):
        with archives.extract_archive(str(tmp_path / "missing.gz"), config, str(tmp_path / "tmp"), LOGGER,
                                      runner=Runner()):
            pass
    assert not list((tmp_path / "tmp").glob("find-pan-*"))
