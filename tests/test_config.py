"""Tests for find_pan.config: regex and archive-extractor configuration."""

import json
import os
import shutil
import subprocess
import random
import re
from pathlib import Path

import pytest
import yaml

from find_pan import config as find_pan_config

ROOT = Path(__file__).resolve().parents[1]
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"
DEFAULT_EXTRACTOR_CONFIG_PATH = ROOT / "config" / "find-pan-conf.yaml"


@pytest.fixture
def config_module():
    """Override the shared fixture: these tests exercise find_pan.config."""
    return find_pan_config

def test_regex_configuration_loads_and_compiles():
    """Every configured regex section loads and compiles successfully."""
    with CONFIGURATION_PATH.open(encoding="utf-8") as configuration_file:
        configuration = json.load(configuration_file)

    for section_name in ("Anti-PAN Pattern", "TRACK Pattern", "PAN Pattern"):
        patterns = configuration[section_name]
        assert patterns
        for pattern_data in patterns.values():
            assert pattern_data["regex"]
            for regex in pattern_data["regex"]:
                re.compile(regex)


def test_pan_regex_configuration_is_processed(pan_generator):
    """Every configured PAN regex generates a matching, Luhn-valid PAN."""
    patterns = pan_generator.load_pan_patterns(CONFIGURATION_PATH)
    random_source = random.Random(0)

    assert patterns
    for pattern_name, pattern_data in patterns.items():
        generated_pans = pan_generator.generate_pans(pattern_name, pattern_data, 1, random_source)

        assert len(generated_pans) == len(pattern_data["regex"])
        for generated_pan in generated_pans:
            assert re.fullmatch(generated_pan.regex, generated_pan.pan)
            assert pan_generator.luhn_check(generated_pan.pan)


#   ---------------------------------------------------------------------------
#   Archive extractor YAML configuration
#   ---------------------------------------------------------------------------


def test_default_extractor_configuration_exists_and_loads():
    """The bundled find-pan-conf.yaml exists and contains all supported extractors."""
    assert DEFAULT_EXTRACTOR_CONFIG_PATH.exists(), (
        f"Default extractor configuration missing: {DEFAULT_EXTRACTOR_CONFIG_PATH}"
    )

    with DEFAULT_EXTRACTOR_CONFIG_PATH.open(encoding="utf-8") as config_file:
        configuration = yaml.safe_load(config_file)

    assert "extractors" in configuration
    for archive_type in ("tar", "zip", "7z", "gzip"):
        assert archive_type in configuration["extractors"], (
            f"Missing extractor configuration for '{archive_type}'"
        )
        extractor = configuration["extractors"][archive_type]
        assert extractor.get("command"), f"'{archive_type}' has no command"
        assert isinstance(extractor.get("args", []), list)
        assert isinstance(extractor.get("copy_archive_to_tempdir"), bool)
        assert isinstance(extractor.get("compression", []), list)
        assert extractor["compression"]


def test_extractor_configuration_loads_when_file_exists(config_module):
    """load_extractor_config() returns the extractors dictionary from an existing file."""
    extractors = config_module.load_extractor_config(str(DEFAULT_EXTRACTOR_CONFIG_PATH))

    assert isinstance(extractors, dict)
    assert "tar" in extractors
    assert "zip" in extractors
    assert "7z" in extractors
    assert "gzip" in extractors


def test_extractor_configuration_builds_when_file_missing(config_module, tmp_path, monkeypatch):
    """find_extractor_config_path() creates the YAML file when it does not exist."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    #   Hide the bundled appRoot config and the real home directory so the XDG
    #   location is used.
    monkeypatch.setattr(
        config_module, "_application_root", lambda: str(tmp_path / "empty-app-root")
    )
    monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))
    monkeypatch.setattr(
        config_module.shutil,
        "which",
        lambda tool: f"/usr/bin/{tool}" if tool in ("tar", "unzip", "gzip") else None,
    )

    config_path = config_module.find_extractor_config_path()
    assert Path(config_path).exists()

    extractors = config_module.load_extractor_config(config_path)
    assert extractors["tar"]["command"] == "tar"
    assert extractors["zip"]["command"] == "unzip"
    assert extractors["gzip"]["command"] == "gzip"


#   ---------------------------------------------------------------------------
#   JSON regex configuration discovery
#   ---------------------------------------------------------------------------


def test_json_regex_config_prefers_xdg_when_set(config_module, tmp_path, monkeypatch):
    """find_json_regex_config() returns the user XDG file when it exists."""
    config_dir = tmp_path / "find-pan"
    config_dir.mkdir()
    config_file = config_dir / "find-pan-regex.json"
    config_file.write_text('{"PAN Pattern": {}}', encoding="utf-8")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    path = config_module.find_json_regex_config()
    assert path == str(config_file)


def test_json_regex_config_falls_back_to_app_root(config_module, tmp_path, monkeypatch):
    """appRoot config is used when no user-level config exists."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))

    path = config_module.find_json_regex_config()
    assert path.endswith(str(Path("config") / "find-pan-regex.json"))
    assert Path(path).exists()


def test_json_regex_config_raises_when_no_config_exists(
    config_module, tmp_path, monkeypatch
):
    """A missing configuration in every location raises FileNotFoundError."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))
    monkeypatch.setattr(
        config_module, "_application_root", lambda: str(tmp_path / "no-config-here")
    )

    with pytest.raises(FileNotFoundError):
        config_module.find_json_regex_config()


class TestDetectArchiveType:
    """detect_archive_type() maps extensions to extractor keys."""

    @pytest.mark.parametrize(
        ("filename", "expected_type"),
        [
            ("backup.tar", "tar"),
            ("backup.tar.gz", "tar"),
            ("backup.tgz", "tar"),
            ("backup.tar.bz2", "tar"),
            ("backup.tbz2", "tar"),
            ("backup.tar.xz", "tar"),
            ("backup.txz", "tar"),
            ("archive.zip", "zip"),
            ("app.jar", "zip"),
            ("bundle.7z", "7z"),
            ("dump.gz", "gzip"),
            ("UPPER.TAR.GZ", "tar"),
        ],
        ids=lambda item: item[0],
    )
    def test_supported_extensions(self, config_module, filename, expected_type):
        assert config_module.detect_archive_type(filename) == expected_type

    @pytest.mark.parametrize(
        "filename",
        ["readme.txt", "data.bin", "image.png", "archive.unknown"],
    )
    def test_unsupported_extensions_return_none(self, config_module, filename):
        assert config_module.detect_archive_type(filename) is None


class TestExtractorConfig:
    """find-pan-conf.yaml is discovered, built, and loaded."""

    def test_build_extractor_config_creates_yaml_with_discovered_tools(
        self, config_module, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            config_module.shutil,
            "which",
            lambda tool: f"/usr/bin/{tool}" if tool in ("tar", "unzip", "gzip") else None,
        )
        config_path = tmp_path / "find-pan-conf.yaml"

        config_module.build_extractor_config(str(config_path))

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        extractors = data["extractors"]
        assert extractors["tar"]["command"] == "tar"
        assert extractors["zip"]["command"] == "unzip"
        assert extractors["gzip"]["command"] == "gzip"
        #   7z was not discovered, so the first candidate command is recorded.
        assert extractors["7z"]["command"] == "7z"
        #   Compression metadata is present for every extractor.
        for archive_type in ("tar", "zip", "7z", "gzip"):
            assert extractors[archive_type]["compression"]

    def test_load_extractor_config_returns_extractors(self, config_module, tmp_path):
        config_path = tmp_path / "find-pan-conf.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "extractors": {
                        "tar": {"command": "gtar", "args": ["-xf", "{archive}", "-C", "{tempdir}"]}
                    }
                }
            ),
            encoding="utf-8",
        )

        extractors = config_module.load_extractor_config(str(config_path))

        assert extractors["tar"]["command"] == "gtar"



class TestFindExtractorConfigPath:
    """find_extractor_config_path() locates or creates the YAML config.

    Searches, in order:

    1. ``$XDG_CONFIG_HOME/find-pan`` if set.
    2. ``$HOME/.config/find-pan``.
    3. ``<appRoot>/config/find-pan`` where ``<appRoot>`` is the directory
       containing the ``bin`` folder that holds ``find-pan.py``.

    If none of those locations contain a configuration file, one is created in
    the first writable XDG location and populated by discovering extractors on PATH.
    """

    def test_returns_existing_config_file(self, config_module, tmp_path):
        config_dir = tmp_path / "find-pan"
        config_dir.mkdir()
        config_file = config_dir / "find-pan-conf.yaml"
        config_file.write_text("extractors:\n", encoding="utf-8")

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        try:
            path = config_module.find_extractor_config_path()
            assert path == str(config_file)
            #   Existing file must not be overwritten.
            assert Path(path).read_text(encoding="utf-8") == "extractors:\n"
        finally:
            monkeypatch.undo()

    def test_builds_config_under_xdg_config_home(self, config_module, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        #   Hide the bundled appRoot config and the real home directory so the
        #   XDG location is used.
        monkeypatch.setattr(
            config_module, "_application_root", lambda: str(tmp_path / "empty-app-root")
        )
        monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))
        monkeypatch.setattr(
            config_module.shutil,
            "which",
            lambda tool: f"/usr/bin/{tool}" if tool == "tar" else None,
        )

        path = config_module.find_extractor_config_path()

        assert path == str(tmp_path / "find-pan" / "find-pan-conf.yaml")
        assert Path(path).exists()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        assert "extractors" in data
        assert data["extractors"]["tar"]["command"] == "tar"

    def test_builds_config_under_home_dot_config_when_xdg_unset(
        self, config_module, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        #   Force the search to the tmp_path by overriding the home directory.
        monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))
        #   Hide the bundled appRoot config so the home directory is used.
        monkeypatch.setattr(
            config_module, "_application_root", lambda: str(tmp_path / "empty-app-root")
        )
        monkeypatch.setattr(
            config_module.shutil,
            "which",
            lambda tool: f"/usr/bin/{tool}" if tool == "tar" else None,
        )

        path = config_module.find_extractor_config_path()

        assert path == str(tmp_path / ".config" / "find-pan" / "find-pan-conf.yaml")
        assert Path(path).exists()

    def test_returns_app_root_extractor_config_when_no_user_config(
        self, config_module, tmp_path, monkeypatch
    ):
        """An appRoot config is used when no user-level config exists."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))

        path = config_module.find_extractor_config_path()

        assert path.endswith(os.path.join("config", "find-pan-conf.yaml"))
        assert Path(path).exists()

    def test_raises_when_config_directory_cannot_be_created(
        self, config_module, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "not-a-directory"))
        #   Hide the bundled appRoot config and the real home directory so
        #   creation in the XDG location is attempted.
        monkeypatch.setattr(
            config_module, "_application_root", lambda: str(tmp_path / "empty-app-root")
        )
        monkeypatch.setattr(config_module.os.path, "expanduser", lambda _p: str(tmp_path))
        monkeypatch.setattr(
            config_module.os,
            "makedirs",
            lambda _path, exist_ok=False: (_ for _ in ()).throw(OSError("no write")),
        )

        with pytest.raises(FileNotFoundError):
            config_module.find_extractor_config_path()


class TestArchiveTypeDetection:
    """Longest multi-part extension wins over shorter suffixes."""

    def test_tar_gz_beats_gz(self, config_module):
        assert config_module.detect_archive_type("file.tar.gz") == "tar"

    def test_case_insensitive_matching(self, config_module):
        assert config_module.detect_archive_type("FILE.ZIP") == "zip"


def test_dump_patterns_round_trips_json():
    data = json.loads(CONFIGURATION_PATH.read_text(encoding="utf-8"))
    assert json.loads(find_pan_config.dump_patterns(data)) == data


def test_application_root_is_repository_root():
    root = Path(find_pan_config._application_root())
    assert (root / "config" / "find-pan-regex.json").exists()


def test_invalid_regex_raises_config_error():
    from find_pan.errors import ConfigError

    data = {"PAN Pattern": {"X": {"regex": ["(unclosed"], "length": "16"}}}
    with pytest.raises(ConfigError):
        find_pan_config.compile_regex_patterns(data)
    with pytest.raises(ConfigError):
        find_pan_config.compile_regex_patterns_with_prefix(data)


def test_malformed_extractor_yaml_raises_config_error(tmp_path):
    from find_pan.errors import ConfigError

    bad = tmp_path / "conf.yaml"
    bad.write_text("extractors: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError):
        find_pan_config.load_extractor_config(str(bad))
