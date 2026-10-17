"""Tests for processing the PAN regex and archive extractor configurations."""

import json
import random
import re
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"
DEFAULT_EXTRACTOR_CONFIG_PATH = ROOT / "config" / "find-pan-conf.yaml"


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


def test_extractor_configuration_loads_when_file_exists(pan_config):
    """load_extractor_config() returns the extractors dictionary from an existing file."""
    extractors = pan_config.load_extractor_config(str(DEFAULT_EXTRACTOR_CONFIG_PATH))

    assert isinstance(extractors, dict)
    assert "tar" in extractors
    assert "zip" in extractors
    assert "7z" in extractors
    assert "gzip" in extractors


def test_extractor_configuration_builds_when_file_missing(pan_config, tmp_path, monkeypatch):
    """find_extractor_config_path() creates the YAML file when it does not exist."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    #   Hide the bundled appRoot config and the real home directory so the XDG
    #   location is used.
    monkeypatch.setattr(
        pan_config, "_application_root", lambda: str(tmp_path / "empty-app-root")
    )
    monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))
    monkeypatch.setattr(
        pan_config.shutil,
        "which",
        lambda tool: f"/usr/bin/{tool}" if tool in ("tar", "unzip", "gzip") else None,
    )

    config_path = pan_config.find_extractor_config_path()
    assert Path(config_path).exists()

    extractors = pan_config.load_extractor_config(config_path)
    assert extractors["tar"]["command"] == "tar"
    assert extractors["zip"]["command"] == "unzip"
    assert extractors["gzip"]["command"] == "gzip"


#   ---------------------------------------------------------------------------
#   JSON regex configuration discovery (BUG-005)
#   ---------------------------------------------------------------------------


def test_json_regex_config_prefers_xdg_when_set(pan_config, tmp_path, monkeypatch):
    """find_json_regex_config() returns the user XDG file when it exists."""
    config_dir = tmp_path / "find-pan"
    config_dir.mkdir()
    config_file = config_dir / "find-pan-regex.json"
    config_file.write_text('{"PAN Pattern": {}}', encoding="utf-8")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    path = pan_config.find_json_regex_config()
    assert path == str(config_file)


def test_json_regex_config_falls_back_to_app_root(pan_config, tmp_path, monkeypatch):
    """BUG-005: appRoot config is used when no user-level config exists."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))

    path = pan_config.find_json_regex_config()
    assert path.endswith(str(Path("config") / "find-pan-regex.json"))
    assert Path(path).exists()


def test_json_regex_config_raises_when_no_config_exists(
    pan_config, tmp_path, monkeypatch
):
    """A missing configuration in every location raises FileNotFoundError."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(pan_config.os.path, "expanduser", lambda _p: str(tmp_path))
    monkeypatch.setattr(
        pan_config, "_application_root", lambda: str(tmp_path / "no-config-here")
    )

    with pytest.raises(FileNotFoundError):
        pan_config.find_json_regex_config()
