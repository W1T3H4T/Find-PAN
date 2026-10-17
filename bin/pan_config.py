#!/usr/bin/env -S uv run python
##  ===========================================================================
##  File    :   pan_config.py
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   Configuration discovery and compilation for Find-PAN.
##              This module locates the JSON regex patterns and the YAML
##              archive-extractor configuration, compiles regular expressions,
##              and determines archive file types.  It contains no side effects,
##              logging, or global application state.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================

import json
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List

import yaml

# - Default extractor configuration filename
_EXTRACTOR_CONFIG_FILENAME = "find-pan-conf.yaml"
EXTRACTOR_CONFIG_FILENAME = _EXTRACTOR_CONFIG_FILENAME


# - Application root directory, used to locate bundled configuration files.
#   ``pan_config.py`` lives in ``<appRoot>/bin``, so its grandparent is the root.
def _application_root() -> str:
    """Return the application root directory containing the ``bin`` folder."""
    return str(Path(__file__).resolve().parents[1])

# - Regex Pattern Prefix
_REGEX_PATTERN_PREFIX = r"[ '\"{]"

# - Archive type detection table
_ARCHIVE_TYPE_MAP: Dict[str, str] = {
    # tar family
    ".tar": "tar",
    ".tar.gz": "tar",
    ".tgz": "tar",
    ".tar.bz2": "tar",
    ".tbz2": "tar",
    ".tar.xz": "tar",
    ".txz": "tar",
    # zip family
    ".zip": "zip",
    ".jar": "zip",
    ".war": "zip",
    ".ear": "zip",
    # 7z family
    ".7z": "7z",
    # gzip single-file
    ".gz": "gzip",
}


def detect_archive_type(archive_path: str) -> str | None:
    """Return the extractor key for a supported archive, or None."""
    lower_name = archive_path.lower()
    #   Check multi-part extensions first so .tar.gz beats .gz
    for suffix, archive_type in sorted(
        _ARCHIVE_TYPE_MAP.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if lower_name.endswith(suffix):
            return archive_type
    return None


# ===========================================================================
# Find and build the extractor configuration file
# ===========================================================================
def find_extractor_config_path() -> str:
    """Return the path to the extractor YAML configuration file.

    Searches, in order:

    1. ``$XDG_CONFIG_HOME/find-pan`` if ``$XDG_CONFIG_HOME`` is set.
    2. ``$HOME/.config/find-pan``.
    3. ``<appRoot>/config`` where ``<appRoot>`` is the directory containing the
       ``bin`` folder that holds ``find-pan.py``.

    If no configuration file exists, it is created exactly once in the first
    writable well-known XDG location, populated by discovering extractors on PATH.
    """
    existing_path = _find_existing_extractor_config()
    if existing_path:
        return existing_path

    config_dir = _find_pan_config_directory()
    config_file = os.path.join(config_dir, _EXTRACTOR_CONFIG_FILENAME)

    if not os.path.exists(config_file):
        try:
            os.makedirs(config_dir, exist_ok=True)
            build_extractor_config(config_file)
        except OSError as e:
            raise FileNotFoundError(
                f"Unable to create {_EXTRACTOR_CONFIG_FILENAME} at {config_file}: {e}"
            ) from e

    return config_file


def _find_existing_extractor_config() -> str | None:
    """Return an existing extractor config file path, or None."""
    home = os.path.expanduser("~")
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")

    candidates = [
        os.path.join(xdg_config_home, "find-pan") if xdg_config_home else None,
        os.path.join(home, ".config", "find-pan"),
        os.path.join(_application_root(), "config"),
    ]

    for config_dir in (path for path in candidates if path):
        config_file = os.path.join(config_dir, _EXTRACTOR_CONFIG_FILENAME)
        if os.path.exists(config_file):
            return config_file

    return None


def _find_pan_config_directory() -> str:
    """Return the established Find-PAN configuration directory.

    1. ``$XDG_CONFIG_HOME/find-pan`` if ``$XDG_CONFIG_HOME`` is set.
    2. ``$HOME/.config/find-pan``.
    """
    home = os.path.expanduser("~")
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")

    if xdg_config_home:
        return os.path.join(xdg_config_home, "find-pan")

    return os.path.join(home, ".config", "find-pan")


def build_extractor_config(config_path: str) -> None:
    """Create an extractor configuration using tools found on PATH."""
    known_commands = {
        "tar": ["tar", "gtar"],
        "zip": ["unzip"],
        "7z": ["7z", "7zz", "7za"],
        "gzip": ["gzip", "gunzip"],
    }

    compression_algorithms = {
        "tar": ["store"],
        "zip": ["store", "deflate", "bzip2", "lzma"],
        "7z": ["store", "lzma", "lzma2", "bzip2", "deflate", "ppmd", "bcj2"],
        "gzip": ["deflate"],
    }

    extractors: Dict[str, Dict] = {}
    for archive_type, commands in known_commands.items():
        tool_path = None
        for command in commands:
            tool_path = shutil.which(command)
            if tool_path:
                break

        if not tool_path:
            extractors[archive_type] = {
                "command": commands[0],
                "args": [],
                "copy_archive_to_tempdir": archive_type == "gzip",
                "compression": compression_algorithms[archive_type],
            }
            continue

        if archive_type == "tar":
            args = ["-xf", "{archive}", "-C", "{tempdir}"]
        elif archive_type == "zip":
            args = ["{archive}", "-d", "{tempdir}"]
        elif archive_type == "7z":
            args = ["x", "{archive}", "-o{tempdir}", "-y"]
        else:  # gzip
            args = ["-d", "{archive}"]

        extractors[archive_type] = {
            "command": command,
            "args": args,
            "copy_archive_to_tempdir": archive_type == "gzip",
            "compression": compression_algorithms[archive_type],
        }


    config = {"extractors": extractors}
    with open(config_path, "w", encoding="utf-8") as config_file:
        yaml.safe_dump(config, config_file, sort_keys=True)


def load_extractor_config(config_path: str) -> Dict[str, Dict]:
    """Load the extractor YAML configuration."""
    with open(config_path, "r", encoding="utf-8", errors="replace") as config_file:
        data = yaml.safe_load(config_file)
    return data.get("extractors", {})


# ===========================================================================
# Find the JSON pattern file
# ===========================================================================
def find_json_regex_config() -> str:
    """Return the path to the JSON regex pattern configuration file.

    Searches, in order:

    1. ``$XDG_CONFIG_HOME/find-pan`` if ``$XDG_CONFIG_HOME`` is set.
    2. ``$HOME/.config/find-pan``.
    3. ``$HOME/.local/find-pan``.
    4. ``$HOME/.local/share/find-pan``.
    5. ``/usr/local/find-pan``.
    6. ``<appRoot>/config`` where ``<appRoot>`` is the directory containing
       the ``bin`` folder that holds ``find-pan.py``.
    """
    home = os.path.expanduser("~")
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")

    config_paths = [
        os.path.join(xdg_config_home, "find-pan") if xdg_config_home else None,
        os.path.join(home, ".config", "find-pan"),
        os.path.join(home, ".local", "find-pan"),
        os.path.join(home, ".local", "share", "find-pan"),
        "/usr/local/find-pan",
        os.path.join(_application_root(), "config"),
    ]

    #   Filter unset environment variables so os.path.join does not crash.
    config_paths = [path for path in config_paths if path]

    for find_pan_dir in config_paths:
        json_file_path = os.path.join(find_pan_dir, "find-pan-regex.json")

        if os.path.exists(json_file_path):
            return json_file_path

    raise FileNotFoundError("JSON configuration file not found")


# ===========================================================================
# Compile the regex patterns with a prefix
# ===========================================================================
def compile_regex_patterns_with_prefix(json_data: dict) -> list:
    """Compile configured regexes, each prefixed with a boundary character class."""
    compiled_patterns = []

    for category, patterns in json_data.items():
        if isinstance(patterns, dict):
            for pattern_name, details in patterns.items():
                if "regex" in details:
                    for pattern in details["regex"]:
                        prefix_pattern = f"{_REGEX_PATTERN_PREFIX}{pattern}"
                        compiled_patterns.append(
                            (category, pattern_name, re.compile(prefix_pattern))
                        )
    return compiled_patterns


# ===========================================================================
# Compile the regex patterns
# ===========================================================================
def compile_regex_patterns(json_data: dict) -> list:
    """Compile configured regexes as-is."""
    compiled_patterns = []

    for category, patterns in json_data.items():
        if isinstance(patterns, dict):
            for pattern_name, details in patterns.items():
                if "regex" in details:
                    for pattern in details["regex"]:
                        compiled_patterns.append(
                            (category, pattern_name, re.compile(pattern))
                        )

    return compiled_patterns


# ===========================================================================
# Load JSON File
# ===========================================================================
def load_json_data(filename: str) -> dict | None:
    """Load and parse the JSON regex pattern configuration."""
    try:
        with open(filename, "r", encoding="utf-8", errors="replace") as file:
            data = json.load(file)
            return data

    except FileNotFoundError as e:
        raise FileNotFoundError(f"Regex pattern file not found: {filename}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in pattern file {filename}: {e}") from e
