"""Configuration discovery and compilation for Find-PAN.

Locates the JSON regex patterns and the YAML archive-extractor configuration,
compiles the regular expressions, and determines archive file types.  This
module has no side effects, logging, or global application state.
"""

import json
import logging
import os
import re
import shutil
import sys
from dataclasses import asdict, fields
from pathlib import Path
from typing import Dict, List

import yaml

from find_pan.errors import ConfigError
from find_pan.models import ExtractionLimits

logger = logging.getLogger("find_pan.config")

# - Default extractor configuration filename
_EXTRACTOR_CONFIG_FILENAME = "find-pan-conf.yaml"
EXTRACTOR_CONFIG_FILENAME = _EXTRACTOR_CONFIG_FILENAME


# - Application root directory, used to locate bundled configuration files.
#   This file lives in ``<appRoot>/src/find_pan``, so its great-grandparent is the root.
def _application_root() -> str:
    """Return the application root directory containing ``config/``."""
    return str(Path(__file__).resolve().parents[2])

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
        if _is_user_level(existing_path) and _is_legacy_config(existing_path):
            _migrate_legacy_config(existing_path)
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


def _is_user_level(config_path: str) -> bool:
    """Whether *config_path* is a per-user file (never the application's shipped configuration)."""
    shipped = os.path.normcase(os.path.join(_application_root(), "config"))
    return os.path.normcase(os.path.dirname(os.path.abspath(config_path))) != shipped


def _is_legacy_config(config_path: str) -> bool:
    """Whether the file is a flat-format configuration written by find-pan before platform sections.

    Such files were generated automatically on first use and persist; with GNU tar on Windows their
    ``tar`` entry no longer works.  A file with the current ``schema`` marker, or without any flat
    entry (for instance a hand-written one that already uses platform sections), is not legacy.
    """
    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as config_file:
            data = yaml.safe_load(config_file)
    except (OSError, yaml.YAMLError):
        return False                                   # unreadable: load_extractor_config reports it
    if not isinstance(data, dict) or data.get("schema") == SCHEMA_VERSION:
        return False
    extractors = data.get("extractors")
    if not isinstance(extractors, dict):
        return False
    return any(isinstance(entry, dict) and "command" in entry
               and not any(section in entry for section in PLATFORM_SECTIONS)
               for entry in extractors.values())


def _migrate_legacy_config(config_path: str) -> str:
    """Keep the old file as ``<name>.legacy`` (never overwriting a backup) and write the defaults."""
    backup = config_path + ".legacy"
    number = 1
    while os.path.exists(backup):
        number += 1
        backup = f"{config_path}.legacy{number}"
    os.replace(config_path, backup)
    build_extractor_config(config_path)
    logger.warning(
        "Replaced the legacy extractor configuration %s with the current defaults (platform sections). "
        "The old file is kept as %s; copy any customizations into the new file.", config_path, backup,
    )
    return backup


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


#   Version of the configuration layout; written to generated files so that an older generated file
#   (flat entries, no platform sections) can be recognized and upgraded.
SCHEMA_VERSION = 2

#   Sections of an extractor entry that hold per-platform candidates, in lookup order after the exact
#   platform: "posix" covers every platform except Windows.
PLATFORM_SECTIONS = ("windows", "linux", "macos", "posix")
_CWD_VALUES = (None, "tempdir")

#   Windows 10+ ships bsdtar here; it needs no special arguments and also extracts zip files.
_BSDTAR = r"%SystemRoot%\System32\tar.exe"
#   GNU tar on Windows reads "C:" as a host name (--force-local) and the builds disagree about path
#   syntax, so it runs inside the extraction directory (cwd: tempdir) with the destination ".".
_GNU_TAR_WINDOWS = ["--force-local", "-xf", "{archive_posix}", "-C", "."]
_TAR = ["-xf", "{archive}", "-C", "{tempdir}"]
_UNZIP = ["{archive}", "-d", "{tempdir}"]
_SEVEN_ZIP = ["x", "{archive}", "-o{tempdir}", "-y"]

#   The extractors used when no configuration file exists and written into a newly created one.  For
#   every archive type: platform sections ("windows", "linux", "macos", "posix") holding one candidate
#   or an ordered list of candidates; the first whose command exists is used.
DEFAULT_EXTRACTORS: Dict[str, Dict] = {
    "tar": {
        "compression": ["store"],
        "windows": [
            {"command": _BSDTAR, "args": _TAR},
            {"command": r"%ProgramFiles%\Git\usr\bin\tar.exe", "args": _GNU_TAR_WINDOWS, "cwd": "tempdir"},
            {"command": r"%ProgramFiles(x86)%\GnuWin32\bin\tar.exe", "args": _GNU_TAR_WINDOWS, "cwd": "tempdir"},
            {"command": "tar", "args": _GNU_TAR_WINDOWS, "cwd": "tempdir"},
        ],
        "posix": [{"command": "tar", "args": _TAR}],
    },
    "zip": {
        "compression": ["store", "deflate", "bzip2", "lzma"],
        "windows": [
            {"command": "unzip", "args": _UNZIP},
            {"command": r"%ProgramFiles%\Git\usr\bin\unzip.exe", "args": _UNZIP},
            {"command": _BSDTAR, "args": _TAR},
        ],
        "posix": [{"command": "unzip", "args": _UNZIP}],
    },
    "7z": {
        "compression": ["store", "lzma", "lzma2", "bzip2", "deflate", "ppmd", "bcj2"],
        "windows": [
            {"command": r"%ProgramFiles%\7-Zip\7z.exe", "args": _SEVEN_ZIP},
            {"command": "7z", "args": _SEVEN_ZIP},
            {"command": "7za", "args": _SEVEN_ZIP},
        ],
        "posix": [
            {"command": "7zz", "args": _SEVEN_ZIP},
            {"command": "7z", "args": _SEVEN_ZIP},
            {"command": "7za", "args": _SEVEN_ZIP},
        ],
    },
    "gzip": {
        "compression": ["deflate"],
        "copy_archive_to_tempdir": True,
        "windows": [
            {"command": "gzip", "args": ["-d", "{archive}"]},
            {"command": r"%ProgramFiles%\Git\usr\bin\gzip.exe", "args": ["-d", "{archive}"]},
        ],
        "posix": [{"command": "gzip", "args": ["-d", "{archive}"]}],
    },
}


def platform_key(system_platform: str | None = None) -> str:
    """Return the configuration key for a ``sys.platform`` value: windows, linux, macos or other."""
    system_platform = sys.platform if system_platform is None else system_platform
    if system_platform in ("win32", "cygwin"):
        return "windows"
    if system_platform.startswith("linux"):
        return "linux"
    if system_platform == "darwin":
        return "macos"
    return "other"


def extractor_candidates(entry: Dict, platform: str | None = None) -> List[Dict]:
    """Return the ordered candidate extractors of *entry* for *platform* (default: this system).

    An entry is either flat (``command``/``args`` at the top, the original format, one candidate for
    every platform) or has platform sections.  The exact platform section is used, else ``posix`` for
    any non-Windows platform, else the flat keys.  Entry-level settings that are not sections
    (``copy_archive_to_tempdir``, limit overrides, ``compression``) are defaults for each candidate.
    """
    platform = platform_key() if platform is None else platform
    defaults = {key: value for key, value in entry.items() if key not in PLATFORM_SECTIONS}
    section = entry.get(platform)
    if section is None and platform != "windows":
        section = entry.get("posix")
    if section is None:
        return [defaults] if "command" in defaults else []
    candidates = section if isinstance(section, list) else [section]
    return [{**defaults, **candidate} for candidate in candidates]


def _validate_candidate(candidate: object, where: str) -> None:
    if not isinstance(candidate, dict):
        raise ConfigError(f"{where}: expected a mapping with 'command' and 'args', got {candidate!r}")
    if not isinstance(candidate.get("command"), str) or not candidate["command"]:
        raise ConfigError(f"{where}: 'command' must be a non-empty string")
    arguments = candidate.get("args", [])
    if not isinstance(arguments, list) or not all(isinstance(arg, str) for arg in arguments):
        raise ConfigError(f"{where}: 'args' must be a list of strings")
    if candidate.get("cwd") not in _CWD_VALUES:
        raise ConfigError(f"{where}: 'cwd' must be 'tempdir' (or omitted), got {candidate['cwd']!r}")


def validate_extractors(extractors: object, source: str = "extractor configuration") -> None:
    """Raise ``ConfigError`` unless *extractors* is a valid mapping of archive type to entry."""
    if not isinstance(extractors, dict):
        raise ConfigError(f"{source}: 'extractors' must be a mapping")
    for archive_type, entry in extractors.items():
        where = f"{source}: extractor '{archive_type}'"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a mapping, got {entry!r}")
        if "command" in entry:                       # flat format
            _validate_candidate(entry, where)
        for section_name in PLATFORM_SECTIONS:
            if section_name not in entry:
                continue
            section = entry[section_name]
            if not isinstance(section, (dict, list)):
                raise ConfigError(f"{where}, {section_name}: expected a mapping or a list of mappings")
            for number, candidate in enumerate(section if isinstance(section, list) else [section], 1):
                _validate_candidate(candidate, f"{where}, {section_name} #{number}")


_CONFIG_HEADER = """\
# Find-PAN archive extractor configuration.
#
# find-pan expands archives with locally installed tools.  For each archive type this file lists, per
# platform (windows, linux, macos, posix = any non-Windows system), one or more candidate commands; the
# first whose command exists is used.  See README.md ("Extractor configuration") for the full schema.
#
"""


def build_extractor_config(config_path: str) -> None:
    """Write the default extractor configuration (see ``DEFAULT_EXTRACTORS``) to *config_path*."""
    document = {"schema": SCHEMA_VERSION, "limits": asdict(ExtractionLimits()), "extractors": DEFAULT_EXTRACTORS}
    with open(config_path, "w", encoding="utf-8", newline="\n") as config_file:
        config_file.write(_CONFIG_HEADER)
        yaml.safe_dump(document, config_file, sort_keys=True)


def load_extraction_limits(config_path: str) -> ExtractionLimits:
    """Load the ``limits`` section of the extractor YAML (defaults for anything omitted).

    Raises ``ConfigError`` for unknown keys or values that are not positive integers.
    """
    with open(config_path, "r", encoding="utf-8", errors="replace") as config_file:
        try:
            data = yaml.safe_load(config_file)
        except yaml.YAMLError as error:
            raise ConfigError(f"Invalid extractor configuration {config_path}: {error}") from error
    section = (data or {}).get("limits") if isinstance(data, dict) else None
    if section is None:
        return ExtractionLimits()
    if not isinstance(section, dict):
        raise ConfigError(f"Invalid limits in {config_path}: expected a mapping")
    allowed = {field.name for field in fields(ExtractionLimits)}
    for key, value in section.items():
        if key not in allowed:
            raise ConfigError(f"Unknown limit '{key}' in {config_path}; expected one of {sorted(allowed)}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigError(f"Limit '{key}' in {config_path} must be a positive integer, got {value!r}")
    return ExtractionLimits(**section)


def load_extractor_config(config_path: str) -> Dict[str, Dict]:
    """Load the extractor YAML configuration.

    Raises ``ConfigError`` when the file is not valid YAML or not a mapping.
    """
    with open(config_path, "r", encoding="utf-8", errors="replace") as config_file:
        try:
            data = yaml.safe_load(config_file)
        except yaml.YAMLError as error:
            raise ConfigError(f"Invalid extractor configuration {config_path}: {error}") from error
    if not isinstance(data, dict):
        raise ConfigError(f"Invalid extractor configuration {config_path}: expected a mapping")
    extractors = data.get("extractors", {})
    validate_extractors(extractors, f"extractor configuration {config_path}")
    return extractors


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
def _compile(pattern: str, category: str, pattern_name: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as error:
        raise ConfigError(f"Invalid regex in {category} / {pattern_name}: {error}") from error


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
                            (category, pattern_name, _compile(prefix_pattern, category, pattern_name))
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
                            (category, pattern_name, _compile(pattern, category, pattern_name))
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


def dump_patterns(json_data: dict) -> str:
    """Return the pattern configuration as indented JSON (for --debug)."""
    return json.dumps(json_data, indent=4)
