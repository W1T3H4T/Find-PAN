#!/usr/bin/env -S uv run python
##  ===========================================================================
##  File    :   baseline.py
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   Record what find-pan finds in a set of files as a baseline
##              (--create), and later re-run find-pan the same way to verify
##              that nothing changed (--validate).  A baseline is the directory
##              RegressionTests/baseline/<name>/ holding baseline.csv and
##              baseline.yaml.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================
"""Create and validate find-pan regression baselines.

Design: docs/superpowers/specs/2026-10-17-baseline-tool-design.md
"""

import csv
import hashlib
import os
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_ROOT = REPO_ROOT / "RegressionTests" / "baseline"

CSV_FIELDS = ["filename", "line_number", "offset", "pattern_name", "data_type", "matched_data"]

#   find-pan switches that baseline.py controls itself.
OWNED_SWITCHES = ("--csv", "--log-dir", "--summary-json", "--version", "--verbose", "--debug")
#   find-pan switches whose values are paths and are stored repository-relative.
_PATH_SWITCHES = ("--path", "--file", "--rgx-patterns")

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
#   A file is text when its first bytes contain no NUL.
_TEXT_SAMPLE = 8192
_SUMMARY_FIELDS = ("pans", "tracks", "bad_luhn", "anti_pans", "files_scanned",
                   "archives_expanded", "archives_skipped")


class BaselineError(Exception):
    """A usage or environment problem; the message is shown and the exit status is 2."""


# ===========================================================================
# Names and paths
# ===========================================================================
def validate_name(name: str) -> str:
    """Return *name* if it is a safe baseline name, else raise ``BaselineError``."""
    if not _NAME_PATTERN.match(name) or ".." in name:
        raise BaselineError(
            f"invalid baseline name {name!r}: use letters, digits, '.', '_' and '-' "
            "(starting with a letter or digit, no '..' and no path separators)"
        )
    return name


def to_repo_relative(path: str, root: Path = REPO_ROOT) -> str:
    """Return *path* as a repository-relative path with ``/`` separators.

    The path must exist and lie inside *root* (baselines must be reproducible from a checkout).
    """
    candidate = Path(path)
    if not candidate.exists():
        raise BaselineError(f"{path}: does not exist")
    resolved = candidate.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        raise BaselineError(f"{path}: is outside the repository ({root})") from None


def rewrite_find_pan_args(args: Sequence[str], root: Path = REPO_ROOT) -> list[str]:
    """Return the find-pan arguments with every path rewritten repository-relative.

    Raises ``BaselineError`` when an argument names a switch that baseline.py manages itself.
    """
    rewritten: list[str] = []
    in_file_list = False
    pending_path_value = False
    for arg in args:
        owned = next((s for s in OWNED_SWITCHES if arg == s or arg.startswith(s + "=")), None)
        if owned:
            raise BaselineError(f"{owned} is managed by baseline.py and cannot be passed to find-pan")
        if pending_path_value:
            rewritten.append(to_repo_relative(arg, root))
            pending_path_value = False
        elif arg in ("--path", "--rgx-patterns"):
            rewritten.append(arg)
            pending_path_value, in_file_list = True, False
        elif arg == "--file":
            rewritten.append(arg)
            in_file_list = True
        elif arg.startswith("--"):
            switch, equals, value = arg.partition("=")
            in_file_list = False
            if equals and switch in _PATH_SWITCHES:
                rewritten.append(f"{switch}={to_repo_relative(value, root)}")
            else:
                rewritten.append(arg)
        elif in_file_list:
            rewritten.append(to_repo_relative(arg, root))
        else:
            rewritten.append(arg)
    return rewritten


# ===========================================================================
# Input files
# ===========================================================================
def _path_values(args: Sequence[str]) -> tuple[list[str], list[str]]:
    """Return the ``--path`` directories and ``--file`` entries named in *args*."""
    directories: list[str] = []
    files: list[str] = []
    in_file_list = False
    expect_directory = False
    for arg in args:
        if expect_directory:
            directories.append(arg)
            expect_directory = False
        elif arg == "--path":
            expect_directory, in_file_list = True, False
        elif arg.startswith("--path="):
            directories.append(arg.partition("=")[2])
            in_file_list = False
        elif arg == "--file":
            in_file_list = True
        elif arg.startswith("--"):
            in_file_list = False
        elif in_file_list:
            files.append(arg)
    return directories, files


def enumerate_inputs(args: Sequence[str], root: Path = REPO_ROOT) -> list[str]:
    """List the input files named by ``--path`` / ``--file``, in a platform-independent order.

    Paths are repository-relative with ``/`` separators, sorted by their UTF-8 bytes (not by
    directory-walk order or locale), de-duplicated.  Links, devices and sockets under a
    ``--path`` directory are not listed; archives are listed once (their members are not).
    """
    directories, files = _path_values(args)
    found: set[str] = set()
    baseline_dir = (root / "RegressionTests" / "baseline").resolve()

    for directory in directories:
        relative = to_repo_relative(directory, root)
        base = (root / relative).resolve()
        if not base.is_dir():
            raise BaselineError(f"{directory}: --path must be a directory")
        if baseline_dir.exists() and (base == baseline_dir or baseline_dir in base.parents
                                      or base in baseline_dir.parents):
            raise BaselineError(f"{directory}: inputs must not include the baseline directory itself")
        for current, _, names in os.walk(base):
            for name in names:
                full = Path(current) / name
                if full.is_symlink() or not full.is_file():
                    continue
                found.add(full.resolve().relative_to(root.resolve()).as_posix())

    for entry in files:
        relative = to_repo_relative(entry, root)
        if not (root / relative).is_file():
            raise BaselineError(f"{entry}: --file entries must be files")
        if baseline_dir in (root / relative).resolve().parents:
            raise BaselineError(f"{entry}: inputs must not be inside the baseline directory")
        found.add(relative)

    return sorted(found, key=lambda path: path.encode("utf-8"))


def hash_input(rel_path: str, root: Path = REPO_ROOT) -> dict:
    """Return ``{"path", "size", "sha256", "eol_normalized"}`` for a repository-relative file.

    Text files (no NUL in the first 8 KiB) are hashed after ``\\r\\n`` becomes ``\\n`` so a CRLF
    and an LF checkout agree; binary files and archives are hashed exactly as they are.
    """
    data = (root / rel_path).read_bytes()
    is_text = b"\x00" not in data[:_TEXT_SAMPLE]
    digest = hashlib.sha256(data.replace(b"\r\n", b"\n") if is_text else data).hexdigest()
    return {"path": rel_path, "size": len(data), "sha256": digest, "eol_normalized": is_text}


def inputs_manifest(args: Sequence[str], root: Path = REPO_ROOT) -> list[dict]:
    """Return ``hash_input`` for every input file, in enumeration order."""
    return [hash_input(path, root) for path in enumerate_inputs(args, root)]


# ===========================================================================
# CSV rows
# ===========================================================================
def _row_key(row: Sequence[str]) -> tuple:
    return (row[0], int(row[1]), int(row[2]), row[3], row[4], row[5])


def canonical_rows(rows: Iterable[Sequence[str]]) -> list[tuple[str, ...]]:
    """Return *rows* as tuples sorted by (filename, line, offset, pattern, type, data)."""
    return sorted((tuple(row) for row in rows), key=_row_key)


def read_rows(path: Path) -> list[tuple[str, ...]]:
    """Read a find-pan style CSV (header skipped) into canonical order."""
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        next(reader, None)
        rows = [tuple(row) for row in reader if row]
    for row in rows:
        if len(row) != len(CSV_FIELDS):
            raise BaselineError(f"{path}: malformed CSV row {row!r}")
    return canonical_rows(rows)


def write_canonical_csv(rows: Iterable[Sequence[str]], path: Path) -> None:
    """Write *rows* sorted canonically, with the header, UTF-8 and ``\\n`` line endings."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(CSV_FIELDS)
        writer.writerows(canonical_rows(rows))


# ===========================================================================
# Differences
# ===========================================================================
def diff_rows(baseline_rows: Iterable[Sequence[str]], current_rows: Iterable[Sequence[str]]) -> tuple[list, list]:
    """Return ``(missing, extra)``: rows only in the baseline and rows only in the current run."""
    before = Counter(tuple(row) for row in baseline_rows)
    now = Counter(tuple(row) for row in current_rows)
    return (canonical_rows((before - now).elements()), canonical_rows((now - before).elements()))


def diff_inputs(baseline_inputs: Sequence[dict], current_inputs: Sequence[dict]) -> list[str]:
    """Describe added, removed and changed input files."""
    before = {entry["path"]: entry for entry in baseline_inputs}
    now = {entry["path"]: entry for entry in current_inputs}
    messages = []
    for path in sorted(before.keys() - now.keys(), key=lambda p: p.encode("utf-8")):
        messages.append(f"input removed: {path}")
    for path in sorted(now.keys() - before.keys(), key=lambda p: p.encode("utf-8")):
        messages.append(f"input added: {path}")
    for path in sorted(before.keys() & now.keys(), key=lambda p: p.encode("utf-8")):
        if before[path]["sha256"] != now[path]["sha256"]:
            messages.append(f"input changed: {path} (content differs beyond line endings)")
    return messages


def diff_summary(baseline_summary: dict, current_summary: dict) -> list[str]:
    """Describe differences in the counts and skipped files (times and exit status are ignored)."""
    messages = []
    for field in _SUMMARY_FIELDS:
        if baseline_summary.get(field) != current_summary.get(field):
            messages.append(f"{field}: baseline {baseline_summary.get(field)}, now {current_summary.get(field)}")
    before = Counter(tuple(item) for item in baseline_summary.get("skipped", []))
    now = Counter(tuple(item) for item in current_summary.get("skipped", []))
    for reason, path in sorted((before - now).elements()):
        messages.append(f"skipped missing: [{reason}] {path}")
    for reason, path in sorted((now - before).elements()):
        messages.append(f"skipped extra: [{reason}] {path}")
    return messages


def format_row(row: Sequence[str]) -> str:
    """Format a CSV row as ``file:line:offset  type  pattern  data``."""
    filename, line, offset, pattern, data_type, data = row
    return f"{filename}:{line}:{offset}  {data_type}  {pattern}  {data}"
