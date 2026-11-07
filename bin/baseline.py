#!/usr/bin/env -S uv run python
##  ===========================================================================
##  File    :   baseline.py
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   Record what find-pan finds in a set of files as a baseline
##              (--create), and later re-run find-pan the same way to verify
##              that nothing changed (--validate). Configurations are saved in
##              RegressionTests/baseline/<name>.yaml and expected CSVs in its output/ directory.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================
"""Create and validate find-pan regression baselines."""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from find_pan.archives import select_candidate  # noqa: E402  # pylint: disable=wrong-import-position
from find_pan.config import extractor_candidates, find_extractor_config_path, load_extractor_config  # noqa: E402  # pylint: disable=wrong-import-position
from find_pan.filetypes import FileKind, classify_head  # noqa: E402  # pylint: disable=wrong-import-position
from find_pan.version import __version__ as find_pan_version  # noqa: E402  # pylint: disable=wrong-import-position

BASELINE_RELATIVE_ROOT = Path("RegressionTests") / "baseline"
BASELINE_ROOT = REPO_ROOT / BASELINE_RELATIVE_ROOT
OUTPUT_DIRECTORY_NAME = "output"

CSV_FIELDS = ["filename", "line_number", "offset", "pattern_name", "data_type", "matched_data"]

#   find-pan switches whose values are paths and are stored repository-relative.
_PATH_SWITCHES = ("--path", "--file", "--rgx-patterns")

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_CONFIG_SUFFIXES = {".yaml", ".yml"}
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
    if (not _NAME_PATTERN.fullmatch(name) or ".." in name
            or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", name.split(".")[0], re.IGNORECASE)):
        raise BaselineError(
            f"invalid baseline name {name!r}: use letters, digits, '.', '_' and '-' "
            "(starting with a letter or digit, no '..' and no path separators)"
        )
    return name


def _baseline_config_path(identifier: str, root: Path, baseline_root: Path) -> tuple[str, Path]:
    """Resolve a baseline name or YAML path to its config path."""
    if baseline_root.is_symlink():
        raise BaselineError("baseline directory must not be a symbolic link")
    supplied = Path(identifier)
    if supplied.suffix.lower() == ".json":
        raise BaselineError("baseline configuration must use YAML (.yaml); JSON is not supported")
    if supplied.suffix.lower() not in _CONFIG_SUFFIXES:
        validate_name(identifier)
        matches = [path for path in baseline_root.glob(f"{identifier}.*")
                   if path.suffix.lower() in _CONFIG_SUFFIXES and path.stem == identifier]
        if len(matches) > 1:
            raise BaselineError(f"configuration filename collision for baseline {identifier!r}")
        supplied = Path(matches[0].name if matches else f"{identifier}.yaml")

    for existing in baseline_root.glob("*"):
        if (existing.suffix.lower() in _CONFIG_SUFFIXES
                and existing.stem.casefold() == supplied.stem.casefold()
                and existing.name != supplied.name):
            raise BaselineError(f"configuration filename collision: {existing.name} and {supplied.name}")

    if supplied.is_absolute():
        config_path = supplied.resolve()
    elif supplied.parent == Path("."):
        config_path = (baseline_root / supplied).resolve()
    else:
        repository_candidate = (root / supplied).resolve()
        try:
            repository_candidate.relative_to(baseline_root.resolve())
            config_path = repository_candidate
        except ValueError:
            config_path = (baseline_root / supplied).resolve()

    if config_path.parent != baseline_root.resolve():
        raise BaselineError(f"baseline config must be directly inside {baseline_root}: {identifier}")
    if (baseline_root / supplied.name).is_symlink():
        raise BaselineError("baseline configuration files must not be symbolic links")

    validate_name(config_path.stem)
    return config_path.stem, config_path


def _load_baseline_document(config_path: Path) -> dict:
    """Read a YAML baseline configuration."""
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise BaselineError(f"{config_path.name} must contain a mapping")
    return document


def _csv_path(config_path: Path, document: dict) -> Path:
    """Resolve the uniquely named CSV beneath baseline/output."""
    default_name = f"{config_path.stem}.csv"
    csv_name = document.get("csv_file", default_name)
    if csv_name != default_name:
        raise BaselineError(f"{config_path.name}: csv_file must be {default_name!r} in baseline/output")
    output_directory = config_path.parent / OUTPUT_DIRECTORY_NAME
    if output_directory.is_symlink():
        raise BaselineError("baseline/output must not be a symbolic link")
    return output_directory / csv_name


def _check_collisions(config_path: Path, csv_path: Path, force: bool) -> None:
    """Reject filename aliases and outputs owned by another baseline, even with --force."""
    for path in config_path.parent.glob("*"):
        if path.suffix.lower() not in _CONFIG_SUFFIXES:
            continue
        if path.name == config_path.name:
            continue
        if path.stem.casefold() == config_path.stem.casefold():
            raise BaselineError(f"configuration/output filename collision: {path.name} and {config_path.name}")
        try:
            document = _load_baseline_document(path)
        except (BaselineError, OSError, UnicodeError, yaml.YAMLError):
            continue
        stored_csv = document.get("csv_file", f"{path.stem}.csv")
        if isinstance(stored_csv, str) and stored_csv.casefold() == csv_path.name.casefold():
            raise BaselineError(f"output filename collision: {csv_path.name} is referenced by {path.name}")
    for path in csv_path.parent.glob("*"):
        if path.name.casefold() == csv_path.name.casefold() and path.name != csv_path.name:
            raise BaselineError(f"output filename collision: {path.name} and {csv_path.name}")
    for path in (config_path, csv_path):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise BaselineError(f"baseline artifact must be a regular file: {path}")
    if csv_path.exists() and not config_path.exists():
        raise BaselineError(f"output filename collision: {csv_path} has no matching configuration")
    if config_path.exists() and not force:
        raise BaselineError(f"baseline configuration already exists ({config_path}); use --force to regenerate it")


def to_repo_relative(path: str, root: Path = REPO_ROOT, base: Path | None = None) -> str:
    """Return *path* as a repository-relative path with ``/`` separators.

    A relative *path* is taken from the current directory (what a user types), or from *base*
    when given (what was stored: repository-relative).  It must exist and lie inside *root*
    (baselines must be reproducible from a checkout).
    """
    candidate = Path(path)
    if base is not None and not candidate.is_absolute():
        candidate = base / candidate
    if not candidate.exists():
        raise BaselineError(f"{path}: does not exist")
    resolved = candidate.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        raise BaselineError(f"{path}: is outside the repository ({root})") from None


def rewrite_find_pan_args(args: Sequence[str], root: Path = REPO_ROOT) -> list[str]:
    """Return the find-pan arguments with every path rewritten repository-relative.

    Other find-pan arguments are left unchanged.
    """
    rewritten: list[str] = []
    in_file_list = False
    pending_path_value = False
    for arg in args:
        switch_name = arg.partition("=")[0]
        if (arg.startswith("--") and len(switch_name) > 2 and switch_name not in _PATH_SWITCHES
                and any(known.startswith(switch_name) for known in _PATH_SWITCHES)):
            raise BaselineError(f"{switch_name}: abbreviated switch; use the full switch name")
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
        elif arg.startswith("--file="):
            files.append(arg.partition("=")[2])
            in_file_list = False
        elif arg.startswith("--"):
            in_file_list = False
        elif in_file_list:
            files.append(arg)
    return directories, files


def enumerate_inputs(args: Sequence[str], root: Path = REPO_ROOT, baseline_root: Path | None = None) -> list[str]:
    """List the input files named by ``--path`` / ``--file``, in a platform-independent order.

    Paths are repository-relative with ``/`` separators, sorted by their UTF-8 bytes (not by
    directory-walk order or locale), de-duplicated.  Links, devices and sockets under a
    ``--path`` directory are not listed; archives are listed once (their members are not).
    """
    directories, files = _path_values(args)
    if len(directories) > 1:
        raise BaselineError("only one --path is allowed (find-pan scans only the last one)")
    found: set[str] = set()
    baseline_dir = (baseline_root if baseline_root is not None else root / BASELINE_RELATIVE_ROOT).resolve()

    for directory in directories:
        relative = to_repo_relative(directory, root, base=root)
        base = (root / relative).resolve()
        if not base.is_dir():
            raise BaselineError(f"{directory}: --path must be a directory")
        #   Refused even when the baseline directory does not exist yet: the first baseline created
        #   would put its own output inside the scanned tree and every later validate would fail.
        if base == baseline_dir or baseline_dir in base.parents or base in baseline_dir.parents:
            raise BaselineError(f"{directory}: inputs must not include the baseline directory itself")
        for current, _, names in os.walk(base):
            for name in names:
                full = Path(current) / name
                if full.is_symlink() or not full.is_file():
                    continue
                found.add(full.resolve().relative_to(root.resolve()).as_posix())

    for entry in files:
        relative = to_repo_relative(entry, root, base=root)
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


def inputs_manifest(args: Sequence[str], root: Path = REPO_ROOT, baseline_root: Path | None = None) -> list[dict]:
    """Return ``hash_input`` for every input file, in enumeration order."""
    return [hash_input(path, root) for path in enumerate_inputs(args, root, baseline_root)]


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
        try:
            _row_key(row)
        except ValueError:
            raise BaselineError(f"{path}: the line number or offset is not a number in row {row!r}") from None
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

# ===========================================================================
# Running find-pan
# ===========================================================================
@dataclass
class RunResult:
    """What one find-pan run produced."""

    rows: list[tuple[str, ...]]
    summary: dict
    status: int
    stderr: str


def run_find_pan(args: Sequence[str], root: Path = REPO_ROOT) -> RunResult:
    """Run ``bin/find-pan.py`` (as a subprocess, in *root*) and collect its CSV and summary.

    Exit statuses 0 and 1 are results (1 means a requested file was never scanned); anything
    else, or missing output, raises ``BaselineError`` with find-pan's stderr.
    """
    with tempfile.TemporaryDirectory(prefix="baseline-") as scratch:
        csv_path = Path(scratch) / "findings.csv"
        json_path = Path(scratch) / "summary.json"
        command = [sys.executable, str(root / "bin" / "find-pan.py"), *args,
                   "--csv", str(csv_path), "--log-dir", str(Path(scratch) / "logs"),
                   "--summary-json", str(json_path)]
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", check=False)
        if completed.returncode not in (0, 1) or not csv_path.exists() or not json_path.exists():
            detail = (completed.stderr or completed.stdout).strip()[-1500:]
            raise BaselineError(f"find-pan failed (exit status {completed.returncode}): {detail}")
        rows = read_rows(csv_path)
        summary = json.loads(json_path.read_text(encoding="utf-8"))
    return RunResult(rows, summary, completed.returncode, completed.stderr)


def required_tools(inputs: Iterable[str], root: Path = REPO_ROOT) -> list[str]:
    """Return the extractor commands needed to expand the archives among *inputs* (sorted, unique)."""
    extractors = load_extractor_config(find_extractor_config_path())
    logger = logging.getLogger("baseline")
    tools: set[str] = set()
    for rel_path in inputs:
        with open(root / rel_path, "rb") as handle:
            head = handle.read(1024)
        classification = classify_head(head, rel_path, False, logger)
        if classification.kind is FileKind.ARCHIVE:
            #   The tool that would run on this system: the first installed candidate, or else the first
            #   candidate (so a missing tool is named and --create refuses).
            entry = extractors.get(classification.archive_type, {})
            candidates = [c for c in extractor_candidates(entry) if c.get("command")]
            if candidates:
                chosen, _ = select_candidate(candidates)
                tools.add(Path(os.path.expandvars(chosen["command"])).stem)
    return sorted(tools)


def tool_available(tool: str, extractors: dict) -> bool:
    """Is *tool* usable here: on PATH, or replaceable by another installed candidate for the same archive type?

    A baseline records the tool that expanded its archives where it was created (say ``unzip``).  Where
    that tool is missing, any other configured candidate of the same type (say 7-Zip for zip) does the job.
    """
    if shutil.which(tool):
        return True
    for entry in extractors.values():
        candidates = [c for c in extractor_candidates(entry) if c.get("command")]
        if any(Path(os.path.expandvars(c["command"])).stem == tool for c in candidates):
            if any(shutil.which(os.path.expandvars(c["command"])) for c in candidates):
                return True
    return False


# ===========================================================================
# --create
# ===========================================================================
def _has_input(args: Sequence[str]) -> bool:
    directories, files = _path_values(args)
    return bool(directories or files)


def _write_file_baseline(config_path: Path, document: dict, rows: Iterable[Sequence[str]], force: bool) -> None:
    """Serialize publication so concurrent creators cannot overwrite each other's artifacts."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = config_path.parent / ".publish.lock"
    try:
        lock = lock_path.open("x", encoding="utf-8")
    except FileExistsError:
        raise BaselineError("another baseline publication is in progress (.publish.lock exists)") from None
    try:
        with lock:
            _publish_file_baseline(config_path, document, rows, force)
    finally:
        lock_path.unlink()


def _publish_file_baseline(config_path: Path, document: dict, rows: Iterable[Sequence[str]], force: bool) -> None:
    """Write a flat YAML baseline and its CSV, restoring prior files on failure."""
    csv_path = _csv_path(config_path, document)
    _check_collisions(config_path, csv_path, force)
    targets = (config_path, csv_path)
    existing = [path for path in targets if path.exists()]

    config_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{config_path.stem}.", dir=config_path.parent))
    backup = staging / "backup"
    backup.mkdir()
    try:
        staged_csv = staging / csv_path.name
        write_canonical_csv(rows, staged_csv)
        staged_config = staging / config_path.name
        staged_config.write_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8")

        backed_up = []
        installed = []
        try:
            for path in existing:
                os.replace(path, backup / path.name)
                backed_up.append(path)
            os.replace(staged_csv, csv_path)
            installed.append(csv_path)
            os.replace(staged_config, config_path)
            installed.append(config_path)
        except BaseException:
            for path in installed:
                if path.exists():
                    path.unlink()
            for path in backed_up:
                saved = backup / path.name
                if saved.exists():
                    os.replace(saved, path)
            raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def create(name: str, description: str, find_pan_args: Sequence[str], force: bool = False,  # pylint: disable=too-many-arguments
           root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> Path:
    """Create a configuration and its CSV after a complete scan."""
    baseline_name, config_path = _baseline_config_path(name, root, baseline_root)
    _check_collisions(config_path, _csv_path(config_path, {}), force)
    if not _has_input(find_pan_args):
        raise BaselineError("give the files to scan with --path or --file")

    args = rewrite_find_pan_args(find_pan_args, root)
    manifest = inputs_manifest(args, root, baseline_root)
    if not manifest:
        raise BaselineError("no files were found in the requested inputs")
    tools = required_tools([entry["path"] for entry in manifest], root)
    absent = [tool for tool in tools if shutil.which(tool) is None]
    if absent:
        raise BaselineError(f"install {', '.join(absent)} first: expanding these inputs needs it")
    result = run_find_pan(args, root)
    skipped = [f"[{reason}] {path}" for reason, path in result.summary.get("skipped", [])
               ]
    if result.status != 0 or skipped or result.summary.get("archives_skipped"):
        raise BaselineError("find-pan did not scan everything, so nothing was recorded: "
                            + ("; ".join(skipped) or result.stderr.strip()[-1500:]
                               or f"exit status {result.status}"))

    document = {
        "name": baseline_name,
        "description": description,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "csv_file": f"{baseline_name}.csv",
        "find_pan": {"version": find_pan_version, "command": list(args)},
        "python": platform.python_version(),
        "platform": sys.platform,
        "requires_tools": tools,
        "inputs": manifest,
        "summary": {key: value for key, value in result.summary.items()
                    if key in (*_SUMMARY_FIELDS, "skipped", "exit_status")},
    }
    _write_file_baseline(config_path, document, result.rows, force)
    return config_path


# ===========================================================================
# --validate
# ===========================================================================
@dataclass
class Outcome:
    """The result of validating one baseline."""

    name: str
    verdict: str          # PASS, FAIL (...), SKIPPED (environment) or ERROR
    lines: list[str]
    status: int           # 0 ok, 1 differs, 2 error


def _error(name: str, message: str) -> Outcome:
    return Outcome(name, "ERROR", [message], 2)


def _limited(prefix: str, rows: list, max_diff: int, label: str) -> list[str]:
    lines = [f"{prefix}: {format_row(row)}" for row in rows[:max_diff]]
    lines.append(f"{len(rows)} {label} rows" + (f" ({max_diff} shown)" if len(rows) > max_diff else ""))
    return lines


def validate(name: str, strict: bool = False, max_diff: int = 50,  # pylint: disable=too-many-return-statements
             root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> Outcome:
    """Re-run find-pan exactly as recorded for baseline *name* and compare with the stored results."""
    try:
        baseline_name, config_path = _baseline_config_path(name, root, baseline_root)
        if not config_path.is_file():
            return _error(name, f"no baseline named {name!r} (expected {config_path})")
        try:
            document = _load_baseline_document(config_path)
        except yaml.YAMLError as error:
            return _error(name, f"{config_path.name} is not valid YAML: {error}")
        if document.get("name") != baseline_name:
            return _error(name, f"{config_path.name} says name {document.get('name')!r}, "
                                f"but the baseline is {baseline_name!r}")
        csv_path = _csv_path(config_path, document)
        _check_collisions(config_path, csv_path, True)
        if not csv_path.is_file():
            return _error(name, f"baseline output CSV is missing: {csv_path}")

        required = document.get("requires_tools", [])
        extractors = load_extractor_config(find_extractor_config_path()) if required else {}
        missing_tools = [tool for tool in required if not tool_available(tool, extractors)]
        if missing_tools:
            return Outcome(name, "SKIPPED (environment)",
                           [f"required extractor not installed: {', '.join(missing_tools)}"], 1 if strict else 0)

        command = list(document["find_pan"]["command"])
        current_inputs = inputs_manifest(command, root, baseline_root)
        result = run_find_pan(command, root)

        input_messages = diff_inputs(document.get("inputs", []), current_inputs)
        missing, extra = diff_rows(read_rows(csv_path), result.rows)
        summary_messages = diff_summary(document.get("summary", {}), result.summary)
    except BaselineError as error:
        return _error(name, str(error))
    except Exception as error:  # pylint: disable=broad-exception-caught
        #   Garbled files, permission errors and the like are that baseline's problem (status 2),
        #   never an uncaught traceback with status 1 ("differs") that stops --all.
        return _error(name, f"could not validate: {type(error).__name__}: {error}")

    output_differs = bool(missing or extra or summary_messages)
    if not input_messages and not output_differs:
        return Outcome(name, "PASS", [], 0)

    lines = list(input_messages)
    if missing:
        lines += _limited("missing", missing, max_diff, "missing")
    if extra:
        lines += _limited("extra", extra, max_diff, "extra")
    lines += summary_messages
    if input_messages and output_differs:
        verdict = "FAIL (inputs changed, output differs)"
    elif input_messages:
        verdict = "FAIL (inputs changed)"
    else:
        verdict = "FAIL (output differs)"
    return Outcome(name, verdict, lines, 1)


# ===========================================================================
# Command line
# ===========================================================================
def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baseline.py",
        allow_abbrev=False,
        description="Create and validate find-pan regression baselines.",
        epilog="With --create, every other argument is passed to find-pan "
               "(for example --path or --file); use -- to separate them if needed.",
    )
    parser.add_argument("--create", metavar="CONFIG", help=f"Create a YAML configuration in {BASELINE_RELATIVE_ROOT.as_posix()}/ (or supply a NAME).")
    parser.add_argument("--validate", metavar="CONFIG", nargs="?", const="",
                        help="Re-run find-pan and compare with a YAML config or NAME (or every baseline with --all).")
    parser.add_argument("--all", action="store_true", help="With --validate: check every baseline.")
    parser.add_argument("--description", default="", help="With --create: what the baseline covers.")
    parser.add_argument("--force", action="store_true", help="With --create: regenerate an existing configuration and its output.")
    parser.add_argument("--strict", action="store_true",
                        help="With --validate: treat baselines skipped for a missing extractor as failures.")
    parser.add_argument("--max-diff", type=_positive_int, default=50, metavar="N",
                        help="With --validate: maximum differing rows to print per baseline.")
    return parser


def _all_names(baseline_root: Path) -> list[str]:
    if not baseline_root.is_dir():
        return []
    names = [entry.stem for entry in baseline_root.iterdir()
             if entry.is_file() and entry.suffix.lower() in _CONFIG_SUFFIXES
             and not entry.name.startswith(".")]
    return sorted(names)


_LABELS = {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "SKIP", "ERROR": "ERROR"}


def format_outcome(outcome: Outcome, width: int) -> str:
    """One report row (status, name padded to *width*, reason) followed by its indented detail lines."""
    word, _, reason = outcome.verdict.partition(" ")
    label = _LABELS.get(word, word)
    row = f"{label:<5}  {outcome.name:<{width}}  {reason.strip('()')}".rstrip()
    if not outcome.lines:
        return row
    return "\n".join([row, *(f"    {line}" for line in outcome.lines), ""])


def format_totals(outcomes: Sequence[Outcome]) -> str:
    passed = sum(o.verdict == "PASS" for o in outcomes)
    failed = sum(o.verdict.startswith("FAIL") or (o.verdict.startswith("SKIPPED") and o.status == 1)
                 for o in outcomes)
    skipped = sum(o.verdict.startswith("SKIPPED") and o.status == 0 for o in outcomes)
    errors = sum(o.verdict == "ERROR" for o in outcomes)
    noun = "baseline" if len(outcomes) == 1 else "baselines"
    return f"{len(outcomes)} {noun}: {passed} passed, {failed} failed, {skipped} skipped, {errors} errors"


def main(argv: Sequence[str] | None = None, root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> int:
    """Run the tool; return the exit status (0 ok, 1 differences, 2 usage or environment error)."""
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--" in arguments:
        separator = arguments.index("--")
        baseline_args, forwarded = arguments[:separator], arguments[separator + 1:]
    else:
        baseline_args, forwarded = arguments, []
    try:
        args, rest = parser.parse_known_args(baseline_args)
    except SystemExit as exit_request:
        return int(exit_request.code or 0)
    rest.extend(forwarded)

    try:
        if args.create is not None and args.validate is None:
            if args.all:
                raise BaselineError("--all only applies to --validate")
            target = create(args.create, args.description, rest, args.force, root, baseline_root)
            document = _load_baseline_document(target)
            print(f"Confirmed all {len(document.get('inputs', []))} requested input file(s) were scanned successfully.")
            print(f"created baseline {args.create}: {target}")
            return 0

        if args.validate is not None and args.create is None:
            if rest:
                raise BaselineError(f"unexpected arguments with --validate: {' '.join(rest)}")
            if bool(args.validate) == args.all:
                raise BaselineError("give exactly one of a baseline NAME or --all with --validate")
            names = [args.validate] if args.validate else _all_names(baseline_root)
            if not names:
                raise BaselineError(f"no baselines found under {baseline_root}")
            print(f"Validating {len(names)} baseline{'' if len(names) == 1 else 's'}\n")
            width = max(len(name) for name in names)
            outcomes = []
            for name in names:
                outcome = validate(name, args.strict, args.max_diff, root, baseline_root)
                print(format_outcome(outcome, width))
                outcomes.append(outcome)
            print(f"\n{format_totals(outcomes)}")
            statuses = {o.status for o in outcomes}
            return 1 if 1 in statuses else (2 if 2 in statuses else 0)

        raise BaselineError("give exactly one of --create NAME or --validate [NAME | --all]")
    except (BaselineError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
