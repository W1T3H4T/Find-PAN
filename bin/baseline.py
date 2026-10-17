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

from find_pan.config import find_extractor_config_path, load_extractor_config  # noqa: E402
from find_pan.filetypes import FileKind, classify_head  # noqa: E402
from find_pan.version import __version__ as find_pan_version  # noqa: E402

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
        relative = to_repo_relative(directory, root, base=root)
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
            command = extractors.get(classification.archive_type, {}).get("command")
            if command:
                tools.add(Path(command).stem)
    return sorted(tools)


# ===========================================================================
# --create
# ===========================================================================
def _has_input(args: Sequence[str]) -> bool:
    directories, files = _path_values(args)
    return bool(directories or files)


def create(name: str, description: str, find_pan_args: Sequence[str], force: bool = False,
           root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> Path:
    """Run find-pan with *find_pan_args* and archive the result as baseline *name*.

    The baseline is built in a hidden staging directory and moved into place only when everything
    succeeded, so a failure never leaves a partial baseline (and, with *force*, never damages the
    existing one).
    """
    validate_name(name)
    target = baseline_root / name
    if target.exists() and not force:
        raise BaselineError(f"baseline {name!r} already exists ({target}); use --force to replace it")
    if not _has_input(find_pan_args):
        raise BaselineError("give the files to scan with --path or --file")

    args = rewrite_find_pan_args(find_pan_args, root)
    manifest = inputs_manifest(args, root)
    result = run_find_pan(args, root)

    baseline_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{name}.", dir=baseline_root))
    retired = None
    try:
        write_canonical_csv(result.rows, staging / "baseline.csv")
        document = {
            "name": name,
            "description": description,
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "find_pan": {"version": find_pan_version, "command": list(args)},
            "python": platform.python_version(),
            "platform": sys.platform,
            "requires_tools": required_tools([entry["path"] for entry in manifest], root),
            "inputs": manifest,
            "summary": {key: value for key, value in result.summary.items()
                        if key in (*_SUMMARY_FIELDS, "skipped", "exit_status")},
        }
        with open(staging / "baseline.yaml", "w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=True)
        if target.exists():
            retired = Path(tempfile.mkdtemp(prefix=f".{name}.old.", dir=baseline_root))
            os.replace(target, retired / "old")
        try:
            os.replace(staging, target)
        except OSError:
            if retired is not None:
                os.replace(retired / "old", target)       # put the old baseline back
                retired = None
            raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        if retired is not None:
            shutil.rmtree(retired, ignore_errors=True)
    return target


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


def validate(name: str, strict: bool = False, max_diff: int = 50,
             root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> Outcome:
    """Re-run find-pan exactly as recorded for baseline *name* and compare with the stored results."""
    try:
        validate_name(name)
        directory = baseline_root / name
        yaml_path, csv_path = directory / "baseline.yaml", directory / "baseline.csv"
        if not yaml_path.is_file() or not csv_path.is_file():
            return _error(name, f"no baseline named {name!r} (expected {yaml_path} and {csv_path.name})")
        try:
            document = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            return _error(name, f"{yaml_path.name} is not valid YAML: {error}")
        if not isinstance(document, dict) or document.get("name") != name:
            return _error(name, f"{yaml_path.name} says name {document.get('name') if isinstance(document, dict) else None!r}, "
                                f"but the directory is {name!r}")

        missing_tools = [tool for tool in document.get("requires_tools", []) if shutil.which(tool) is None]
        if missing_tools:
            return Outcome(name, "SKIPPED (environment)",
                           [f"required extractor not installed: {', '.join(missing_tools)}"], 1 if strict else 0)

        command = list(document["find_pan"]["command"])
        current_inputs = inputs_manifest(command, root)
        result = run_find_pan(command, root)

        input_messages = diff_inputs(document.get("inputs", []), current_inputs)
        missing, extra = diff_rows(read_rows(csv_path), result.rows)
        summary_messages = diff_summary(document.get("summary", {}), result.summary)
    except BaselineError as error:
        return _error(name, str(error))
    except (KeyError, TypeError) as error:
        return _error(name, f"baseline.yaml is incomplete or malformed ({error!r})")

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
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baseline.py",
        allow_abbrev=False,
        description="Create and validate find-pan regression baselines.",
        epilog="With --create, every other argument is passed to find-pan "
               "(for example --path or --file); use -- to separate them if needed.",
    )
    parser.add_argument("--create", metavar="NAME", help="Run find-pan and archive the result as baseline NAME.")
    parser.add_argument("--validate", metavar="NAME", nargs="?", const="",
                        help="Re-run find-pan and compare with baseline NAME (or every baseline with --all).")
    parser.add_argument("--all", action="store_true", help="With --validate: check every baseline.")
    parser.add_argument("--description", default="", help="With --create: what the baseline covers.")
    parser.add_argument("--force", action="store_true", help="With --create: replace an existing baseline.")
    parser.add_argument("--strict", action="store_true",
                        help="With --validate: treat baselines skipped for a missing extractor as failures.")
    parser.add_argument("--max-diff", type=int, default=50, metavar="N",
                        help="With --validate: most differing rows to print per baseline.")
    return parser


def _all_names(baseline_root: Path) -> list[str]:
    if not baseline_root.is_dir():
        return []
    return sorted(entry.name for entry in baseline_root.iterdir()
                  if entry.is_dir() and not entry.name.startswith(".") and (entry / "baseline.yaml").is_file())


def _print_outcome(outcome: Outcome) -> None:
    print(f"{outcome.name}: {outcome.verdict}")
    for line in outcome.lines:
        print(f"    {line}")


def main(argv: Sequence[str] | None = None, root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> int:
    """Run the tool; return the exit status (0 ok, 1 differences, 2 usage or environment error)."""
    parser = build_parser()
    try:
        args, rest = parser.parse_known_args(argv)
    except SystemExit as exit_request:
        return int(exit_request.code or 0)
    rest = [item for item in rest if item != "--"]

    try:
        if args.create is not None and args.validate is None:
            if args.all:
                raise BaselineError("--all only applies to --validate")
            target = create(args.create, args.description, rest, args.force, root, baseline_root)
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
            outcomes = []
            for name in names:
                outcome = validate(name, args.strict, args.max_diff, root, baseline_root)
                _print_outcome(outcome)
                outcomes.append(outcome)
            passed = sum(o.verdict == "PASS" for o in outcomes)
            failed = sum(o.verdict.startswith("FAIL") or (o.verdict.startswith("SKIPPED") and o.status == 1)
                         for o in outcomes)
            skipped = sum(o.verdict.startswith("SKIPPED") and o.status == 0 for o in outcomes)
            errors = sum(o.verdict == "ERROR" for o in outcomes)
            print(f"{passed} passed, {failed} failed, {skipped} skipped, {errors} errors")
            statuses = {o.status for o in outcomes}
            return 1 if 1 in statuses else (2 if 2 in statuses else 0)

        raise BaselineError("give exactly one of --create NAME or --validate [NAME | --all]")
    except BaselineError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
