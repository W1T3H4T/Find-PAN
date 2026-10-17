#!/usr/bin/env -S uv run python
##  ===========================================================================
##  File    :   update_version.py
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   Manage the Find-PAN project version in pyproject.toml and src/find_pan/version.py.
##              Supports bumping major/minor/patch, setting an explicit
##              version, or printing the current version.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================

import argparse
import re
import sys
from pathlib import Path


VERSION_PATTERN = re.compile(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', re.MULTILINE)


def read_pyproject_version(pyproject_path: Path) -> tuple[int, int, int]:
    """Return the current version as (major, minor, patch)."""
    text = pyproject_path.read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(text)
    if not match:
        raise ValueError(f"No valid version line found in {pyproject_path}")
    return tuple(int(part) for part in match.groups())


def write_pyproject_version(
    pyproject_path: Path, version: tuple[int, int, int]
) -> None:
    """Persist the version in pyproject.toml."""
    text = pyproject_path.read_text(encoding="utf-8")
    new_version_line = f'version = "{version[0]}.{version[1]}.{version[2]}"'
    new_text, count = VERSION_PATTERN.subn(new_version_line, text, count=1)
    if count == 0:
        raise ValueError(f"Could not find version line to update in {pyproject_path}")
    pyproject_path.write_text(new_text, encoding="utf-8")


MODULE_VERSION_PATTERN = re.compile(r'^__version__\s*=\s*"\d+\.\d+\.\d+"', re.MULTILINE)


def write_version_module(version_path: Path, version: tuple[int, int, int]) -> None:
    """Persist the version in the package's version module."""
    text = version_path.read_text(encoding="utf-8")
    new_line = f'__version__ = "{version[0]}.{version[1]}.{version[2]}"'
    new_text, count = MODULE_VERSION_PATTERN.subn(new_line, text, count=1)
    if count == 0:
        raise ValueError(f"Could not find __version__ line to update in {version_path}")
    version_path.write_text(new_text, encoding="utf-8")


def parse_set_version(value: str) -> tuple[int, int, int]:
    """Parse a MAJOR.MINOR.PATCH string into a version tuple."""
    parts = value.split(".")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"version must be in MAJOR.MINOR.PATCH format, got: {value!r}"
        )
    try:
        return tuple(int(part) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"version components must be integers, got: {value!r}"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the Find-PAN version in pyproject.toml."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--major", action="store_true", help="Increment the major version."
    )
    group.add_argument(
        "--minor", action="store_true", help="Increment the minor version."
    )
    group.add_argument(
        "--patch", action="store_true", help="Increment the patch version."
    )
    group.add_argument(
        "--show", action="store_true", help="Display the current version."
    )
    group.add_argument(
        "--version",
        metavar="VERSION",
        type=parse_set_version,
        help="Set the version to MAJOR.MINOR.PATCH.",
    )
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "pyproject.toml",
        help="Path to pyproject.toml (default: repository root).",
    )
    parser.add_argument(
        "--version-file",
        type=Path,
        default=None,
        help="Path to the package version module "
        "(default: src/find_pan/version.py next to pyproject.toml, updated only if it exists).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    current = read_pyproject_version(args.pyproject)

    if args.show:
        print(f"{current[0]}.{current[1]}.{current[2]}")
        return 0

    if args.version is not None:
        new_version = args.version
    elif args.major:
        new_version = (current[0] + 1, 0, 0)
    elif args.minor:
        new_version = (current[0], current[1] + 1, 0)
    elif args.patch:
        new_version = (current[0], current[1], current[2] + 1)
    else:
        #   Should not happen because the mutually exclusive group is required.
        parser.error("No version action specified")

    write_pyproject_version(args.pyproject, new_version)
    version_file = args.version_file or args.pyproject.parent / "src" / "find_pan" / "version.py"
    if args.version_file is not None or version_file.exists():
        write_version_module(version_file, new_version)
    print(f"Updated version: {current[0]}.{current[1]}.{current[2]} -> {new_version[0]}.{new_version[1]}.{new_version[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
