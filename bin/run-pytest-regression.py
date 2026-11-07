#!/usr/bin/env -S uv run python
"""Run all pytest regression tests from the repository root.

Run inside the project environment managed by uv:

    uv run python bin/run-pytest-regression.py
    uv run python bin/run-pytest-regression.py --workers 4

One-time setup (bin/setup-env.ps1 on Windows, bin/setup-env.sh on
WSL/Linux/macOS) installs the project's dependencies in .venv. Set
UV_PROJECT_ENVIRONMENT=.venv for direct uv commands.
"""

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _positive_int(value: str) -> int:
    try:
        workers = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if workers < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return workers


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the pytest regression suite.")
    parser.add_argument("--workers", type=_positive_int, metavar="N",
                        help="run pytest tests concurrently using N workers (requires pytest-xdist)")
    options, pytest_arguments = parser.parse_known_args(arguments)

    try:
        import pytest  # pylint: disable=import-outside-toplevel,unused-import
    except ImportError:
        print(
            "Error: pytest is not available in this Python environment.\n"
            "Run the one-time setup for your platform:\n"
            "  Windows / PowerShell:  .\\bin\\setup-env.ps1\n"
            "  WSL / Linux / macOS:    ./bin/setup-env.sh\n"
            "then invoke via:  uv run python bin/run-pytest-regression.py",
            file=sys.stderr,
        )
        return 1

    command = [sys.executable, "-m", "pytest", "-q", "-v"]
    if options.workers is not None:
        command.extend(["-n", str(options.workers)])
    command.extend(pytest_arguments)
    completed_process = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
    return completed_process.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
