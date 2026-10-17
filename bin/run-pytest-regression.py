#!/usr/bin/env python3
"""Run all pytest regression tests from the repository root.

Run inside the project environment managed by uv:

    uv run python bin/run-pytest-regression.py

One-time setup (bin/setup-env.ps1 on Windows, bin/setup-env.sh on
WSL/Linux/macOS) configures UV_PROJECT_ENVIRONMENT per platform, so plain
`uv` commands automatically use the correct project environment.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main(arguments: list[str] | None = None) -> int:
    arguments = arguments or []

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

    command = [sys.executable, "-m", "pytest", "-q"]
    if arguments:
        command.extend(arguments)
    completed_process = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
    return completed_process.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))