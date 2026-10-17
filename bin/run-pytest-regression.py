#!/usr/bin/env python3
"""Run all pytest regression tests from the repository root."""

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main(arguments: list[str] | None = None) -> int:
    """Run pytest and return its exit code."""
    command = [sys.executable, "-m", "pytest", "-q"]
    if arguments:
        command.extend(arguments)

    completed_process = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
    return completed_process.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
