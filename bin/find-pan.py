#!/usr/bin/env -S uv run python
##  ===========================================================================
##  File    :   find-pan.py
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   Launcher for Find-PAN, which scans a file system or archive for
##              Primary Account Number (PAN) and Track Data patterns.  The
##              implementation lives in the ``find_pan`` package under ``src/``.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from find_pan.cli import main  # noqa: E402  pylint: disable=wrong-import-position

if __name__ == "__main__":
    raise SystemExit(main())
