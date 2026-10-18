"""Every baseline in RegressionTests/baseline/ must validate against the current scanner.

This confirms only that they all pass; a baseline that fails shows its differences in the report.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = ROOT / "RegressionTests" / "baseline"
spec = importlib.util.spec_from_file_location("baseline", ROOT / "bin" / "baseline.py")
baseline = importlib.util.module_from_spec(spec)
sys.modules["baseline"] = baseline
spec.loader.exec_module(baseline)

NAMES = sorted(entry.name for entry in BASELINE_DIR.iterdir() if (entry / "baseline.yaml").is_file())


@pytest.mark.parametrize("name", NAMES)
def test_shipped_baseline_validates(name):
    outcome = baseline.validate(name)
    if outcome.verdict.startswith("SKIPPED"):
        pytest.skip("; ".join(outcome.lines))
    assert outcome.verdict == "PASS", "\n".join(outcome.lines)
