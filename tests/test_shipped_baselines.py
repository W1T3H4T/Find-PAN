"""The baselines shipped in RegressionTests/baseline/ must validate against the current scanner."""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = ROOT / "RegressionTests" / "baseline"
spec = importlib.util.spec_from_file_location("baseline", ROOT / "bin" / "baseline.py")
baseline = importlib.util.module_from_spec(spec)
sys.modules["baseline"] = baseline
spec.loader.exec_module(baseline)

SHIPPED = ["plain-text", "archives", "masked"]


def test_the_expected_baselines_are_shipped():
    present = sorted(entry.name for entry in BASELINE_DIR.iterdir() if (entry / "baseline.yaml").is_file())
    assert present == sorted(SHIPPED)


@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_baseline_validates(name):
    outcome = baseline.validate(name)
    if outcome.verdict.startswith("SKIPPED"):
        pytest.skip("; ".join(outcome.lines))
    assert outcome.verdict == "PASS", "\n".join(outcome.lines)


@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_baseline_files_are_well_formed(name):
    directory = BASELINE_DIR / name
    document = yaml.safe_load((directory / "baseline.yaml").read_text(encoding="utf-8"))
    assert document["name"] == name and document["description"]
    assert document["find_pan"]["command"] and document["inputs"]
    for entry in document["inputs"]:
        assert "\\" not in entry["path"] and not entry["path"].startswith("/")
    assert [e["path"] for e in document["inputs"]] == sorted(e["path"] for e in document["inputs"])
    for filename in ("baseline.yaml", "baseline.csv"):
        assert b"\r" not in (directory / filename).read_bytes()


def test_the_masked_baseline_contains_no_raw_card_numbers():
    rows = baseline.read_rows(BASELINE_DIR / "masked" / "baseline.csv")
    assert rows and all("*" in row[5] for row in rows)
