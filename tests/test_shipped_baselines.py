"""The baselines shipped in RegressionTests/baseline/ must validate against the current scanner.

Every fixture in RegressionTests/ (each text file and each compressed file) has its own baseline,
plus three group baselines.  Adding a fixture without a baseline, or changing a fixture or the
scanner's output for it, fails here.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "RegressionTests"
BASELINE_DIR = FIXTURE_DIR / "baseline"
spec = importlib.util.spec_from_file_location("baseline", ROOT / "bin" / "baseline.py")
baseline = importlib.util.module_from_spec(spec)
sys.modules["baseline"] = baseline
spec.loader.exec_module(baseline)

GROUPS = ["plain-text", "masked", "archives"]
COMPRESSED_SUFFIXES = {".zip", ".tar", ".7z", ".gz", ".tgz", ".bz2", ".xz"}


def fixture_files() -> list[Path]:
    """Every file directly inside RegressionTests/ (the baseline directory is not a fixture)."""
    return sorted((p for p in FIXTURE_DIR.iterdir() if p.is_file()), key=lambda p: p.name.encode("utf-8"))


def baseline_name(fixture: Path) -> str:
    """`archive-<stem>` for compressed files, `file-<stem>` for everything else."""
    return ("archive-" if fixture.suffix.lower() in COMPRESSED_SUFFIXES else "file-") + fixture.stem


FIXTURES = fixture_files()
PER_FILE = {baseline_name(fixture): fixture for fixture in FIXTURES}
EXPECTED = sorted(GROUPS + list(PER_FILE))


def test_fixture_names_map_to_unique_baseline_names():
    assert len(PER_FILE) == len(FIXTURES)


def test_every_fixture_is_covered_and_no_unexpected_baselines_exist():
    present = sorted(entry.name for entry in BASELINE_DIR.iterdir() if (entry / "baseline.yaml").is_file())
    assert present == EXPECTED


@pytest.mark.parametrize("name", sorted(PER_FILE))
def test_each_per_file_baseline_describes_exactly_its_fixture(name):
    fixture = PER_FILE[name]
    document = yaml.safe_load((BASELINE_DIR / name / "baseline.yaml").read_text(encoding="utf-8"))
    assert document["find_pan"]["command"] == ["--file", f"RegressionTests/{fixture.name}"]
    assert [entry["path"] for entry in document["inputs"]] == [f"RegressionTests/{fixture.name}"]


@pytest.mark.parametrize("name", EXPECTED)
def test_shipped_baseline_validates(name):
    """A fixture or scanner change shows up here as missing/extra rows or `inputs changed`."""
    outcome = baseline.validate(name)
    if outcome.verdict.startswith("SKIPPED"):
        pytest.skip("; ".join(outcome.lines))
    assert outcome.verdict == "PASS", "\n".join(outcome.lines)


@pytest.mark.parametrize("name", EXPECTED)
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


def test_a_changed_fixture_is_detected(tmp_path):
    """The guarantee itself: editing a fixture makes validation fail and names the lost row."""
    import shutil

    fixture = PER_FILE["file-VISA"]
    root = tmp_path / "repo"
    (root / "RegressionTests").mkdir(parents=True)
    for part in ("bin", "src", "config"):
        shutil.copytree(ROOT / part, root / part, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(BASELINE_DIR / "file-VISA", root / "RegressionTests" / "baseline" / "file-VISA")
    edited = root / "RegressionTests" / fixture.name
    lines = fixture.read_text(encoding="utf-8").splitlines()
    edited.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")        # drop the first line
    outcome = baseline.validate("file-VISA", root=root, baseline_root=root / "RegressionTests" / "baseline")
    assert outcome.verdict == "FAIL (inputs changed, output differs)"
    assert any(line.startswith("missing:") and "VISA.txt:" in line for line in outcome.lines)
