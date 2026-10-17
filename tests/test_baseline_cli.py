"""End-to-end tests for bin/baseline.py --create / --validate.

Each test works on a throw-away copy of the repository (bin/find-pan.py, src/, config/ and three
fixtures), so the find-pan that runs is the real one and no real baseline is touched.
"""

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("baseline", ROOT / "bin" / "baseline.py")
baseline = importlib.util.module_from_spec(spec)
sys.modules["baseline"] = baseline
spec.loader.exec_module(baseline)

FIXTURES = ("VISA.txt", "American-Express.txt", "UnionPay.txt")
PAN = "4556737586899855"


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    """A repository skeleton built once per module."""
    base = tmp_path_factory.mktemp("template")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    (base / "bin").mkdir()
    shutil.copy(ROOT / "bin" / "find-pan.py", base / "bin" / "find-pan.py")
    shutil.copytree(ROOT / "src", base / "src", ignore=ignore)
    shutil.copytree(ROOT / "config", base / "config", ignore=ignore)
    (base / "RegressionTests").mkdir()
    for name in FIXTURES:
        shutil.copy(ROOT / "RegressionTests" / name, base / "RegressionTests" / name)
    return base


@pytest.fixture
def repo(template, tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(template, root)
    return root


@pytest.fixture
def bl_root(repo):
    return repo / "RegressionTests" / "baseline"


def files_args(repo, *names):
    return ["--file", *[str(repo / "RegressionTests" / name) for name in (names or FIXTURES)]]


def create(repo, bl_root, name="plain", *args, force=False, description="test baseline"):
    return baseline.create(name, description, list(args) or files_args(repo), force=force,
                           root=repo, baseline_root=bl_root)


def validate(repo, bl_root, name, **kwargs):
    return baseline.validate(name, root=repo, baseline_root=bl_root, **kwargs)


def tree_state(path: Path) -> dict:
    return {str(p.relative_to(path)): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


# --- create ---------------------------------------------------------------------------------------------------------


def test_create_then_validate_passes(repo, bl_root):
    target = create(repo, bl_root)
    assert (target / "baseline.csv").exists() and (target / "baseline.yaml").exists()
    data = yaml.safe_load((target / "baseline.yaml").read_text(encoding="utf-8"))
    assert data["name"] == "plain" and data["description"] == "test baseline"
    assert data["find_pan"]["command"][0] == "--file"
    assert data["find_pan"]["command"][1:] == [f"RegressionTests/{n}" for n in FIXTURES]
    assert [entry["path"] for entry in data["inputs"]] == sorted(f"RegressionTests/{n}" for n in FIXTURES)
    assert data["summary"]["pans"] > 0 and data["requires_tools"] == []
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "PASS" and outcome.status == 0


def test_create_refuses_an_existing_name_without_force_and_replaces_with_force(repo, bl_root):
    create(repo, bl_root)
    with pytest.raises(baseline.BaselineError, match="exists"):
        create(repo, bl_root)
    create(repo, bl_root, force=True, description="second")
    assert yaml.safe_load((bl_root / "plain" / "baseline.yaml").read_text(encoding="utf-8"))["description"] == "second"


def test_failed_create_leaves_no_partial_directory(repo, bl_root):
    """Review Focus 4."""
    with pytest.raises(baseline.BaselineError):
        create(repo, bl_root, "broken", "--file", str(repo / "RegressionTests" / "VISA.txt"), "--no-such-switch")
    assert not (bl_root / "broken").exists()
    assert not bl_root.exists() or list(bl_root.iterdir()) == []      # no staging leftovers
    create(repo, bl_root, "keep")
    before = tree_state(bl_root / "keep")
    with pytest.raises(baseline.BaselineError):
        create(repo, bl_root, "keep", "--file", str(repo / "RegressionTests" / "VISA.txt"), "--no-such-switch", force=True)
    assert tree_state(bl_root / "keep") == before
    assert [p.name for p in bl_root.iterdir()] == ["keep"]


def test_create_rejects_owned_switches_and_outside_paths(repo, bl_root, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text(f"card {PAN}\n", encoding="utf-8")
    with pytest.raises(baseline.BaselineError, match="cannot be passed"):
        create(repo, bl_root, "x", *files_args(repo), "--csv", "mine.csv")
    with pytest.raises(baseline.BaselineError, match="outside"):
        create(repo, bl_root, "x", "--file", str(outside))
    assert not (bl_root / "x").exists()


def test_create_requires_an_input(repo, bl_root):
    with pytest.raises(baseline.BaselineError, match="--path or --file"):
        create(repo, bl_root, "x", "--mask")


def test_create_with_zero_findings(repo, bl_root):
    """Review Focus 2."""
    empty = repo / "RegressionTests" / "clean.txt"
    empty.write_text("nothing to see\n", encoding="utf-8")
    create(repo, bl_root, "clean", "--file", str(empty))
    assert (bl_root / "clean" / "baseline.csv").read_text(encoding="utf-8").splitlines() == [
        "filename,line_number,offset,pattern_name,data_type,matched_data"]
    assert validate(repo, bl_root, "clean").verdict == "PASS"


# --- validate: differences ----------------------------------------------------------------------------------------------------


def test_validate_detects_an_edited_input_and_names_the_lost_row(repo, bl_root):
    create(repo, bl_root)
    visa = repo / "RegressionTests" / "VISA.txt"
    lines = visa.read_text(encoding="utf-8").splitlines()
    visa.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")        # drop the first line
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "FAIL (inputs changed, output differs)" and outcome.status == 1
    text = "\n".join(outcome.lines)
    assert "input changed: RegressionTests/VISA.txt" in text
    assert any(line.startswith("missing:") and "VISA.txt:" in line for line in outcome.lines)


def test_validate_detects_a_corrupted_baseline_row(repo, bl_root):
    create(repo, bl_root)
    csv_path = bl_root / "plain" / "baseline.csv"
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1][:-1] + ("0" if lines[1][-1] != "0" else "1")      # alter the matched data
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "FAIL (output differs)"
    assert sum(line.startswith("missing:") for line in outcome.lines) == 1
    assert sum(line.startswith("extra:") for line in outcome.lines) == 1


def test_validate_detects_a_changed_summary_count(repo, bl_root):
    create(repo, bl_root)
    yaml_path = bl_root / "plain" / "baseline.yaml"
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    data["summary"]["pans"] += 1
    yaml_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "FAIL (output differs)"
    assert any(line.startswith("pans: baseline") for line in outcome.lines)


def test_crlf_only_change_to_an_input_passes(repo, bl_root):
    create(repo, bl_root)
    visa = repo / "RegressionTests" / "VISA.txt"
    visa.write_bytes(visa.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert validate(repo, bl_root, "plain").verdict == "PASS"


def test_validate_reports_added_and_removed_input_files(repo, bl_root):
    data = repo / "RegressionTests" / "set"
    data.mkdir()
    for name in ("VISA.txt", "UnionPay.txt"):
        shutil.copy(repo / "RegressionTests" / name, data / name)
    create(repo, bl_root, "dir", "--path", str(data))
    (data / "UnionPay.txt").unlink()
    (data / "extra.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    outcome = validate(repo, bl_root, "dir")
    text = "\n".join(outcome.lines)
    assert "input removed: RegressionTests/set/UnionPay.txt" in text
    assert "input added: RegressionTests/set/extra.txt" in text
    assert outcome.status == 1


def test_max_diff_limits_printed_rows_but_prints_the_count(repo, bl_root):
    create(repo, bl_root)
    csv_path = bl_root / "plain" / "baseline.csv"
    header, *rows = csv_path.read_text(encoding="utf-8").splitlines()
    csv_path.write_text("\n".join([header] + rows[:3]) + "\n", encoding="utf-8")
    outcome = validate(repo, bl_root, "plain", max_diff=2)
    assert sum(line.startswith("extra:") for line in outcome.lines) == 2
    assert any("extra rows" in line and str(len(rows) - 3) in line for line in outcome.lines)


def test_validate_does_not_modify_the_baseline(repo, bl_root):
    create(repo, bl_root)
    before = tree_state(bl_root)
    validate(repo, bl_root, "plain")
    assert tree_state(bl_root) == before


# --- validate: environment and errors ----------------------------------------------------------------------------------------------


def test_missing_tool_is_skipped_and_fails_with_strict(repo, bl_root):
    create(repo, bl_root)
    yaml_path = bl_root / "plain" / "baseline.yaml"
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    data["requires_tools"] = ["definitely-not-installed-tool"]
    yaml_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    soft = validate(repo, bl_root, "plain")
    assert soft.verdict == "SKIPPED (environment)" and soft.status == 0
    assert "definitely-not-installed-tool" in "\n".join(soft.lines)
    assert validate(repo, bl_root, "plain", strict=True).status == 1


def test_unknown_baseline_is_an_error(repo, bl_root):
    outcome = validate(repo, bl_root, "nope")
    assert outcome.verdict == "ERROR" and outcome.status == 2


def test_yaml_name_must_match_directory_and_bad_names_are_rejected(repo, bl_root):
    """Review Focus 1."""
    create(repo, bl_root)
    yaml_path = bl_root / "plain" / "baseline.yaml"
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    data["name"] = "other"
    yaml_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert validate(repo, bl_root, "plain").status == 2
    for bad in ("..", "a/b", "a" + chr(92) + "b", "/abs"):
        with pytest.raises(baseline.BaselineError):
            create(repo, bl_root, bad)
        assert validate(repo, bl_root, bad).status == 2


def test_a_missing_recorded_input_is_an_error(repo, bl_root):
    create(repo, bl_root)
    (repo / "RegressionTests" / "VISA.txt").unlink()
    outcome = validate(repo, bl_root, "plain")
    assert outcome.status == 2 and "VISA.txt" in "\n".join(outcome.lines)


# --- main: validate --all and exit codes -------------------------------------------------------------------------------------------


def run_main(repo, bl_root, *argv):
    return baseline.main(list(argv), root=repo, baseline_root=bl_root)


def test_validate_all_mixes_pass_and_fail_and_returns_1(repo, bl_root, capsys):
    create(repo, bl_root, "good")
    create(repo, bl_root, "bad")
    csv_path = bl_root / "bad" / "baseline.csv"
    csv_path.write_text("\n".join(csv_path.read_text(encoding="utf-8").splitlines()[:-1]) + "\n", encoding="utf-8")
    assert run_main(repo, bl_root, "--validate", "--all") == 1
    out = capsys.readouterr().out
    assert "bad: FAIL" in out and "good: PASS" in out and "1 passed, 1 failed" in out


def test_validate_all_continues_after_a_broken_baseline(repo, bl_root, capsys):
    """Review Focus 5."""
    create(repo, bl_root, "good")
    create(repo, bl_root, "broken")
    (bl_root / "broken" / "baseline.yaml").write_text("name: [unclosed", encoding="utf-8")
    assert run_main(repo, bl_root, "--validate", "--all") == 2             # broken + pass
    assert "good: PASS" in capsys.readouterr().out
    create(repo, bl_root, "fails")
    csv_path = bl_root / "fails" / "baseline.csv"
    csv_path.write_text("\n".join(csv_path.read_text(encoding="utf-8").splitlines()[:-1]) + "\n", encoding="utf-8")
    assert run_main(repo, bl_root, "--validate", "--all") == 1             # broken + fail


def test_validate_all_with_no_baselines_is_an_error(repo, bl_root, capsys):
    """Review Focus 5."""
    assert run_main(repo, bl_root, "--validate", "--all") == 2
    assert "no baselines" in capsys.readouterr().err


def test_main_exit_codes_and_argument_rules(repo, bl_root, capsys):
    files = files_args(repo)
    assert run_main(repo, bl_root, "--create", "plain", "--description", "d", *files) == 0
    assert run_main(repo, bl_root, "--validate", "plain") == 0
    assert run_main(repo, bl_root, "--validate", "unknown") == 2
    assert run_main(repo, bl_root, "--create", "plain", *files) == 2                       # exists
    assert run_main(repo, bl_root, "--create", "plain", "--force", *files) == 0
    assert run_main(repo, bl_root, "--validate") == 2                                       # neither NAME nor --all
    assert run_main(repo, bl_root, "--validate", "plain", "--all") == 2                     # both
    assert run_main(repo, bl_root) == 2                                                     # neither action
    capsys.readouterr()


def test_main_passes_unknown_switches_to_find_pan_and_accepts_double_dash(repo, bl_root):
    assert run_main(repo, bl_root, "--create", "masked", "--description", "d", "--",
                    *files_args(repo, "VISA.txt"), "--mask") == 0
    csv_text = (bl_root / "masked" / "baseline.csv").read_text(encoding="utf-8")
    assert PAN not in csv_text and "*" in csv_text
    data = yaml.safe_load((bl_root / "masked" / "baseline.yaml").read_text(encoding="utf-8"))
    assert "--mask" in data["find_pan"]["command"]
