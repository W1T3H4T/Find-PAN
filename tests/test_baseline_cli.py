"""End-to-end tests for bin/baseline.py --create / --validate.

Each test works on a throw-away copy of the repository (bin/find-pan.py, src/, config/ and three
fixtures), so the find-pan that runs is the real one and no real baseline is touched.
"""

import importlib.util
import io
import shutil
import sys
import threading
from pathlib import Path

import pytest
import yaml
from find_pan import config

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
    return repo / baseline.BASELINE_RELATIVE_ROOT


def files_args(repo, *names):
    return ["--file", *[str(repo / "RegressionTests" / name) for name in (names or FIXTURES)]]


def create(repo, bl_root, name="plain", *args, force=False, description="test baseline"):  # pylint: disable=keyword-arg-before-vararg
    return baseline.create(name, description, list(args) or files_args(repo), force=force,
                           root=repo, baseline_root=bl_root)


def validate(repo, bl_root, name, **kwargs):
    return baseline.validate(name, root=repo, baseline_root=bl_root, **kwargs)


def tree_state(path: Path) -> dict:
    return {str(p.relative_to(path)): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


# --- create ---------------------------------------------------------------------------------------------------------


def test_create_then_validate_passes(repo, bl_root):
    target = create(repo, bl_root)
    assert target == bl_root / "plain.yaml"
    assert (bl_root / "output" / "plain.csv").exists() and target.exists()
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert data["name"] == "plain" and data["description"] == "test baseline"
    assert data["find_pan"]["command"][0] == "--file"
    assert data["find_pan"]["command"] == files_args(repo)
    assert "inputs" not in data and "summary" not in data
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "PASS" and outcome.status == 0


def test_relative_arguments_replay_from_original_working_directory(repo, bl_root, monkeypatch):
    monkeypatch.chdir(repo / "RegressionTests")
    target = create(repo, bl_root, "relative", "--file", "VISA.txt")
    document = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert document["find_pan"]["command"] == ["--file", "VISA.txt"]
    assert document["find_pan"]["working_directory"] == {"relative_to_repo": "RegressionTests"}
    monkeypatch.chdir(repo)
    assert validate(repo, bl_root, "relative").verdict == "PASS"


def test_relative_arguments_outside_repo_replay_from_original_working_directory(repo, bl_root, tmp_path, monkeypatch):
    (tmp_path / "outside.txt").write_text(f"{PAN}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    target = create(repo, bl_root, "outside", "--file", "outside.txt")
    document = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert document["find_pan"]["working_directory"] == {"absolute": str(tmp_path.resolve())}
    monkeypatch.chdir(repo)
    assert validate(repo, bl_root, "outside").verdict == "PASS"


def test_validation_scans_to_separate_temporary_csv(repo, bl_root, monkeypatch):
    create(repo, bl_root)
    saved_csv = bl_root / "output" / "plain.csv"
    original = saved_csv.read_bytes()
    real_run = baseline.subprocess.run
    csv_paths = []

    def capture_run(command, **kwargs):
        csv_paths.append(Path(command[command.index("--csv") + 1]))
        return real_run(command, **kwargs)

    monkeypatch.setattr(baseline.subprocess, "run", capture_run)
    assert validate(repo, bl_root, "plain").verdict == "PASS"
    assert len(csv_paths) == 1 and csv_paths[0] != saved_csv
    assert not csv_paths[0].exists()
    assert saved_csv.read_bytes() == original


def test_exclude_dir_is_passed_through_to_find_pan(repo, bl_root):
    directory = repo / "RegressionTests" / "nested"
    (directory / "cache-data").mkdir(parents=True)
    (directory / "cache-data" / "ignored.txt").write_text(f"{PAN}\n", encoding="utf-8")
    (directory / "included.txt").write_text(f"{PAN}\n", encoding="utf-8")
    target = create(repo, bl_root, "excluded", "--path", str(directory), "--exclude-dir", "cache-*")
    document = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert document["find_pan"]["command"] == ["--path", str(directory), "--exclude-dir", "cache-*"]
    (directory / "cache-data" / "ignored.txt").write_text("changed\n", encoding="utf-8")
    assert validate(repo, bl_root, "excluded").verdict == "PASS"


def test_scan_regression_root_excludes_baseline_artifacts(repo, bl_root):
    assert run_main(repo, bl_root, "--create", "regression", "--path", str(repo / "RegressionTests"),
                    "--exclude-dir", "baseline") == 0
    document = yaml.safe_load((bl_root / "regression.yaml").read_text(encoding="utf-8"))
    assert document["find_pan"]["command"] == ["--path", str(repo / "RegressionTests"), "--exclude-dir", "baseline"]
    assert validate(repo, bl_root, "regression").verdict == "PASS"


def test_main_consumes_baseline_options_and_forwards_scanner_options(repo, bl_root):
    target = repo / "RegressionTests" / "VISA.txt"
    assert run_main(repo, bl_root, "--create", "forwarded", "--file", str(target),
                    "--description", "example", "--debug", "--exclude-dir", "cache*") == 0
    document = yaml.safe_load((bl_root / "forwarded.yaml").read_text(encoding="utf-8"))
    assert document["description"] == "example"
    assert document["find_pan"]["command"] == ["--file", str(target),
                                                "--debug", "--exclude-dir", "cache*"]
    assert validate(repo, bl_root, "forwarded").verdict == "PASS"


def test_separator_preserves_remaining_arguments(repo, bl_root, monkeypatch):
    received = {}
    target = bl_root / "captured.yaml"
    monkeypatch.setattr(baseline, "create", lambda name, description, args, force, root, baseline_root:
                        received.update(name=name, description=description, args=args, force=force) or target)
    monkeypatch.setattr(baseline, "_load_baseline_document", lambda path: {})
    assert run_main(repo, bl_root, "--create", "captured", "--force", "--", "--description", "scanner",
                    "--", "literal") == 0
    assert received == {"name": "captured", "description": "", "args": ["--description", "scanner", "--", "literal"],
                        "force": True}


def test_create_and_validate_yaml_config_file(repo, bl_root):
    config_path = bl_root / "flat.yaml"

    assert run_main(repo, bl_root, "--create", str(config_path), "--description", "flat baseline",
                    "--", *files_args(repo)) == 0
    csv_path = bl_root / "output" / "flat.csv"
    assert config_path.is_file() and csv_path.is_file()
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert document["name"] == "flat" and document["description"] == "flat baseline"
    assert document["csv_file"] == csv_path.name
    assert validate(repo, bl_root, str(config_path)).verdict == "PASS"
    assert validate(repo, bl_root, config_path.name).verdict == "PASS"


def test_create_rejects_json_baseline_configuration(repo, bl_root, capsys):
    config_path = bl_root / "flat.json"
    assert run_main(repo, bl_root, "--create", str(config_path), "--", *files_args(repo)) == 2
    assert not config_path.exists()
    assert "must use YAML" in capsys.readouterr().err


def test_validate_all_discovers_yaml_files_and_named_baselines(repo, bl_root):
    create(repo, bl_root, str(bl_root / "flat.yaml"))
    create(repo, bl_root, "legacy")

    assert run_main(repo, bl_root, "--validate", "--all") == 0


def test_create_refuses_an_existing_name_without_force_and_replaces_with_force(repo, bl_root):
    create(repo, bl_root)
    with pytest.raises(baseline.BaselineError, match="exists"):
        create(repo, bl_root)
    create(repo, bl_root, force=True, description="second")
    assert yaml.safe_load((bl_root / "plain.yaml").read_text(encoding="utf-8"))["description"] == "second"


@pytest.mark.parametrize("alias", ["plain.yml", "PLAIN.yaml"])
@pytest.mark.parametrize("force", [False, True])
def test_create_rejects_configuration_aliases_even_with_force(repo, bl_root, alias, force):
    create(repo, bl_root)
    before = tree_state(bl_root)
    with pytest.raises(baseline.BaselineError, match="collision"):
        create(repo, bl_root, alias, force=force)
    assert tree_state(bl_root) == before


@pytest.mark.parametrize("force", [False, True])
def test_create_rejects_orphan_output_even_with_force(repo, bl_root, force):
    output = bl_root / "output"
    output.mkdir(parents=True)
    (output / "plain.csv").write_text("must not overwrite", encoding="utf-8")
    before = tree_state(bl_root)
    with pytest.raises(baseline.BaselineError, match="collision"):
        create(repo, bl_root, force=force)
    assert tree_state(bl_root) == before


def test_create_and_validate_reject_shared_output_ownership(repo, bl_root):
    create(repo, bl_root)
    (bl_root / "other.yaml").write_text("name: other\ncsv_file: plain.csv\n", encoding="utf-8")
    before = tree_state(bl_root)
    with pytest.raises(baseline.BaselineError, match="collision"):
        create(repo, bl_root, force=True)
    assert validate(repo, bl_root, "plain").status == 2
    assert tree_state(bl_root) == before


def test_validate_rejects_output_path_overrides(repo, bl_root):
    create(repo, bl_root)
    config_path = bl_root / "plain.yaml"
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    document["csv_file"] = "../elsewhere.csv"
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert validate(repo, bl_root, "plain").status == 2


@pytest.mark.parametrize("identifier", ["output/nested.yaml", "nested/config.yaml", "../outside.yaml"])
def test_create_rejects_configuration_paths_outside_flat_directory(repo, bl_root, identifier):
    with pytest.raises(baseline.BaselineError, match="directly inside"):
        create(repo, bl_root, identifier)


def test_named_baseline_resolves_existing_yml_file(repo, bl_root):
    create(repo, bl_root, "short.yml")
    assert validate(repo, bl_root, "short").verdict == "PASS"
    assert create(repo, bl_root, "short", force=True) == bl_root / "short.yml"


def test_validate_accepts_case_differences_in_name_and_csv(repo, bl_root):
    config_path = create(repo, bl_root, "example-multi")
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    document["name"] = "Example-Multi"
    document["csv_file"] = "Example-Multi.csv"
    config_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    original = bl_root / "output" / "example-multi.csv"
    temporary = original.with_name("temporary.csv")
    original.rename(temporary)
    temporary.rename(original.with_name(document["csv_file"]))
    before = tree_state(bl_root)
    for identifier in ("Example-Multi", "example-multi", "EXAMPLE-MULTI.yaml"):
        outcome = validate(repo, bl_root, identifier)
        assert outcome.verdict == "PASS", outcome.lines
    assert tree_state(bl_root) == before


def test_validate_rejects_multiple_case_insensitive_configurations(repo, bl_root):
    config_path = create(repo, bl_root, "example")
    (bl_root / "EXAMPLE.yml").write_bytes(config_path.read_bytes())
    before = tree_state(bl_root)
    outcome = validate(repo, bl_root, "example")
    assert outcome.status == 2 and "collision" in outcome.lines[0]
    assert tree_state(bl_root) == before


def test_publication_lock_prevents_overwrite(repo, bl_root):
    create(repo, bl_root)
    lock = bl_root / ".publish.lock"
    lock.write_text("busy", encoding="utf-8")
    before = tree_state(bl_root)
    with pytest.raises(baseline.BaselineError, match="publication"):
        baseline._write_file_baseline(bl_root / "plain.yaml", {"csv_file": "plain.csv"}, [], True)
    assert tree_state(bl_root) == before


def test_failed_create_leaves_no_partial_directory(repo, bl_root):
    """Review Focus 4."""
    with pytest.raises(baseline.BaselineError):
        create(repo, bl_root, "broken", "--file", str(repo / "RegressionTests" / "VISA.txt"), "--no-such-switch")
    assert not (bl_root / "broken.yaml").exists()
    assert not bl_root.exists() or list(bl_root.iterdir()) == []      # no staging leftovers
    create(repo, bl_root, "keep")
    before = tree_state(bl_root)
    with pytest.raises(baseline.BaselineError):
        create(repo, bl_root, "keep", "--file", str(repo / "RegressionTests" / "VISA.txt"), "--no-such-switch", force=True)
    assert tree_state(bl_root) == before
    assert sorted(p.name for p in bl_root.iterdir()) == ["keep.yaml", "output"]


def test_create_forwards_outside_paths(repo, bl_root, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text(f"card {PAN}\n", encoding="utf-8")
    create(repo, bl_root, "x", "--file", str(outside))
    assert validate(repo, bl_root, "x").verdict == "PASS"


def test_create_requires_an_input(repo, bl_root):
    with pytest.raises(baseline.BaselineError, match="find-pan failed"):
        create(repo, bl_root, "x", "--mask")


def test_create_accepts_an_empty_input_directory(repo, bl_root):
    empty_directory = repo / "RegressionTests" / "empty"
    empty_directory.mkdir()
    create(repo, bl_root, "empty", "--path", str(empty_directory))
    assert validate(repo, bl_root, "empty").verdict == "PASS"


def test_create_refuses_to_baseline_a_skipped_binary_file(repo, bl_root):
    binary_file = repo / "RegressionTests" / "binary.bin"
    binary_file.write_bytes(b"\x00\x01\x02\x03")
    with pytest.raises(baseline.BaselineError, match="did not scan everything.*BINARY"):
        create(repo, bl_root, "binary", "--skip-binary", "--file", str(binary_file))
    assert not (bl_root / "binary.yaml").exists()


def test_main_confirms_all_requested_files_were_scanned(repo, bl_root, capsys):
    assert run_main(repo, bl_root, "--create", "confirmed", *files_args(repo, "VISA.txt")) == 0
    assert "Confirmed find-pan completed successfully." in capsys.readouterr().out


def test_create_with_zero_findings(repo, bl_root):
    """Review Focus 2."""
    empty = repo / "RegressionTests" / "clean.txt"
    empty.write_text("nothing to see\n", encoding="utf-8")
    create(repo, bl_root, "clean", "--file", str(empty))
    assert (bl_root / "output" / "clean.csv").read_text(encoding="utf-8").splitlines() == [
        "filename,line_number,offset,pattern_name,data_type,matched_data"]
    assert validate(repo, bl_root, "clean").verdict == "PASS"


# --- validate: differences ----------------------------------------------------------------------------------------------------


def test_validate_detects_an_edited_input_and_names_the_lost_row(repo, bl_root):
    create(repo, bl_root)
    visa = repo / "RegressionTests" / "VISA.txt"
    lines = visa.read_text(encoding="utf-8").splitlines()
    visa.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")        # drop the first line
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "FAIL (output differs)" and outcome.status == 1
    assert any(line.startswith("missing:") and "VISA.txt:" in line for line in outcome.lines)


def test_validate_detects_a_corrupted_baseline_row(repo, bl_root):
    create(repo, bl_root)
    csv_path = bl_root / "output" / "plain.csv"
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1][:-1] + ("0" if lines[1][-1] != "0" else "1")      # alter the matched data
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "FAIL (output differs)"
    assert sum(line.startswith("missing:") for line in outcome.lines) == 1
    assert sum(line.startswith("extra:") for line in outcome.lines) == 1


def test_validate_ignores_legacy_summary_metadata(repo, bl_root):
    create(repo, bl_root)
    yaml_path = bl_root / "plain.yaml"
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    data["summary"] = {"pans": 999999}
    yaml_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    outcome = validate(repo, bl_root, "plain")
    assert outcome.verdict == "PASS"


def test_input_change_without_csv_change_passes(repo, bl_root):
    clean = repo / "RegressionTests" / "clean.txt"
    clean.write_text("nothing here\n", encoding="utf-8")
    create(repo, bl_root, "clean", "--file", str(clean))
    clean.write_text("still nothing here\n", encoding="utf-8")
    assert validate(repo, bl_root, "clean").verdict == "PASS"


def test_validate_rejects_invalid_csv_header(repo, bl_root):
    create(repo, bl_root)
    csv_path = bl_root / "output" / "plain.csv"
    csv_path.write_text("wrong,header\n", encoding="utf-8")
    outcome = validate(repo, bl_root, "plain")
    assert outcome.status == 2 and "invalid CSV header" in "\n".join(outcome.lines)


def test_crlf_only_change_to_an_input_passes(repo, bl_root):
    create(repo, bl_root)
    visa = repo / "RegressionTests" / "VISA.txt"
    visa.write_bytes(visa.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert validate(repo, bl_root, "plain").verdict == "PASS"


def test_validate_reports_changed_csv_rows_for_added_and_removed_files(repo, bl_root):
    data = repo / "RegressionTests" / "set"
    data.mkdir()
    for name in ("VISA.txt", "UnionPay.txt"):
        shutil.copy(repo / "RegressionTests" / name, data / name)
    create(repo, bl_root, "dir", "--path", str(data))
    (data / "UnionPay.txt").unlink()
    (data / "extra.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    outcome = validate(repo, bl_root, "dir")
    text = "\n".join(outcome.lines)
    assert "missing: UnionPay.txt:" in text
    assert "extra: extra.txt:" in text
    assert outcome.status == 1


def test_max_diff_limits_printed_rows_but_prints_the_count(repo, bl_root):
    create(repo, bl_root)
    csv_path = bl_root / "output" / "plain.csv"
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


def test_validate_ignores_legacy_tool_metadata(repo, bl_root):
    create(repo, bl_root)
    yaml_path = bl_root / "plain.yaml"
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    data["requires_tools"] = ["definitely-not-installed-tool"]
    yaml_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert validate(repo, bl_root, "plain").verdict == "PASS"


def test_unknown_baseline_is_an_error(repo, bl_root):
    outcome = validate(repo, bl_root, "nope")
    assert outcome.verdict == "ERROR" and outcome.status == 2


def test_yaml_name_must_match_filename_and_bad_names_are_rejected(repo, bl_root):
    """Review Focus 1."""
    create(repo, bl_root)
    yaml_path = bl_root / "plain.yaml"
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


def report_status(out, name):
    """The final status label on the report line for baseline *name*."""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in {"PASS", "FAIL"} and parts[1] == name:
            return parts[0]
    return None


def test_list_shows_discovered_baseline_names_without_running_scans(repo, bl_root, capsys, monkeypatch):
    bl_root.mkdir(parents=True)
    (bl_root / "zeta.yaml").write_text("", encoding="utf-8")
    (bl_root / "alpha.yml").write_text("", encoding="utf-8")
    (bl_root / ".hidden.yaml").write_text("", encoding="utf-8")
    (bl_root / "notes.txt").write_text("", encoding="utf-8")
    (bl_root / "nested.yaml").mkdir()
    monkeypatch.setattr(baseline, "run_find_pan", lambda *args, **kwargs: pytest.fail("unexpected scan"))
    assert run_main(repo, bl_root, "--list") == 0
    output = capsys.readouterr()
    assert output.out.splitlines() == ["alpha", "zeta"]
    assert not output.err


def test_list_with_no_baselines(repo, bl_root, capsys):
    assert run_main(repo, bl_root, "--list") == 0
    assert capsys.readouterr().out.strip() == "No baselines found."


@pytest.mark.parametrize("arguments", [
    ("--list", "--create", "name"),
    ("--list", "--validate", "name"),
    ("--list", "--all"),
    ("--list", "--file", "input.txt"),
])
def test_list_rejects_other_actions_and_scanner_arguments(repo, bl_root, arguments, capsys):
    assert run_main(repo, bl_root, *arguments) == 2
    assert "--list cannot be combined" in capsys.readouterr().err


def test_validate_all_mixes_pass_and_fail_and_returns_1(repo, bl_root, capsys):
    create(repo, bl_root, "good")
    create(repo, bl_root, "bad")
    csv_path = bl_root / "output" / "bad.csv"
    csv_path.write_text("\n".join(csv_path.read_text(encoding="utf-8").splitlines()[:-1]) + "\n", encoding="utf-8")
    assert run_main(repo, bl_root, "--validate", "--all") == 1
    out = capsys.readouterr().out
    assert report_status(out, "bad") == "FAIL" and report_status(out, "good") == "PASS"
    assert "1 passed, 1 failed" in out


def test_validate_all_reports_running_before_each_result(repo, bl_root, capsys, monkeypatch):
    bl_root.mkdir(parents=True)
    for name in ("bad", "broken", "good"):
        (bl_root / f"{name}.yaml").touch()
    verdicts = {"bad": ("FAIL (output differs)", 1), "broken": ("ERROR", 2), "good": ("PASS", 0)}

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    clock = iter((0, 1, 2.25, 3, 5.5, 6, 9.75, 10))
    monkeypatch.setattr(baseline.time, "perf_counter", lambda: next(clock))

    def fake_validate(name, *_args):
        verdict, status = verdicts[name]
        return baseline.Outcome(name, verdict, ["detail\ncontinued"] if name == "broken" else [], status)

    monkeypatch.setattr(baseline, "validate", fake_validate)
    assert run_main(repo, bl_root, "--validate", "--all") == 1
    output = capsys.readouterr().out
    assert "RUN    bad \u280b\r" in output and "\rFAIL   bad     1.25s  output differs\n" in output
    assert "RUN    broken \u280b\r" in output and "\rFAIL   broken  2.50s  error  | detail continued\n" in output
    assert "RUN    good \u280b\r" in output and "\rPASS   good    3.75s\n" in output
    assert "1 passed, 1 failed, 0 skipped, 1 errors, total time 10.00s" in output


def test_running_indicator_animates_and_stops(capsys):
    second_frame = threading.Event()
    stream = sys.stdout

    class ObservedStream:
        encoding = "utf-8"

        def write(self, text):
            stream.write(text)
            if "\u2819" in text:
                second_frame.set()

        def flush(self):
            stream.flush()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "stdout", ObservedStream())
        with baseline._running_indicator("slow", True):
            assert second_frame.wait(2)
    output = capsys.readouterr().out
    assert "RUN    slow \u280b" in output and "RUN    slow \u2819" in output
    assert output.endswith("\r" + " " * len("RUN    slow \u280b") + "\r")


def test_running_indicator_falls_back_to_ascii_and_cleans_up_on_error(monkeypatch):
    class AsciiStream(io.StringIO):
        encoding = "ascii"

    stream = AsciiStream()
    monkeypatch.setattr(sys, "stdout", stream)
    with pytest.raises(RuntimeError, match="interrupted"):
        with baseline._running_indicator("broken", True):
            raise RuntimeError("interrupted")
    assert stream.getvalue() == "RUN    broken .\r" + " " * len("RUN    broken .") + "\r"


def test_validate_all_redirected_output_has_one_line_per_baseline(repo, bl_root, capsys, monkeypatch):
    bl_root.mkdir(parents=True)
    for name in ("bad", "good"):
        (bl_root / f"{name}.yaml").touch()
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr(baseline, "validate", lambda name, *_: baseline.Outcome(
        name, "FAIL (output differs)" if name == "bad" else "PASS", ["difference"] if name == "bad" else [],
        1 if name == "bad" else 0))
    assert run_main(repo, bl_root, "--validate", "--all") == 1
    output = capsys.readouterr().out
    assert "RUN    " not in output and "\r" not in output
    rows = [line for line in output.splitlines() if line.startswith(("PASS", "FAIL"))]
    assert len(rows) == 2 and "difference" in rows[0]


def test_validate_all_continues_after_a_broken_baseline(repo, bl_root, capsys):
    """Review Focus 5."""
    create(repo, bl_root, "good")
    create(repo, bl_root, "broken")
    (bl_root / "broken.yaml").write_text("name: [unclosed", encoding="utf-8")
    assert run_main(repo, bl_root, "--validate", "--all") == 2             # broken + pass
    assert report_status(capsys.readouterr().out, "good") == "PASS"
    create(repo, bl_root, "fails")
    csv_path = bl_root / "output" / "fails.csv"
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
    csv_text = (bl_root / "output" / "masked.csv").read_text(encoding="utf-8")
    assert PAN not in csv_text and "*" in csv_text
    data = yaml.safe_load((bl_root / "masked.yaml").read_text(encoding="utf-8"))
    assert "--mask" in data["find_pan"]["command"]


# --- review findings ----------------------------------------------------------------------------------------------------


def test_create_refuses_a_run_that_did_not_scan_everything(repo, bl_root):
    """A baseline of a run with a skipped or failed archive would never really be checked."""
    bogus = repo / "RegressionTests" / "broken.7z"
    bogus.write_bytes(bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) + b"\x00" * 40)
    with pytest.raises(baseline.BaselineError):
        create(repo, bl_root, "arch", "--file", str(bogus))
    assert not (bl_root / "arch.yaml").exists()
    assert not bl_root.exists() or list(bl_root.iterdir()) == []


def test_validate_all_survives_garbled_baseline_files(repo, bl_root, capsys):
    create(repo, bl_root, "good")
    create(repo, bl_root, "garbled")
    (bl_root / "garbled.yaml").write_bytes(b"\xff\xfe\x00 not utf-8 \x81")
    create(repo, bl_root, "badrow")
    csv_path = bl_root / "output" / "badrow.csv"
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    parts = lines[1].split(",")
    parts[1] = "x"
    lines[1] = ",".join(parts)
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert run_main(repo, bl_root, "--validate", "--all") == 2
    out = capsys.readouterr().out
    assert [report_status(out, n) for n in ("good", "garbled", "badrow")] == ["PASS", "FAIL", "FAIL"]
    assert "error" in out


@pytest.mark.parametrize("failure", [OSError("disk full"), KeyboardInterrupt()], ids=["oserror", "interrupt"])
def test_a_failed_replace_keeps_the_old_baseline_and_leaves_no_staging(repo, bl_root, monkeypatch, failure):
    create(repo, bl_root, "keep")
    before = tree_state(bl_root)
    real_replace = baseline.os.replace
    target = bl_root / "keep.yaml"

    def flaky(src, dst):
        if Path(dst) == target and Path(src).parent.name.startswith(".keep."):
            raise failure
        return real_replace(src, dst)

    monkeypatch.setattr(baseline.os, "replace", flaky)
    with pytest.raises(type(failure)):
        create(repo, bl_root, "keep", *files_args(repo), force=True)
    assert tree_state(bl_root) == before
    assert sorted(entry.name for entry in bl_root.iterdir()) == ["keep.yaml", "output"]


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_max_diff_must_be_a_positive_number(repo, bl_root, value, capsys):
    create(repo, bl_root)
    assert run_main(repo, bl_root, "--validate", "plain", "--max-diff", value) == 2
    capsys.readouterr()


def test_validate_all_report_is_laid_out_in_columns_with_a_header_and_totals(repo, bl_root, capsys):
    create(repo, bl_root, "good")
    create(repo, bl_root, "a-much-longer-name")
    csv_path = bl_root / "output" / "a-much-longer-name.csv"
    rows_kept = csv_path.read_text(encoding="utf-8").splitlines()[:-1]
    csv_path.write_text("\n".join(rows_kept) + "\n", encoding="utf-8")
    run_main(repo, bl_root, "--validate", "--all")
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "Validating 2 baselines" and lines[1] == ""
    rows = [line for line in lines if line.startswith(("PASS", "FAIL"))]
    assert len(rows) == 2
    #   The names start in the same column, so the verdict text after them lines up as well.
    assert rows[0].index("a-much-longer-name") == rows[1].index("good")
    failing = next(line for line in rows if line.startswith("FAIL"))
    assert "output differs" in failing and "extra: " in failing
    assert lines[-1].startswith("2 baselines: 1 passed, 1 failed, 0 skipped, 0 errors, total time ")
    assert lines[-2] == ""


# --- a recorded tool may be replaced by another candidate for the same archive type -------------------------------------------------


def test_a_recorded_tool_counts_as_available_when_another_candidate_for_its_type_is_installed(monkeypatch):
    """The baseline was made where `unzip` was installed; here only 7-Zip is, and it expands zip as well."""
    installed = {"7z"}
    monkeypatch.setattr(baseline.shutil, "which", lambda command: command if command in installed else None)
    extractors = {
        "zip": {"posix": [{"command": "unzip", "args": []}, {"command": "7z", "args": []}]},
        "tar": {"posix": [{"command": "tar", "args": []}]},
    }
    monkeypatch.setattr(config, "platform_key", lambda system=None: "linux")
    assert baseline.tool_available("unzip", extractors)
    assert baseline.tool_available("7z", extractors)
    assert not baseline.tool_available("tar", extractors)              # nothing for tar is installed
    assert not baseline.tool_available("definitely-not-installed-tool", extractors)
