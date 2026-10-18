"""generate-test-data.py: many small files with known PAN and track data, and the answers to check find-pan with."""

import importlib.util
import json
import time
from collections import Counter
from pathlib import Path

import pytest

from find_pan import cli

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "generate-test-data.py"
KEYS = ("pans", "tracks", "bad_luhn", "anti_pans")


def load():
    spec = importlib.util.spec_from_file_location("generate_test_data", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(tmp_path, *options, files=150, seed=3, name="tree"):
    out = tmp_path / name
    status = load().main(["--out", str(out), "--files", str(files), "--seed", str(seed), *options])
    assert status == 0
    return out, out.with_name(name + ".expected")


def answers(directory):
    return (json.loads((directory / "expected.json").read_text(encoding="utf-8")),
            json.loads((directory / "manifest.json").read_text(encoding="utf-8")))


def scan(tmp_path, tree, *options):
    summary = tmp_path / "summary.json"
    status = cli.main(["--path", str(tree), "--summary-json", str(summary), "--log-dir", str(tmp_path / "logs"), *options])
    assert status == 0
    return json.loads(summary.read_text(encoding="utf-8"))


# --- the answers describe what was written -----------------------------------------------------------------------


def test_the_manifest_totals_are_the_sum_of_its_files(tmp_path):
    _, expected_dir = generate(tmp_path, "--binary", "10", "--archives", "10")
    expected, manifest = answers(expected_dir)
    assert expected == manifest["totals"]
    for key in KEYS:
        assert sum(entry[key] for entry in manifest["entries"]) == expected[key]
    assert manifest["seed"] == 3 and manifest["binary_files"] > 0


def test_every_kind_of_hit_is_planted_by_the_default_mix(tmp_path):
    _, expected_dir = generate(tmp_path, files=400)
    expected, _ = answers(expected_dir)
    assert all(expected[key] > 0 for key in KEYS)


def test_the_same_seed_gives_the_same_tree_whatever_the_time(tmp_path, monkeypatch):
    """Archive members carry no timestamp, so the bytes depend on the seed alone."""
    monkeypatch.setattr(time, "time", lambda: 1_000_000_000.0)
    first, first_answers = generate(tmp_path, "--archives", "10", name="one")
    monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
    second, second_answers = generate(tmp_path, "--archives", "10", name="two")
    listing = lambda root: sorted((p.relative_to(root).as_posix(), p.read_bytes()) for p in root.rglob("*") if p.is_file())
    assert listing(first) == listing(second)
    assert answers(first_answers)[0] == answers(second_answers)[0]


def test_files_are_spread_over_directories_and_vary_in_extension(tmp_path):
    tree, _ = generate(tmp_path, "--per-dir", "20", "--depth", "2", files=200)
    per_directory = Counter(path.parent for path in tree.rglob("*") if path.is_file())
    assert max(per_directory.values()) <= 20 and len(per_directory) >= 10
    assert len({path.suffix for path in tree.rglob("*") if path.is_file()}) >= 4


def test_a_flat_tree_has_no_subdirectories(tmp_path):
    tree, _ = generate(tmp_path, "--depth", "0", files=30)
    assert not [path for path in tree.iterdir() if path.is_dir()]


def test_the_answers_stay_outside_the_scanned_tree(tmp_path):
    tree, expected_dir = generate(tmp_path, files=20)
    assert not (tree / "expected.json").exists() and (expected_dir / "expected.json").exists()


# --- find-pan agrees ---------------------------------------------------------------------------------------------


def test_find_pan_reports_exactly_what_was_planted(tmp_path):
    tree, expected_dir = generate(tmp_path, "--binary", "5", files=300)
    expected, _ = answers(expected_dir)
    summary = scan(tmp_path, tree)
    assert {key: summary[key] for key in KEYS} == expected


def test_find_pan_agrees_for_other_mixes_and_larger_files(tmp_path):
    tree, expected_dir = generate(tmp_path, "--mix", "pan=1,delimited=1,bad-luhn=1,anti-pan=1,track=1,clean=0",
                                  "--max-hits", "6", "--max-size", "20000", files=80, seed=11)
    expected, _ = answers(expected_dir)
    assert {key: scan(tmp_path, tree)[key] for key in KEYS} == expected


def test_min_size_makes_every_file_at_least_that_big_and_find_pan_still_agrees(tmp_path):
    tree, expected_dir = generate(tmp_path, "--min-size", "50000", "--max-size", "52000", "--binary", "10", files=12, seed=5)
    assert all(path.stat().st_size >= 50000 for path in tree.rglob("*") if path.is_file())
    expected, _ = answers(expected_dir)
    assert {key: scan(tmp_path, tree)[key] for key in KEYS} == expected


def test_find_pan_reports_what_was_planted_inside_archives(tmp_path):
    tree, expected_dir = generate(tmp_path, "--archives", "30", "--nest", "50", files=200)
    expected, manifest = answers(expected_dir)
    assert any(entry["kind"] == "archive" for entry in manifest["entries"])
    summary = scan(tmp_path, tree)
    if summary["archives_skipped"]:
        pytest.skip("no extractor installed for every archive type used")
    assert {key: summary[key] for key in KEYS} == expected


def test_pans_txt_is_a_pan_list_that_finds_every_planted_pan(tmp_path):
    tree, expected_dir = generate(tmp_path, files=200)
    expected, _ = answers(expected_dir)
    listed = (expected_dir / "pans.txt").read_text(encoding="utf-8").split()
    summary = scan(tmp_path, tree, "--pan-list", str(expected_dir / "pans.txt"))
    assert summary["pans"] == expected["pans"] and len(listed) > 0
    assert all(entry["found"] >= 1 for entry in summary["expected"]["pans"])


def test_tracks_txt_is_a_track_list_that_finds_every_planted_track(tmp_path):
    tree, expected_dir = generate(tmp_path, files=200)
    expected, _ = answers(expected_dir)
    summary = scan(tmp_path, tree, "--track-list", str(expected_dir / "tracks.txt"))
    assert summary["tracks"] == expected["tracks"]
    assert all(entry["found"] >= 1 for entry in summary["expected"]["tracks"])


# --- usage -------------------------------------------------------------------------------------------------------


def test_a_non_empty_output_directory_is_refused(tmp_path, capsys):
    (tmp_path / "tree").mkdir()
    (tmp_path / "tree" / "keep.txt").write_text("x", encoding="utf-8")
    assert load().main(["--out", str(tmp_path / "tree"), "--files", "5"]) == 1
    assert "not empty" in capsys.readouterr().err


@pytest.mark.parametrize("mix", ["bogus=1", "pan=-1", "pan=abc", "pan=0,track=0"])
def test_a_bad_mix_is_an_error(tmp_path, capsys, mix):
    assert load().main(["--out", str(tmp_path / "t"), "--files", "5", "--mix", mix]) == 1
    assert "Error" in capsys.readouterr().err


def test_binary_and_archive_shares_cannot_exceed_everything(tmp_path, capsys):
    assert load().main(["--out", str(tmp_path / "t"), "--files", "5", "--binary", "60", "--archives", "60"]) == 1
