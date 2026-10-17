"""Tests for bin/generate-pan.py."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GENERATE_PAN_PATH = ROOT / "bin" / "generate-pan.py"
CONFIGURATION_PATH = ROOT / "config" / "find-pan-regex.json"

spec = importlib.util.spec_from_file_location("generate_pan", GENERATE_PAN_PATH)
generate_pan = importlib.util.module_from_spec(spec)
sys.modules["generate_pan"] = generate_pan
spec.loader.exec_module(generate_pan)


def test_default_output_path_uses_hyphens_for_spaces():
    path = generate_pan.default_output_path("Diners Club International")
    assert path.name == "Diners-Club-International.txt"


def test_generate_pans_respects_count(pan_generator):
    patterns = generate_pan.load_pan_patterns(CONFIGURATION_PATH)
    rng = __import__("random").Random(0)

    generated = generate_pan.generate_pans("VISA", patterns["VISA"], 5, rng)
    assert len(generated) == 5
    for item in generated:
        assert item.pattern_name == "VISA"
        assert generate_pan.luhn_check(item.pan)


def test_generate_pans_count_zero_returns_empty(pan_generator):
    patterns = generate_pan.load_pan_patterns(CONFIGURATION_PATH)
    rng = __import__("random").Random(0)

    generated = generate_pan.generate_pans("VISA", patterns["VISA"], 0, rng)
    assert generated == []


def test_main_writes_default_output_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = generate_pan.main(
        ["--pan-pattern", "VISA", "--count", "2", "--seed", "0", "--patterns", str(CONFIGURATION_PATH)]
    )
    assert result == 0

    output_file = tmp_path / "VISA.txt"
    assert output_file.exists()
    text = output_file.read_text(encoding="utf-8")
    assert "Synthetic PANs for VISA:" in text
    assert text.count("\n") == 3  # header + 2 PANs + trailing newline

    captured = capsys.readouterr()
    assert "Wrote 2 PAN(s)" in captured.err


def test_main_writes_custom_output_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    custom_output = tmp_path / "my-pans.txt"

    result = generate_pan.main(
        [
            "--pan-pattern",
            "VISA",
            "--count",
            "1",
            "--seed",
            "0",
            "--patterns",
            str(CONFIGURATION_PATH),
            "--output",
            str(custom_output),
        ]
    )
    assert result == 0
    assert custom_output.exists()
    assert custom_output.read_text(encoding="utf-8").count("\n") == 2


def test_main_all_writes_default_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    patterns = generate_pan.load_pan_patterns(CONFIGURATION_PATH)

    result = generate_pan.main(
        ["--all", "--count", "1", "--seed", "0", "--patterns", str(CONFIGURATION_PATH)]
    )
    assert result == 0

    expected_count = sum(len(data["regex"]) for data in patterns.values())
    for pattern_name in patterns:
        output_file = generate_pan.default_output_path(pattern_name)
        assert output_file.exists(), f"{output_file} was not created"

    text = (tmp_path / "VISA.txt").read_text(encoding="utf-8")
    assert "Synthetic PANs for VISA:" in text
    assert text.count("\n") == 2

    captured = capsys.readouterr()
    assert f"Wrote {expected_count} PAN(s)" in captured.err


def test_main_all_with_output_writes_single_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    patterns = generate_pan.load_pan_patterns(CONFIGURATION_PATH)
    custom_output = tmp_path / "all-pans.txt"
    expected_count = sum(len(data["regex"]) for data in patterns.values())

    result = generate_pan.main(
        [
            "--all",
            "--count",
            "1",
            "--seed",
            "0",
            "--patterns",
            str(CONFIGURATION_PATH),
            "--output",
            str(custom_output),
        ]
    )
    assert result == 0
    assert custom_output.exists()
    text = custom_output.read_text(encoding="utf-8")
    assert text.count("Synthetic PANs for") == len(patterns)
    assert text.count("\n") == expected_count + len(patterns)

    captured = capsys.readouterr()
    assert f"Wrote {expected_count} PAN(s) to {custom_output}" in captured.err


def test_main_all_and_pan_pattern_are_mutually_exclusive(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = generate_pan.main(
        [
            "--all",
            "--pan-pattern",
            "VISA",
            "--count",
            "1",
            "--seed",
            "0",
            "--patterns",
            str(CONFIGURATION_PATH),
        ]
    )
    assert result == 2
    assert "--all cannot be used with --pan-pattern" in capsys.readouterr().err


def test_main_non_verbose_output_omits_regex_and_pan_prefix(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = generate_pan.main(
        ["--pan-pattern", "VISA", "--count", "2", "--seed", "0", "--patterns", str(CONFIGURATION_PATH)]
    )
    assert result == 0

    text = (tmp_path / "VISA.txt").read_text(encoding="utf-8")
    assert "Synthetic PANs for VISA:" in text
    assert "PAN:" not in text
    assert "Regex" not in text
    assert text.count("\n") == 3  # header + 2 PANs + trailing newline


def test_main_verbose_output_includes_regex_and_pan_prefix(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    result = generate_pan.main(
        [
            "--pan-pattern",
            "VISA",
            "--count",
            "2",
            "--seed",
            "0",
            "--patterns",
            str(CONFIGURATION_PATH),
            "--verbose",
        ]
    )
    assert result == 0

    text = (tmp_path / "VISA.txt").read_text(encoding="utf-8")
    assert "Synthetic PANs for VISA:" in text
    assert text.count("PAN:") == 2
    assert text.count("Regex 1:") == 2
