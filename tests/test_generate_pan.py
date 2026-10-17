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


def test_random_text_lines_have_multiple_hits(tmp_path):
    out = tmp_path / "random.txt"

    result = generate_pan.main(
        ["--random-text", "40", "--max-hits", "4", "--seed", "1",
         "--patterns", str(CONFIGURATION_PATH), "--output", str(out)]
    )
    assert result == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 40
    assert all(any(c.isdigit() for c in line) for line in lines)


def test_random_text_is_reproducible_with_seed(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    for out in (a, b):
        generate_pan.main(["--random-text", "5", "--seed", "7",
                           "--patterns", str(CONFIGURATION_PATH), "--output", str(out)])
    assert a.read_text() == b.read_text()


def test_random_text_rejects_bad_counts():
    assert generate_pan.main(["--random-text", "0"]) == 2
    assert generate_pan.main(["--random-text", "3", "--max-hits", "0"]) == 2


def test_random_text_is_found_by_scanner(compiled_patterns, tmp_path):
    """The scanner must find every embedded hit, with no Luhn or anti-PAN noise."""
    import re

    out = tmp_path / "random.txt"
    generate_pan.main(["--random-text", "60", "--max-hits", "4", "--seed", "3",
                       "--patterns", str(CONFIGURATION_PATH), "--output", str(out)])
    lines = out.read_text(encoding="utf-8").splitlines()

    # Each hit is a bare PAN or a track record (which embeds one PAN).
    track = re.compile(r"%B\d{12,19}\^[^^]+\^\d+\?|;\d{12,19}=\d+\?")
    bare_pan = re.compile(r"(?<!\d)\d{12,19}(?!\d)")
    expected = 0
    for line in lines:
        expected += len(track.findall(line))
        expected += len(bare_pan.findall(track.sub(" ", line)))

    import logging

    from find_pan.logging_setup import Loggers
    from find_pan.models import MatchKind, ScanStats
    from find_pan.redact import Redactor
    from find_pan.reporting import Reporter
    from find_pan.scanner import Scanner
    from find_pan.settings import Settings

    loggers = Loggers(pan=logging.getLogger("test.gen.pan"), trace=logging.getLogger("test.gen.trace"))
    reporter = Reporter(Redactor(False), [], ScanStats(), loggers.trace, 500)
    Scanner(Settings(), compiled_patterns, reporter, loggers).scan_file(str(out))
    stats = reporter.stats
    found = stats.count(MatchKind.PAN) + stats.count(MatchKind.TRACK)
    assert stats.count(MatchKind.BAD_LUHN) == 0
    assert stats.count(MatchKind.ANTI_PAN) == 0
    assert found == expected
    assert found > len(lines)
