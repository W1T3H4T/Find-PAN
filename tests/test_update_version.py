"""Tests for bin/update_version.py."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UPDATE_VERSION_PATH = ROOT / "bin" / "update_version.py"

spec = importlib.util.spec_from_file_location("update_version", UPDATE_VERSION_PATH)
update_version = importlib.util.module_from_spec(spec)
sys.modules["update_version"] = update_version
spec.loader.exec_module(update_version)

(
    build_parser,
    parse_set_version,
    read_pyproject_version,
    write_pyproject_version,
    main,
) = (
    update_version.build_parser,
    update_version.parse_set_version,
    update_version.read_pyproject_version,
    update_version.write_pyproject_version,
    update_version.main,
)


def test_read_and_write_version(tmp_path):
    """The version line in pyproject.toml is read and updated correctly."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "find-pan"\nversion = "1.2.3"\n', encoding="utf-8"
    )

    assert read_pyproject_version(pyproject) == (1, 2, 3)

    write_pyproject_version(pyproject, (2, 0, 0))
    assert read_pyproject_version(pyproject) == (2, 0, 0)


def test_parse_set_version_accepts_valid_version():
    assert parse_set_version("4.5.6") == (4, 5, 6)


def test_parse_set_version_rejects_wrong_format():
    with pytest.raises(SystemExit):
        parser = build_parser()
        parser.parse_args(["--version", "1.2"])


def test_parse_set_version_rejects_non_numeric_components():
    with pytest.raises(SystemExit):
        parser = build_parser()
        parser.parse_args(["--version", "1.2.x"])


def test_mutually_exclusive_action_group():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--major", "--minor"])


def test_bump_major(tmp_path, capsys):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('version = "1.2.3"\n', encoding="utf-8")

    assert main(["--major", "--pyproject", str(pyproject)]) == 0
    assert read_pyproject_version(pyproject) == (2, 0, 0)
    captured = capsys.readouterr()
    assert "Updated version: 1.2.3 -> 2.0.0" in captured.out


def test_bump_minor(tmp_path, capsys):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('version = "1.2.3"\n', encoding="utf-8")

    assert main(["--minor", "--pyproject", str(pyproject)]) == 0
    assert read_pyproject_version(pyproject) == (1, 3, 0)


def test_bump_patch(tmp_path, capsys):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('version = "1.2.3"\n', encoding="utf-8")

    assert main(["--patch", "--pyproject", str(pyproject)]) == 0
    assert read_pyproject_version(pyproject) == (1, 2, 4)


def test_show_version(tmp_path, capsys):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('version = "7.8.9"\n', encoding="utf-8")

    assert main(["--show", "--pyproject", str(pyproject)]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "7.8.9"


def test_set_explicit_version(tmp_path, capsys):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('version = "0.0.0"\n', encoding="utf-8")

    assert main(["--version", "9.10.11", "--pyproject", str(pyproject)]) == 0
    assert read_pyproject_version(pyproject) == (9, 10, 11)
