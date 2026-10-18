"""bin/find-pan.sh and bin/find-pan.ps1: run find-pan from any directory with the arguments passed through."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

BIN = Path(__file__).resolve().parents[1] / "bin"
PAN = "4556737586899855"


def _bash():
    """A bash that understands the checkout's paths: any on POSIX, Git's on Windows (not the WSL stub)."""
    found = shutil.which("bash")
    if found is None:
        return None
    if sys.platform == "win32" and "git" not in found.lower():
        return None
    return found


LAUNCHERS = {
    "sh": ([_bash(), str(BIN / "find-pan.sh")] if _bash() else None),
    "ps1": ([shutil.which("pwsh"), "-NoProfile", "-File", str(BIN / "find-pan.ps1")] if shutil.which("pwsh") else None),
}


@pytest.fixture(params=sorted(LAUNCHERS))
def launcher(request):
    command = LAUNCHERS[request.param]
    if command is None:
        pytest.skip(f"no shell available for find-pan.{request.param}")
    return command


def run(command, cwd, *arguments):
    return subprocess.run([*command, *arguments], cwd=cwd, capture_output=True, text=True, timeout=120)


def test_the_launchers_exist_and_the_shell_one_is_executable():
    assert (BIN / "find-pan.sh").is_file() and (BIN / "find-pan.ps1").is_file()
    assert b"\r\n" not in (BIN / "find-pan.sh").read_bytes()
    if sys.platform != "win32":
        assert (BIN / "find-pan.sh").stat().st_mode & 0o111


def test_version_is_passed_through(launcher, tmp_path):
    result = run(launcher, tmp_path, "--version")
    assert result.returncode == 0 and "find-pan.py v" in result.stdout


def test_relative_paths_are_relative_to_where_the_launcher_is_run(launcher, tmp_path):
    (tmp_path / "card.txt").write_text(f"card {PAN} here\n", encoding="utf-8")
    result = run(launcher, tmp_path, "--file", "card.txt", "--mask", "--log-dir", "logs",
                 "--summary-json", "summary.json")
    assert result.returncode == 0 and "PANs Matched  :        1" in result.stdout
    assert (tmp_path / "summary.json").is_file() and PAN not in result.stdout


def test_the_exit_status_of_find_pan_is_returned(launcher, tmp_path):
    result = run(launcher, tmp_path, "--file", "absent.txt", "--log-dir", "logs")
    assert result.returncode == 1


def test_arguments_with_spaces_arrive_intact(launcher, tmp_path):
    folder = tmp_path / "data with spaces"
    folder.mkdir()
    (folder / "card.txt").write_text(f"card {PAN} here\n", encoding="utf-8")
    result = run(launcher, tmp_path, "--path", str(folder), "--log-dir", str(tmp_path / "log dir"))
    assert result.returncode == 0 and "PANs Matched  :        1" in result.stdout
