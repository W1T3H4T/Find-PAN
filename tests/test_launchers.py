"""bin/find-pan.sh and bin/find-pan.ps1: run find-pan from any directory with the arguments passed through."""

import json
import os
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
    if sys.platform != "win32":
        return found
    if found and "git" in found.lower():
        return found
    git = shutil.which("git")
    if git:
        git_root = Path(git).resolve().parent.parent
        for candidate in (git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


LAUNCHERS = {
    "sh": ([_bash(), str(BIN / "find-pan.sh")] if _bash() else None),
    "ps1": ([shutil.which("pwsh"), "-NoProfile", "-File", str(BIN / "find-pan.ps1")] if shutil.which("pwsh") else None),
}


@pytest.fixture(name="launcher", params=sorted(LAUNCHERS))
def launcher_fixture(request):
    command = LAUNCHERS[request.param]
    if command is None:
        pytest.skip(f"no shell available for find-pan.{request.param}")
    return command


def run(command, cwd, *arguments):
    env = os.environ.copy()
    env["FIND_PAN_HOME"] = str(BIN.parent)
    return subprocess.run([*command, *arguments], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120, check=False)


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


def test_launcher_ignores_inherited_uv_environment(launcher, tmp_path):
    alternate = tmp_path / "unexpected-environment"
    env = os.environ.copy()
    env.pop("FIND_PAN_HOME", None)
    env["UV_PROJECT_ENVIRONMENT"] = str(alternate)
    result = subprocess.run([*launcher, "--version"], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "find-pan.py v" in result.stdout
    assert not alternate.exists()


def test_the_exit_status_of_find_pan_is_returned(launcher, tmp_path):
    result = run(launcher, tmp_path, "--file", "absent.txt", "--log-dir", "logs")
    assert result.returncode == 1


def test_arguments_with_spaces_arrive_intact(launcher, tmp_path):
    folder = tmp_path / "data with spaces"
    folder.mkdir()
    (folder / "card.txt").write_text(f"card {PAN} here\n", encoding="utf-8")
    result = run(launcher, tmp_path, "--path", str(folder), "--log-dir", str(tmp_path / "log dir"))
    assert result.returncode == 0 and "PANs Matched  :        1" in result.stdout


def test_find_pan_home_selects_launcher_and_environment(launcher, tmp_path):
    home = tmp_path / "project with spaces"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "find-pan.py").write_text(
        "import json, os, sys\nprint(json.dumps([sys.prefix, os.getcwd(), sys.argv[1:]]))\nsys.exit(7)\n",
        encoding="utf-8",
    )
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(home / ".venv")],
                   check=True, timeout=120, capture_output=True)
    env = os.environ.copy()
    env["FIND_PAN_HOME"] = str(home)
    env["UV_PROJECT_ENVIRONMENT"] = str(tmp_path / "wrong-environment")
    result = subprocess.run([*launcher, "argument with spaces"], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120, check=False)
    prefix, cwd, arguments = json.loads(result.stdout)
    assert Path(prefix).resolve() == (home / ".venv").resolve()
    assert Path(cwd).resolve() == tmp_path.resolve()
    assert arguments == ["argument with spaces"] and result.returncode == 7
    assert not (tmp_path / "wrong-environment").exists()


@pytest.mark.parametrize("launcher_exists", [False, True])
def test_invalid_find_pan_home_fails_clearly(launcher, tmp_path, launcher_exists):
    home = tmp_path / "missing project"
    if launcher_exists:
        (home / "bin").mkdir(parents=True)
        (home / "bin" / "find-pan.py").touch()
    env = os.environ.copy()
    env["FIND_PAN_HOME"] = str(home)
    result = subprocess.run([*launcher, "--version"], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 1
    assert ("Python was not found" if launcher_exists else "launcher not found") in result.stderr
