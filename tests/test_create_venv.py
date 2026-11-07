"""Exercise environment creation in temporary project copies, never the active environment."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def bash_command():
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


SHELLS = {"sh": bash_command(), "ps1": shutil.which("pwsh") or shutil.which("powershell")}


@pytest.fixture(params=["sh", "ps1"])
def project(request, tmp_path):
    shell = SHELLS[request.param]
    if not shell:
        pytest.skip(f"no shell available for {request.param}")
    if not shutil.which("uv"):
        pytest.skip("uv is not installed")
    root = tmp_path / "project with spaces"
    (root / "bin").mkdir(parents=True)
    script = root / "bin" / f"setup-env.{request.param}"
    shutil.copy(ROOT / "bin" / script.name, script)
    for name in ("pyproject.toml", "uv.lock", "README.md", "requirements.txt"):
        shutil.copy(ROOT / name, root / name)
    shutil.copytree(ROOT / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    return root, script, shell, request.param


def execute(project, env=None, fail_removal=False, recreate=False):
    root, script, shell, kind = project
    if kind == "sh":
        if fail_removal:
            command = [shell, "-c", 'rm() { return 1; }; export -f rm; exec "$@"', "--", shell, str(script), "--recreate"]
        else:
            command = [shell, str(script), *(["--recreate"] if recreate else [])]
    elif fail_removal:
        script_literal = str(script).replace("'", "''")
        command = [shell, "-NoProfile", "-Command",
                   f"function Remove-Item {{ throw 'simulated removal failure' }}; & '{script_literal}' -Recreate"]
    else:
        command = [shell, "-NoProfile", "-File", str(script), *(["-Recreate"] if recreate else [])]
    return subprocess.run(command, cwd=root.parent, env=env, capture_output=True, text=True, timeout=180, check=False)


@pytest.mark.parametrize("existing", [False, True])
def test_creates_project_venv_and_replaces_existing_directory(project, existing):
    root, _, _, _ = project
    if existing:
        (root / ".venv").mkdir()
        (root / ".venv" / "old-marker").write_text("old", encoding="utf-8")
    env = os.environ.copy()
    env["UV_PROJECT_ENVIRONMENT"] = ".venv-other"
    result = execute(project, env, recreate=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / ".venv" / "pyvenv.cfg").is_file()
    assert not (root / ".venv" / "old-marker").exists()
    assert not (root / ".venv-other").exists()
    python = root / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    check = subprocess.run([str(python), "-m", "pip", "check"], capture_output=True, text=True, timeout=30, check=False)
    assert check.returncode == 0, check.stdout + check.stderr
    assert "pytest" in result.stdout


def test_pip_install_failure_is_reported(project):
    root, _, _, _ = project
    with (root / "requirements.txt").open("a", encoding="utf-8") as requirements:
        requirements.write("\npytest==0.0.0\n")
    result = execute(project)
    assert result.returncode != 0
    assert "conflict" in (result.stdout + result.stderr).lower()
    assert (root / ".venv" / "pyvenv.cfg").is_file()


def test_failed_removal_explains_manual_recovery_without_creating_environment(project):
    root, _, _, _ = project
    (root / ".venv").mkdir()
    marker = root / ".venv" / "old-marker"
    marker.write_text("old", encoding="utf-8")
    result = execute(project, os.environ.copy(), fail_removal=True)
    assert result.returncode != 0
    assert "manually remove the .venv directory" in result.stderr.lower()
    assert "run this script again" in result.stderr.lower()
    assert marker.read_text(encoding="utf-8") == "old"
    assert not (root / ".venv" / "pyvenv.cfg").exists()


def test_setup_uses_and_preserves_venv_without_changing_shell_profile(project, tmp_path):
    root, _, _, _ = project
    env = os.environ.copy()
    env["UV_PROJECT_ENVIRONMENT"] = ".venv"
    prepared = subprocess.run(["uv", "sync", "--locked"], cwd=root, env=env,
                              capture_output=True, text=True, timeout=180, check=False)
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    marker = root / ".venv" / "keep-marker"
    marker.write_text("keep", encoding="utf-8")
    env["UV_PROJECT_ENVIRONMENT"] = str(tmp_path / "unexpected-environment")
    env["HOME"] = str(tmp_path)
    profile = tmp_path / ".bashrc"
    profile.write_text("# existing profile\n", encoding="utf-8")
    result = execute(project, env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.read_text(encoding="utf-8") == "keep"
    assert profile.read_text(encoding="utf-8") == "# existing profile\n"
    assert not (tmp_path / "unexpected-environment").exists()
