"""Tests for the pytest regression runner."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "bin" / "run-pytest-regression.py"
specification = importlib.util.spec_from_file_location("pytest_regression_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = runner
specification.loader.exec_module(runner)


def test_runner_forwards_worker_count_and_pytest_arguments(monkeypatch):
    captured = {}

    def fake_run(command, cwd, check):
        captured.update(command=command, cwd=cwd, check=check)
        return SimpleNamespace(returncode=3)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner.main(["--workers", "4", "tests/test_baseline.py", "-k", "create"]) == 3
    assert captured["command"][-5:] == ["-n", "4", "tests/test_baseline.py", "-k", "create"]
    assert captured["cwd"] == ROOT and captured["check"] is False


def test_runner_omits_parallel_option_when_workers_are_not_requested(monkeypatch):
    captured = {}

    def fake_run(command, **_):
        captured["command"] = command
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    assert runner.main(["tests/test_baseline.py"]) == 0
    assert "-n" not in captured["command"]


@pytest.mark.parametrize("workers", ["0", "-1", "many"])
def test_runner_rejects_non_positive_or_non_numeric_worker_counts(workers):
    with pytest.raises(SystemExit) as error:
        runner.main(["--workers", workers])
    assert error.value.code == 2
