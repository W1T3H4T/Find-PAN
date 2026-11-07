"""Behavioral coverage for bin utility lint cleanup."""

import argparse
import importlib.util
import logging
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "bin" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_obfuscator_compiles_only_dictionary_categories(capsys):
    module = load("obfuscator_cleanup", "obfuscate-pan.py")
    module._Args = argparse.Namespace(json="patterns.json")
    patterns = module.compile_regex_patterns({
        "notes": ["not a category"],
        "PAN Pattern": {"example": {"regex": ["[0-9]{4}"]}, "other": {}},
    })
    assert len(patterns) == 1
    assert patterns[0][:2] == ("PAN Pattern", "example")
    assert patterns[0][2].fullmatch("1234")
    assert "PAN Pattern" in capsys.readouterr().out


def test_obfuscator_keeps_error_reporting_for_invalid_regex(capsys):
    module = load("obfuscator_invalid_regex", "obfuscate-pan.py")
    module._Args = argparse.Namespace(json="patterns.json")
    assert module.compile_regex_patterns({"PAN Pattern": {"bad": {"regex": ["["]}}}) == []
    assert "Error compiling regex patterns" in capsys.readouterr().out


def test_purge_logger_retains_filename_format(tmp_path, monkeypatch):
    module = load("purge_cleanup", "purge-log-files.py")
    monkeypatch.chdir(tmp_path)
    logger = module.init_logger()
    try:
        names = [Path(handler.baseFilename).name for handler in logger.handlers
                 if isinstance(handler, logging.FileHandler)]
        assert len(names) == 1
        assert re.fullmatch(r"purge-log-files_[0-9]{8}\.log", names[0])
    finally:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
