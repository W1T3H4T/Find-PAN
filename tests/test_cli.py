"""Tests for find_pan.cli."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from find_pan import cli
from find_pan.settings import Settings
from find_pan.version import __version__

ROOT = Path(__file__).resolve().parents[1]
PAN = "4556737586899855"


def scan_args(tmp_path, *extra):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(exist_ok=True)
    return ["--path", str(scan_dir), "--log-dir", str(tmp_path / "logs"), *extra]


def test_parse_args_defaults():
    settings = cli.parse_args([])
    assert isinstance(settings, Settings)
    assert settings.path is None and settings.csv is None
    assert settings.report_delta == 500 and settings.line_limit == 0
    assert not any([settings.mask, settings.log_anti_pan, settings.debug, settings.verbose,
                    settings.skip_binary, settings.rgx_prefix, settings.exception_test])
    assert settings.log_dir.endswith("Find-PAN-Logs")
    assert settings.files == ()


def test_parse_args_all_flags():
    settings = cli.parse_args([
        "--path", "p", "--file", "a.txt", "b.zip", "--file", "c.tar", "--log-dir", "l", "--rgx-patterns", "r.json",
        "--rgx-prefix", "--skip-binary", "--line-limit", "5", "--report-delta", "7", "--csv", "o.csv",
        "--verbose", "--debug", "--mask", "--log-anti-pan", "--exception-test",
    ])
    assert settings == Settings(
        path="p", files=("a.txt", "b.zip", "c.tar"), log_dir="l", rgx_patterns="r.json", rgx_prefix=True,
        skip_binary=True, line_limit=5, report_delta=7, csv="o.csv", verbose=True, debug=True,
        mask=True, log_anti_pan=True, exception_test=True,
    )


@pytest.mark.parametrize("value", ["0", "-3"])
def test_report_delta_below_one_is_argparse_error(value, capsys):
    with pytest.raises(SystemExit) as info:
        cli.parse_args(["--report-delta", value])
    assert info.value.code == 2
    assert "report-delta" in capsys.readouterr().err


def test_version_works_without_config(monkeypatch, capsys):
    def no_config():
        raise FileNotFoundError("no config")

    monkeypatch.setattr(cli, "find_json_regex_config", no_config)
    assert cli.main(["--version"]) == 0
    assert f"find-pan.py v{__version__}" in capsys.readouterr().out


def test_parser_does_not_look_up_config():
    assert cli.parse_args([]).rgx_patterns is None


def test_missing_arguments_prints_help_returns_1(tmp_path, capsys):
    status = cli.main(["--log-dir", str(tmp_path / "logs")])
    assert status == 1
    assert "usage:" in capsys.readouterr().out


def test_bad_pattern_file_returns_1_and_creates_no_csv(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    csv_path = tmp_path / "out.csv"
    status = cli.main(scan_args(tmp_path, "--rgx-patterns", str(bad), "--csv", str(csv_path)))
    assert status == 1
    assert not csv_path.exists()
    assert "Traceback" not in capsys.readouterr().err


def test_missing_pattern_file_returns_1(tmp_path, capsys):
    status = cli.main(scan_args(tmp_path, "--rgx-patterns", str(tmp_path / "missing.json")))
    assert status == 1
    assert "not found" in capsys.readouterr().err


def test_unwritable_csv_returns_1_without_traceback(tmp_path, capsys):
    status = cli.main(scan_args(tmp_path, "--csv", str(tmp_path)))  # a directory
    captured = capsys.readouterr()
    assert status == 1
    assert "Cannot open CSV output" in captured.err
    assert "Traceback" not in captured.err + captured.out


def test_unwritable_log_dir_returns_1(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    status = cli.main(["--path", str(tmp_path), "--log-dir", str(blocker)])
    assert status == 1
    assert "Cannot set up logging" in capsys.readouterr().err


def test_keyboard_interrupt_closes_csv_and_returns_1(tmp_path, monkeypatch, capsys):
    def interrupt(self, path):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.Scanner, "scan_path", interrupt)
    csv_path = tmp_path / "out.csv"
    status = cli.main(scan_args(tmp_path, "--csv", str(csv_path)))
    assert status == 1
    assert csv_path.read_text(encoding="utf-8").startswith("filename,")  # flushed and closed
    assert "Scan complete." in capsys.readouterr().out


def test_debug_dumps_patterns_without_name_error(tmp_path, capsys):
    status = cli.main(scan_args(tmp_path, "--debug"))
    assert status == 0
    assert "Anti-PAN Pattern" in capsys.readouterr().out


def test_scan_reports_summary_and_returns_0(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_text(f"card {PAN}\n", encoding="utf-8")
    assert cli.main(scan_args(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "PANs Matched  :        1" in out
    assert "Scanned       :        1 Files." in out


def test_line_limit_flag_end_to_end(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_text(f"card {PAN}\n" * 6, encoding="utf-8")
    assert cli.main(scan_args(tmp_path, "--line-limit", "3")) == 0
    assert "PANs Matched  :        3" in capsys.readouterr().out




def test_exception_test_flag_exits_with_one(tmp_path, capsys):
    with pytest.raises(SystemExit) as info:
        cli.main(["--exception-test"])
    assert info.value.code == 1
    assert "Exception Information:" in capsys.readouterr().out


def test_print_exception_info_accepts_none(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "exit", lambda code: None)
    cli.print_exception_info(None)
    assert "Exception Information:" in capsys.readouterr().out


def test_print_exception_info_reports_active_exception(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "exit", lambda code: None)
    try:
        raise ValueError("boom")
    except ValueError as error:
        cli.print_exception_info(error)
    out = capsys.readouterr().out
    assert "Type    : ValueError" in out and "Message : boom" in out


def test_print_exception_info_extra_context_and_exit_status(capsys):
    with pytest.raises(SystemExit) as info:
        cli.print_exception_info("extra context")
    assert info.value.code == 1
    assert "Info    : extra context" in capsys.readouterr().out


def test_launcher_version_subprocess():
    result = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "find-pan.py"), "--version"],
        capture_output=True, text=True, check=False, cwd=ROOT,
    )
    assert result.returncode == 0
    assert f"find-pan.py v{__version__}" in result.stdout


def test_command_line_arguments_line_printed_for_real_argv(tmp_path, monkeypatch, capsys):
    """Deferred minor 1: the launcher passes argv=None, so sys.argv must be used."""
    args = scan_args(tmp_path)
    monkeypatch.setattr(sys, "argv", ["find-pan.py", *args])
    assert cli.main() == 0
    assert "Command-line arguments:" in capsys.readouterr().out


@pytest.mark.parametrize("stage", ["find_json_regex_config", "load_json_data", "compile_regex_patterns"])
def test_keyboard_interrupt_anywhere_returns_1_without_traceback(tmp_path, monkeypatch, capsys, stage):
    """Deferred minor 3: Ctrl-C before the scan loop must not traceback."""
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, stage, interrupt)
    status = cli.main(scan_args(tmp_path, "--csv", str(tmp_path / "o.csv")))
    captured = capsys.readouterr()
    assert status == 1
    assert "Traceback" not in captured.err
    assert "Interrupted" in captured.err


def test_invalid_regex_returns_1_with_one_line_error(tmp_path, capsys):
    """Deferred minor 5: a bad regex is a configuration error, not an exception dump."""
    bad = tmp_path / "bad.json"
    bad.write_text('{"PAN Pattern": {"X": {"regex": ["(unclosed"], "length": "16"}}}', encoding="utf-8")
    status = cli.main(scan_args(tmp_path, "--rgx-patterns", str(bad)))
    captured = capsys.readouterr()
    assert status == 1
    assert "Error:" in captured.err and "Exception Information" not in captured.out




def test_close_failure_does_not_mask_scan_error(tmp_path, monkeypatch, capsys):
    """Deferred minor 6: a failing sink close() must not replace the scan error."""
    def boom(self, path):
        raise ValueError("scan exploded")

    def bad_close(self):
        raise OSError("close exploded")

    monkeypatch.setattr(cli.Scanner, "scan_path", boom)
    monkeypatch.setattr(cli.Reporter, "close", bad_close)
    status = cli.main(scan_args(tmp_path))
    err = capsys.readouterr().err
    assert status == 1
    assert "scan exploded" in err


def test_console_encoding_never_drops_findings(tmp_path, monkeypatch, capsys):
    """Deferred minor 7: a cp1252 console must not turn U+FFFD into a logging error."""
    import io

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "a.txt").write_bytes(b"caf\xe9 " + PAN.encode() + b"\n")
    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding="cp1252", write_through=True)
    monkeypatch.setattr(sys, "stdout", console)
    status = cli.main(scan_args(tmp_path, "--verbose"))
    assert status == 0
    assert "Logging error" not in capsys.readouterr().err
    assert PAN in raw.getvalue().decode("cp1252")


@pytest.mark.parametrize("flag", ["--tar", "--tar-tmp"])
def test_removed_flags_are_rejected(flag, tmp_path, capsys):
    with pytest.raises(SystemExit) as info:
        cli.parse_args([flag, str(tmp_path)])
    assert info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_file_flag_takes_many_files_and_can_repeat():
    settings = cli.parse_args(["--file", "a", "b", "c", "--file", "d"])
    assert settings.files == ("a", "b", "c", "d")


def test_file_scans_only_the_listed_files(tmp_path, capsys):
    listed = tmp_path / "listed.txt"
    unlisted = tmp_path / "unlisted.txt"
    listed.write_text(f"card {PAN}\n", encoding="utf-8")
    unlisted.write_text("card 4012888888881881\n", encoding="utf-8")
    status = cli.main(["--file", str(listed), "--log-dir", str(tmp_path / "logs")])
    out = capsys.readouterr().out
    assert status == 0
    assert "PANs Matched  :        1" in out and "Scanned       :        1 Files." in out


def test_file_and_path_can_be_combined(tmp_path, capsys):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "in_dir.txt").write_text("card 4012888888881881\n", encoding="utf-8")
    listed = tmp_path / "listed.txt"
    listed.write_text(f"card {PAN}\n", encoding="utf-8")
    status = cli.main(["--file", str(listed), "--path", str(scan_dir), "--log-dir", str(tmp_path / "logs")])
    assert status == 0
    assert "PANs Matched  :        2" in capsys.readouterr().out


def test_missing_file_entry_is_reported_skipped_and_the_run_continues(tmp_path, capsys):
    good = tmp_path / "good.txt"
    good.write_text(f"card {PAN}\n", encoding="utf-8")
    folder = tmp_path / "folder"
    folder.mkdir()
    status = cli.main(["--file", str(tmp_path / "missing.txt"), str(folder), str(good),
                       "--log-dir", str(tmp_path / "logs")])
    captured = capsys.readouterr()
    assert status == 1                                   # a requested file was never scanned
    assert "missing.txt" in captured.err and "folder" in captured.err
    assert "PANs Matched  :        1" in captured.out    # processing did not stop
    assert "-- Skipped Files --" in captured.out
    assert "[NOT-FOUND]" in captured.out and "[NOT-A-FILE]" in captured.out


def test_archive_expanded_and_listed_in_summary(tmp_path, monkeypatch, capsys):
    import zipfile

    archive = tmp_path / "bundle.dat"        # content, not the extension, says zip
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("inner.txt", f"card {PAN}\n")
    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("needs a local unzip")
    monkeypatch.setattr(cli, "find_extractor_config_path", lambda: "unused")
    monkeypatch.setattr(cli, "load_extractor_config", lambda path: {
        "zip": {"command": unzip, "args": ["-o", "{archive}", "-d", "{tempdir}"]}})
    status = cli.main(["--file", str(archive), "--log-dir", str(tmp_path / "logs")])
    out = capsys.readouterr().out
    assert status == 0
    assert "PANs Matched  :        1" in out and "Archives expanded: 1" in out


def test_missing_extractor_tool_is_a_warning_listed_in_the_summary(tmp_path, monkeypatch, capsys):
    archive = tmp_path / "a.zip"
    archive.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    monkeypatch.setattr(cli, "find_extractor_config_path", lambda: "unused")
    monkeypatch.setattr(cli, "load_extractor_config", lambda path: {})
    status = cli.main(["--file", str(archive), "--log-dir", str(tmp_path / "logs")])
    captured = capsys.readouterr()
    assert status == 0                                    # a missing tool is a warning, not a failure
    assert "Warning:" in captured.err
    assert "[ARCHIVE-NO-TOOL]" in captured.out and "Archives skipped (no tool or failed): 1" in captured.out


def test_failing_extractor_tool_is_an_error_and_listed(tmp_path, monkeypatch, capsys):
    archive = tmp_path / "a.zip"
    archive.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    monkeypatch.setattr(cli, "find_extractor_config_path", lambda: "unused")
    monkeypatch.setattr(cli, "load_extractor_config", lambda path: {
        "zip": {"command": sys.executable, "args": ["-c", "import sys; sys.exit(3)"]}})
    status = cli.main(["--file", str(archive), "--log-dir", str(tmp_path / "logs")])
    captured = capsys.readouterr()
    assert status == 1
    assert "Error:" in captured.err
    assert "[ARCHIVE-FAILED]" in captured.out


def test_path_scan_expands_archives_found_in_the_directory(tmp_path, monkeypatch, capsys):
    import zipfile

    unzip = shutil.which("unzip")
    if unzip is None:
        pytest.skip("needs a local unzip")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    with zipfile.ZipFile(scan_dir / "bundle.zip", "w") as handle:
        handle.writestr("inner.txt", f"card {PAN}\n")
    monkeypatch.setattr(cli, "find_extractor_config_path", lambda: "unused")
    monkeypatch.setattr(cli, "load_extractor_config", lambda path: {
        "zip": {"command": unzip, "args": ["-o", "{archive}", "-d", "{tempdir}"]}})
    assert cli.main(["--path", str(scan_dir), "--log-dir", str(tmp_path / "logs")]) == 0
    assert "PANs Matched  :        1" in capsys.readouterr().out
