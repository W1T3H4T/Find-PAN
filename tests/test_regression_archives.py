"""Regression tests against the real archive fixtures in RegressionTests/.

ZIP_Test.zip, TAR_Test.tar and 7z_Test.7z each contain the same 13 text files
that sit next to them, so scanning an archive must find exactly as many PANs as
scanning the plain files.  The tests use the real extraction tools from the
default extractor configuration and skip when a tool is not installed.
"""

import re
import shutil
from pathlib import Path

import pytest

from find_pan import cli
from find_pan.config import detect_archive_type, find_extractor_config_path, load_extractor_config

FIXTURES = Path(__file__).resolve().parents[1] / "RegressionTests"
ARCHIVES = ["ZIP_Test.zip", "TAR_Test.tar", "7z_Test.7z"]


def pans_matched(output: str) -> int:
    return int(re.search(r"PANs Matched  :\s+(\d+)", output).group(1))


def run(tmp_path, capsys, *arguments) -> tuple[int, str]:
    status = cli.main([*arguments, "--log-dir", str(tmp_path / "logs")])
    return status, capsys.readouterr().out


def require_extractor(archive: Path) -> None:
    config = load_extractor_config(find_extractor_config_path())
    command = config.get(detect_archive_type(str(archive)), {}).get("command")
    if not command or shutil.which(command) is None:
        pytest.skip(f"extractor {command!r} for {archive.name} is not installed")


@pytest.fixture
def plain_count(tmp_path, capsys):
    """PANs found in the plain text fixtures (no archives)."""
    plain = tmp_path / "plain"
    plain.mkdir()
    for source in FIXTURES.glob("*.txt"):
        shutil.copy(source, plain / source.name)
    status, output = run(tmp_path, capsys, "--path", str(plain))
    assert status == 0
    count = pans_matched(output)
    assert count > 0
    return count


@pytest.mark.parametrize("name", ARCHIVES)
def test_archive_yields_the_same_pans_as_the_plain_files(name, tmp_path, capsys, plain_count):
    archive = FIXTURES / name
    require_extractor(archive)
    status, output = run(tmp_path, capsys, "--file", str(archive))
    assert status == 0
    assert pans_matched(output) == plain_count
    assert "Archives expanded: 1" in output
    assert "-- Skipped Files --" not in output


def test_path_scan_expands_every_archive_found(tmp_path, capsys, plain_count):
    for name in ARCHIVES:
        require_extractor(FIXTURES / name)
    #   Scan a copy: RegressionTests/ also holds the baseline CSVs, which contain card numbers too.
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for source in [*FIXTURES.glob("*.txt"), *(FIXTURES / name for name in ARCHIVES)]:
        shutil.copy(source, fixtures / source.name)
    status, output = run(tmp_path, capsys, "--path", str(fixtures))
    assert status == 0
    assert pans_matched(output) == plain_count * (1 + len(ARCHIVES))
    assert f"Archives expanded: {len(ARCHIVES)}" in output


def test_archive_is_recognized_by_content_not_by_extension(tmp_path, capsys, plain_count):
    source = FIXTURES / "ZIP_Test.zip"
    require_extractor(source)
    disguised = tmp_path / "quarterly-report.txt"       # a zip pretending to be text
    shutil.copy(source, disguised)
    status, output = run(tmp_path, capsys, "--file", str(disguised))
    assert status == 0
    assert pans_matched(output) == plain_count
    assert "Archives expanded: 1" in output


def test_fixture_listing_reports_what_it_skipped(tmp_path, capsys):
    status, output = run(tmp_path, capsys, "--file", str(tmp_path / "nope.zip"), str(FIXTURES / "VISA.txt"))
    assert status == 1
    assert "[NOT-FOUND]" in output and "PANs Matched" in output
