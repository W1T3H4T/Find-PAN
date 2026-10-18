"""Regression tests against the real archive fixtures in RegressionTests/.

ZIP_Test.zip, TAR_Test.tar and 7z_Test.7z each contain the same text files, and
the same files sit next to them, so scanning an archive must find exactly as many
PANs as scanning those plain files.  Other fixtures in RegressionTests/ (added at
any time) are not in the archives and are left out of the comparison.  The tests use the real extraction tools from the
default extractor configuration and skip when a tool is not installed.
"""

import os
import re
import shutil
import tarfile
from pathlib import Path

import pytest

from find_pan import cli
from find_pan.config import detect_archive_type, extractor_candidates, find_extractor_config_path, load_extractor_config

FIXTURES = Path(__file__).resolve().parents[1] / "RegressionTests"
ARCHIVES = ["ZIP_Test.zip", "TAR_Test.tar", "7z_Test.7z"]


def archived_fixtures() -> list[Path]:
    """The plain fixtures that the archives contain, named by TAR_Test.tar (readable without any tool)."""
    with tarfile.open(FIXTURES / "TAR_Test.tar") as handle:
        names = {Path(member.name).name for member in handle.getmembers() if member.isfile()}
    return sorted(FIXTURES / name for name in names if (FIXTURES / name).is_file())


def pans_matched(output: str) -> int:
    return int(re.search(r"PANs Matched  :\s+(\d+)", output).group(1))


def run(tmp_path, capsys, *arguments) -> tuple[int, str]:
    status = cli.main([*arguments, "--log-dir", str(tmp_path / "logs")])
    return status, capsys.readouterr().out


def require_extractor(archive: Path) -> None:
    entry = load_extractor_config(find_extractor_config_path()).get(detect_archive_type(str(archive)), {})
    commands = [c["command"] for c in extractor_candidates(entry)]
    if not any(shutil.which(os.path.expandvars(command)) for command in commands):
        pytest.skip(f"no extractor for {archive.name} is installed (tried {', '.join(commands)})")


@pytest.fixture
def plain_count(tmp_path, capsys):
    """PANs found in the plain text fixtures (no archives)."""
    plain = tmp_path / "plain"
    plain.mkdir()
    for source in archived_fixtures():
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
    for source in [*archived_fixtures(), *(FIXTURES / name for name in ARCHIVES)]:
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
