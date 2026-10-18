"""Real extractions with every flavor of tar found on Windows.

Git for Windows ships an MSYS GNU tar (rejects backslashes), GnuWin32 ships a native GNU tar 1.13
(rejects forward-slash drive paths) and Windows 10+ has bsdtar in System32.  No absolute path
suits all of them, so find-pan runs GNU tar inside the extraction directory with relative,
drive-free arguments.  Each flavor that is installed is exercised for real.
"""

import logging
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

from find_pan import archives

LOGGER = logging.getLogger("test.tar")

CANDIDATES = {
    "git-msys-gnu-tar": r"C:\Program Files\Git\usr\bin\tar.exe",
    "gnuwin32-gnu-tar": r"C:\Program Files (x86)\GnuWin32\bin\tar.exe",
    "windows-bsdtar": r"C:\Windows\System32\tar.exe",
}
#   Only the builds installed on this machine are tested (on other systems this module is not collected,
#   see collect_ignore in conftest.py), so no test needs to skip.
INSTALLED = sorted(name for name, location in CANDIDATES.items() if Path(location).exists())


@pytest.fixture
def tar_archive(tmp_path):
    member = tmp_path / "member.txt"
    member.write_text("card 4556737586899855\n", encoding="utf-8")
    nested = tmp_path / "sub dir"                     # a space in the path, too
    nested.mkdir()
    path = nested / "archive.tar"
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as handle:
        handle.add(member, arcname="member.txt")
        handle.add(member, arcname="deep/er/member2.txt")
    return path


@pytest.mark.parametrize("flavor", INSTALLED)
def test_every_installed_tar_extracts_an_archive(flavor, tar_archive, tmp_path, monkeypatch):
    executable = Path(CANDIDATES[flavor])
    archives._is_gnu_tar.cache_clear()
    config = {"tar": {"command": str(executable), "args": ["-xf", "{archive}", "-C", "{tempdir}"]}}
    with archives.extract_archive(str(tar_archive), config, LOGGER) as directory:
        names = sorted(p.relative_to(directory).as_posix() for p in Path(directory).rglob("*") if p.is_file())
    assert names == ["deep/er/member2.txt", "member.txt"]


@pytest.mark.parametrize("flavor", INSTALLED)
def test_a_relative_archive_path_works_with_every_installed_tar(flavor, tar_archive, tmp_path, monkeypatch):
    """The user's failing case: find-pan.py --file .\\RegressionTests\\TAR_Test.tar from PowerShell."""
    executable = Path(CANDIDATES[flavor])
    archives._is_gnu_tar.cache_clear()
    monkeypatch.chdir(tar_archive.parent.parent)
    relative = ".\\" + str(Path(tar_archive.parent.name) / tar_archive.name)
    config = {"tar": {"command": str(executable), "args": ["-xf", "{archive}", "-C", "{tempdir}"]}}
    with archives.extract_archive(relative, config, LOGGER) as directory:
        assert (Path(directory) / "member.txt").read_text(encoding="utf-8").startswith("card 4556")


@pytest.mark.parametrize("flavor", INSTALLED)
def test_archive_outside_the_system_temp_directory(flavor, tmp_path):
    """Regression: MSYS tar resolves '..' through its /tmp mount, so a relative path going up from the real
    system temp directory led into Git's own tree and the archive was reported as not found."""
    executable = Path(CANDIDATES[flavor])
    archives._is_gnu_tar.cache_clear()
    member = tmp_path / "member.txt"
    member.write_text("card 4556737586899855\n", encoding="utf-8")
    work = Path(tempfile.mkdtemp(prefix="tar-flavor-", dir=Path(__file__).resolve().parents[1]))   # in the repo
    try:
        archive = work / "archive.tar"
        with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as handle:
            handle.add(member, arcname="member.txt")
        config = {"tar": {"command": str(executable), "args": ["-xf", "{archive}", "-C", "{tempdir}"]}}
        with archives.extract_archive(str(archive), config, LOGGER) as directory:   # default system temp dir
            assert (Path(directory) / "member.txt").is_file()
    finally:
        shutil.rmtree(work, ignore_errors=True)
