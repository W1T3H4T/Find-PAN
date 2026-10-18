"""Real extractions with every tar build the shipped Windows configuration knows about.

Git for Windows ships an MSYS GNU tar (rejects backslashes), GnuWin32 ships a native GNU tar 1.13
(rejects forward-slash drive paths, cannot read PAX headers) and Windows 10+ has bsdtar in System32.
No single command line suits them all, which is why the shipped configuration lists one candidate
per build, each with its own arguments.  Every candidate whose tool is installed is run for real,
on its own, so a wrong argument for any one build fails here.  (On other systems this module is not
collected, see collect_ignore in conftest.py.)
"""

import logging
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

import pytest

from find_pan import archives, config

LOGGER = logging.getLogger("test.tar")
ROOT = Path(__file__).resolve().parents[1]

#   The shipped Windows tar candidates whose tool is installed here, keyed by a readable name.
CANDIDATES = {
    c["command"]: c
    for c in config.extractor_candidates(config.DEFAULT_EXTRACTORS["tar"], "windows")
    if shutil.which(os.path.expandvars(c["command"]))
}
#   "tar" on PATH is a candidate too, but which build it is depends on the machine; the others cover them.
INSTALLED = sorted(name for name, c in CANDIDATES.items() if c["command"] != "tar")


def only(candidate):
    """A configuration whose only tar candidate is *candidate*, so that exact build is the one used."""
    return {"tar": {"windows": [candidate]}}


@pytest.fixture(autouse=True)
def windows_platform(monkeypatch):
    monkeypatch.setattr(config, "platform_key", lambda system=None: "windows")


@pytest.fixture
def tar_archive(tmp_path):
    member = tmp_path / "member.txt"
    member.write_text("card 4556737586899855\n", encoding="utf-8")
    nested = tmp_path / "sub dir"                     # a space in the path, too
    nested.mkdir()
    path = nested / "archive.tar"
    #   Classic GNU format: Python 3.14 defaults to PAX, which GnuWin32's tar 1.13 cannot read.
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as handle:
        handle.add(member, arcname="member.txt")
        handle.add(member, arcname="deep/er/member2.txt")
    return path


def test_the_shipped_configuration_has_a_candidate_for_each_installed_tar():
    assert INSTALLED, "no Windows tar candidate is installed on this machine"


@pytest.mark.parametrize("flavor", INSTALLED)
def test_every_installed_tar_extracts_an_archive(flavor, tar_archive):
    with archives.extract_archive(str(tar_archive), only(CANDIDATES[flavor]), LOGGER) as directory:
        names = sorted(p.relative_to(directory).as_posix() for p in Path(directory).rglob("*") if p.is_file())
    assert names == ["deep/er/member2.txt", "member.txt"]


@pytest.mark.parametrize("flavor", INSTALLED)
def test_a_relative_archive_path_works_with_every_installed_tar(flavor, tar_archive, monkeypatch):
    """The reported failure: find-pan.py --file .\\RegressionTests\\TAR_Test.tar from PowerShell."""
    monkeypatch.chdir(tar_archive.parent.parent)
    relative = ".\\" + str(Path(tar_archive.parent.name) / tar_archive.name)
    with archives.extract_archive(relative, only(CANDIDATES[flavor]), LOGGER) as directory:
        assert (Path(directory) / "member.txt").read_text(encoding="utf-8").startswith("card 4556")


@pytest.mark.parametrize("flavor", INSTALLED)
def test_archive_outside_the_system_temp_directory(flavor, tmp_path):
    """MSYS tar resolves '..' through its /tmp mount, so a relative path going up from the real system
    temp directory led into Git's own tree; the archive here lives in the repository, outside Temp."""
    member = tmp_path / "member.txt"
    member.write_text("card 4556737586899855\n", encoding="utf-8")
    work = Path(tempfile.mkdtemp(prefix="tar-flavor-", dir=ROOT))
    try:
        archive = work / "archive.tar"
        with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as handle:
            handle.add(member, arcname="member.txt")
        with archives.extract_archive(str(archive), only(CANDIDATES[flavor]), LOGGER) as directory:
            assert (Path(directory) / "member.txt").is_file()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_the_default_candidate_order_picks_a_working_tar(tar_archive):
    """What a user gets with no customization: the first installed candidate in the shipped list."""
    with archives.extract_archive(str(tar_archive), config.DEFAULT_EXTRACTORS, LOGGER) as directory:
        assert (Path(directory) / "member.txt").is_file()
