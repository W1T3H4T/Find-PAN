"""Tests for find_pan.filetypes.classify: content decides, the extension is a hint."""

import bz2
import gzip
import io
import logging
import lzma
import tarfile
import zipfile

import pytest

from find_pan import filetypes
from find_pan.filetypes import FileKind

LOGGER = logging.getLogger("test.classify")


def make_zip(path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.txt", "hello")


def make_tar(path, mode="w"):
    source = path.parent / "member.txt"
    source.write_text("hello", encoding="utf-8")
    with tarfile.open(path, mode) as archive:
        archive.add(source, arcname="member.txt")


def kind_of(path, skip_binary=False):
    return filetypes.classify(str(path), skip_binary, LOGGER)


@pytest.mark.parametrize("name, builder, expected", [
    ("a.zip", make_zip, "zip"),
    ("a.tar", make_tar, "tar"),
    ("a.tar.gz", lambda p: make_tar(p, "w:gz"), "tar"),
    ("a.tar.bz2", lambda p: make_tar(p, "w:bz2"), "tar"),
    ("a.tar.xz", lambda p: make_tar(p, "w:xz"), "tar"),
])
def test_archives_detected_by_content_with_matching_extension(tmp_path, name, builder, expected):
    target = tmp_path / name
    builder(target)
    result = kind_of(target)
    assert result.kind is FileKind.ARCHIVE and result.archive_type == expected


@pytest.mark.parametrize("builder, expected", [
    (make_zip, "zip"),
    (make_tar, "tar"),
    (lambda p: make_tar(p, "w:gz"), "gzip"),   # no extension hint: gzip expands to a tar, found next
])
def test_archive_detected_without_any_extension(tmp_path, builder, expected):
    target = tmp_path / "backup_blob"
    builder(target)
    result = kind_of(target)
    assert result.kind is FileKind.ARCHIVE and result.archive_type == expected


def test_single_file_gzip_detected(tmp_path):
    target = tmp_path / "dump.gz"
    target.write_bytes(gzip.compress(b"card 4556737586899855\n"))
    assert kind_of(target).archive_type == "gzip"


def test_seven_zip_and_bzip2_xz_signatures(tmp_path):
    seven = tmp_path / "x.7z"
    seven.write_bytes(bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) + b"\x00" * 40)
    assert kind_of(seven).archive_type == "7z"
    bzip = tmp_path / "plain.bz2"
    bzip.write_bytes(bz2.compress(b"hello"))
    assert kind_of(bzip).archive_type == "bzip2"
    xz = tmp_path / "plain.xz"
    xz.write_bytes(lzma.compress(b"hello"))
    assert kind_of(xz).archive_type == "xz"


def test_text_file_named_zip_is_not_trusted_as_an_archive(tmp_path):
    target = tmp_path / "notes.zip"
    target.write_text("just text 4556737586899855\n", encoding="utf-8")
    result = kind_of(target)
    assert result.kind is FileKind.TEXT
    assert "extension" in result.note and "zip" in result.note


def test_plain_text_is_text_without_note(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("hello\n", encoding="utf-8")
    result = kind_of(target)
    assert result.kind is FileKind.TEXT and result.note == ""


def test_empty_and_tiny_files_are_text(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    tiny = tmp_path / "tiny"
    tiny.write_bytes(b"PK")
    assert kind_of(empty).kind is FileKind.TEXT
    assert kind_of(tiny).kind is FileKind.TEXT


def test_archive_wins_over_binary_check(tmp_path, monkeypatch):
    monkeypatch.setattr(filetypes, "is_executable", lambda *a, **k: False)
    target = tmp_path / "a.zip"
    make_zip(target)
    assert kind_of(target, skip_binary=True).kind is FileKind.ARCHIVE


def test_binary_and_executable_only_classified_with_skip_binary(tmp_path, monkeypatch):
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"abc\x00def\xffghi" + b"x" * 20)
    monkeypatch.setattr(filetypes, "is_executable", lambda *a, **k: False)
    assert kind_of(binary, skip_binary=False).kind is FileKind.TEXT
    assert kind_of(binary, skip_binary=True).kind is FileKind.BINARY
    monkeypatch.setattr(filetypes, "is_executable", lambda *a, **k: True)
    assert kind_of(binary, skip_binary=True).kind is FileKind.EXECUTABLE


def test_unreadable_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        kind_of(tmp_path / "missing.bin")
