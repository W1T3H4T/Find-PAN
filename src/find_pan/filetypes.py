"""File-type checks used to decide whether a file is worth scanning."""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from find_pan.config import detect_archive_type

#   MIME types of executables and libraries that are never worth scanning.
EXECUTABLE_MIME_TYPES = (
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-shared-library",
    "application/x-pie-executable",
    "application/x-mach-binary",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-dylib",
)

_SAMPLE_SIZE = 1024
_TAR_HEADER_SIZE = 512


@lru_cache(maxsize=4)
def _detector(magic_module):
    """One libmagic instance per module, built on first use (it is expensive to construct)."""
    return magic_module.Magic(mime=True)


def read_head(file_path: str) -> bytes:
    """Return the first bytes of *file_path*.  ``OSError`` propagates."""
    with open(file_path, "rb") as handle:
        return handle.read(_SAMPLE_SIZE)


def is_executable(
    file_path: str, logger: logging.Logger, verbose: bool = False, head: bytes | None = None
) -> bool:
    """Return whether libmagic reports *file_path* as an executable.

    With *head* (the leading bytes already read) the file is not opened again.
    python-magic is imported lazily.  On Windows the import needs the native
    ``libmagic-1.dll``; if it is missing the interpreter may fail, and on
    Linux/macOS ``libmagic`` comes from the system package manager.  When the
    library is unavailable or fails, this returns False and callers fall back
    to the content heuristic in ``looks_binary``.
    """
    try:
        import magic  # pylint: disable=import-outside-toplevel
    except ImportError:
        logger.warning(
            "python-magic is not available; install the platform libmagic "
            "dependency to enable MIME-based binary skipping for %s",
            file_path,
        )
        return False

    try:
        if head is not None or os.path.isfile(file_path):
            detector = _detector(magic)
            file_type = detector.from_buffer(head) if head is not None else detector.from_file(file_path)
            logger.debug("MIME/Type: %s: %s", file_type, file_path)
            if any(mime_type in file_type for mime_type in EXECUTABLE_MIME_TYPES):
                if verbose:
                    logger.info("Skipped %s: %s", file_type, file_path)
                return True
    except PermissionError:
        logger.warning("Skipping file due to PermissionError: %s", file_path)
    except Exception as error:  # pylint: disable=broad-exception-caught
        logger.warning(
            "python-magic failed for %s (%s); using fallback binary detection.",
            file_path,
            error,
        )
    return False


#   Byte-order marks of UTF-16/32 text, which legitimately contains NUL bytes.
_TEXT_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")
#   Control bytes that do not occur in text (tab, LF, CR, FF and ESC are allowed).
_NON_TEXT_BYTES = frozenset(set(range(0, 32)) - {9, 10, 12, 13, 27})
_BINARY_RATIO = 0.30


def looks_binary(head: bytes) -> bool:
    """Return whether the leading bytes of a file look like binary data.

    A NUL byte makes it binary (unless a UTF-16/32 byte-order mark says the
    file is text); otherwise it is binary when more than 30% of the sample is
    non-text control bytes.  Latin-1 and other 8-bit text are not binary.
    """
    if not head or head.startswith(_TEXT_BOMS):
        return False
    if b"\x00" in head:
        return True
    return sum(1 for byte in head if byte in _NON_TEXT_BYTES) / len(head) > _BINARY_RATIO


class FileKind(Enum):
    """How the scanner should handle a file."""

    TEXT = "text"
    ARCHIVE = "archive"
    EXECUTABLE = "executable"
    BINARY = "binary"


@dataclass(frozen=True)
class FileClassification:
    """The result of ``classify``: what to do with a file, and why.

    ``archive_type`` is the extractor key (``tar``, ``zip``, ``7z``, ``gzip``,
    ``bzip2``, ``xz``) and is only set for archives.  ``note`` records a
    disagreement between the extension and the content.
    """

    kind: FileKind
    archive_type: str | None = None
    note: str = ""


#   Content signatures: (offset, bytes, format).  The tar "ustar" marker sits at offset 257.
_SIGNATURES = (
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"PK\x07\x08", "zip"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"\x1f\x8b\x08", "gzip"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (257, b"ustar", "tar"),
)
_BZIP2_BLOCK_MAGIC = b"1AY&SY"
_TAR_COMPRESSED = ("gzip", "bzip2", "xz")


def sniff_archive_format(head: bytes) -> str | None:
    """Return the archive format named by the file's leading bytes, or None.

    Only content is consulted.
    """
    for offset, signature, name in _SIGNATURES:
        if head[offset:offset + len(signature)] == signature:
            return name
    if head[:3] == b"BZh" and head[4:10] == _BZIP2_BLOCK_MAGIC:
        return "bzip2"
    return None


def classify(
    file_path: str, skip_binary: bool, logger: logging.Logger, verbose: bool = False
) -> FileClassification:
    """Open *file_path* once to read its head and classify it (see ``classify_head``).

    ``OSError`` propagates.
    """
    return classify_head(read_head(file_path), file_path, skip_binary, logger, verbose)


def classify_head(
    head: bytes, file_path: str, skip_binary: bool, logger: logging.Logger, verbose: bool = False
) -> FileClassification:
    """Decide how to handle a file from its leading bytes, trusting content over the extension.

    The extension is only a hint: it chooses between ``tar`` and a bare
    compressor for gzip/bzip2/xz data, and it triggers a note when it claims an
    archive the content does not confirm.  Archives take precedence over the
    binary and executable checks, which apply only with ``skip_binary``.  The
    file is never opened here, so a caller that already holds it open can
    classify and scan it with a single open.
    """
    hint = detect_archive_type(file_path)
    sniffed = sniff_archive_format(head)

    if sniffed is not None:
        archive_type = "tar" if (sniffed in _TAR_COMPRESSED and hint == "tar") else sniffed
        return FileClassification(FileKind.ARCHIVE, archive_type)

    note = ""
    if hint is not None:
        note = f"extension suggests a {hint} archive but the content is not one; scanning as a file"

    if skip_binary:
        if is_executable(file_path, logger, verbose, head=head):
            return FileClassification(FileKind.EXECUTABLE, note=note)
        if looks_binary(head):
            return FileClassification(FileKind.BINARY, note=note)
    return FileClassification(FileKind.TEXT, note=note)
