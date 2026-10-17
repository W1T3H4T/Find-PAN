"""File-type checks used to decide whether a file is worth scanning."""

import logging
import os

from find_pan.models import SkipReason

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


def is_executable(file_path: str, logger: logging.Logger, verbose: bool = False) -> bool:
    """Return whether libmagic reports *file_path* as an executable.

    python-magic is imported lazily.  On Windows the import needs the native
    ``libmagic-1.dll``; if it is missing the interpreter may fail, and on
    Linux/macOS ``libmagic`` comes from the system package manager.  When the
    library is unavailable or fails, this returns False and callers fall back
    to the null-byte heuristic in ``has_binary_content``.
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
        if os.path.isfile(file_path):
            file_type = magic.Magic(mime=True).from_file(file_path)
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


def has_binary_content(file_path: str) -> bool:
    """Return whether the start of the file contains both NUL and 0xFF bytes.

    The last two sampled bytes are ignored.  ``OSError`` propagates.
    """
    with open(file_path, "rb") as handle:
        sample = handle.read(_SAMPLE_SIZE)[:-2]
    return 0x00 in sample and 0xFF in sample


def skip_reason(
    file_path: str, skip_binary: bool, logger: logging.Logger, verbose: bool = False
) -> SkipReason | None:
    """Return why *file_path* should be skipped, or None to scan it."""
    if not skip_binary:
        return None
    if is_executable(file_path, logger, verbose):
        return SkipReason.EXECUTABLE
    try:
        if has_binary_content(file_path):
            return SkipReason.BINARY
    except OSError as error:
        logger.warning("Error reading file: %s - %s", file_path, error)
    return None
