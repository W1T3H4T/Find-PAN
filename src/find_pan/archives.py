"""Archive extraction through external programs.

The extractor commands come from the YAML extractor configuration, so no
Python archive library (and none of its path-traversal pitfalls) is involved.
"""

import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Callable, Iterator

from find_pan.config import EXTRACTOR_CONFIG_FILENAME, detect_archive_type
from find_pan.errors import ExtractorError


@contextmanager
def extract_archive(
    archive_path: str,
    extractor_config: dict[str, dict],
    tar_tmp: str,
    logger: logging.Logger,
    runner: Callable = subprocess.run,
    verbose: bool = False,
) -> Iterator[str]:
    """Extract *archive_path* into a temporary directory and yield its path.

    The directory and its contents are always removed afterwards.  Raises
    ``ExtractorError`` for an unsupported type, a missing or incomplete
    extractor configuration, a missing command, or a failing extraction.
    """
    archive_type = detect_archive_type(archive_path)
    if archive_type is None:
        raise ExtractorError(f"Unsupported archive type: {archive_path}")

    extractor = extractor_config.get(archive_type)
    if not extractor:
        raise ExtractorError(
            f"No extractor configured for archive type '{archive_type}' ({archive_path}). "
            f"Run the setup script to build {EXTRACTOR_CONFIG_FILENAME}."
        )

    command = extractor.get("command")
    args_template = extractor.get("args", [])
    if not command or not args_template:
        raise ExtractorError(
            f"Incomplete extractor configuration for '{archive_type}': missing command or args."
        )

    if tar_tmp:
        os.makedirs(tar_tmp, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="find-pan-", dir=tar_tmp or None)
    try:
        logger.info("Archive Scan: extracting %s as %s into %s ...", archive_path, archive_type, temp_dir)

        if extractor.get("copy_archive_to_tempdir", False):
            #   gzip and similar in-place decompressors need the archive inside
            #   the temp directory so the result lands there as well.
            archive_for_extractor = os.path.join(temp_dir, os.path.basename(archive_path))
            try:
                shutil.copy2(archive_path, archive_for_extractor)
            except OSError as error:
                raise ExtractorError(f"Cannot copy {archive_path} for extraction: {error}") from error
        else:
            archive_for_extractor = archive_path

        cmd = [shutil.which(command) or command] + [
            arg.format(archive=archive_for_extractor, tempdir=temp_dir) for arg in args_template
        ]
        if verbose:
            logger.info("Extractor command: %s", " ".join(cmd))

        try:
            runner(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            raise ExtractorError(
                f"Extractor failed for {archive_path}: {error} (stderr: {error.stderr})"
            ) from error
        except FileNotFoundError as error:
            raise ExtractorError(
                f"Extractor command not found: {command}. "
                f"Update {EXTRACTOR_CONFIG_FILENAME} with the correct path."
            ) from error

        yield temp_dir
    finally:
        try:
            shutil.rmtree(temp_dir)
            logger.info("Cleaned up temporary extraction directory: %s", temp_dir)
        except OSError as error:
            logger.warning("Could not remove temporary extraction directory %s: %s", temp_dir, error)
