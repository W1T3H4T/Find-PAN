"""Archive extraction through external programs.

The extractor commands come from the YAML extractor configuration, so no
Python archive library (and none of its path-traversal pitfalls) is involved.
"""

import logging
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import fields, replace
from functools import lru_cache
from typing import Callable, Iterator

from find_pan.config import EXTRACTOR_CONFIG_FILENAME, detect_archive_type
from find_pan.errors import ExtractorError, ExtractorUnavailable, LimitExceeded
from find_pan.models import ExtractionLimits


_IS_WINDOWS = sys.platform == "win32"
#   How often the watchdog inspects a running extractor.
_POLL_SECONDS = 0.1
_MB = 1024 * 1024


def _tree_usage(directory: str) -> tuple[int, int]:
    """Return (total bytes, entry count) under *directory*, without following links."""
    total = count = 0
    pending = [directory]
    while pending:
        try:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    count += 1
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue          # vanished or unreadable while being written
        except OSError:
            continue
    return total, count


def _kill_tree(process: subprocess.Popen) -> None:
    """Kill the extractor and everything it started."""
    try:
        if _IS_WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                           capture_output=True, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    process.kill()
    process.wait()


def run_limited(cmd: list[str], directory: str, limits: ExtractionLimits) -> subprocess.CompletedProcess:
    """Run an extractor, stopping it if it exceeds *limits* on what it writes to *directory*.

    A watchdog polls the directory size, entry count, elapsed time and free
    disk space; on a breach the tool and its children are killed and
    ``LimitExceeded`` is raised.  A non-zero exit raises ``CalledProcessError``
    (like ``subprocess.run(check=True)``).  Output goes to temporary files, so
    a noisy tool can never block on a full pipe.
    """
    if shutil.disk_usage(directory)[2] < limits.min_free_bytes:
        raise LimitExceeded(f"free disk space is already below {limits.min_free_bytes // _MB} MB")

    with tempfile.TemporaryFile() as out_file, tempfile.TemporaryFile() as err_file:
        options = {"start_new_session": True} if not _IS_WINDOWS else {}
        process = subprocess.Popen(cmd, stdout=out_file, stderr=err_file, **options)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - started > limits.timeout_seconds:
                    raise LimitExceeded(f"extraction exceeded the time limit of {limits.timeout_seconds} seconds")
                total, count = _tree_usage(directory)
                if total > limits.max_extracted_bytes:
                    raise LimitExceeded(f"extracted data exceeded {limits.max_extracted_bytes // _MB} MB")
                if count > limits.max_files:
                    raise LimitExceeded(f"extracted file count exceeded {limits.max_files} files")
                if shutil.disk_usage(directory)[2] < limits.min_free_bytes:
                    raise LimitExceeded(f"free disk space fell below {limits.min_free_bytes // _MB} MB")
                time.sleep(_POLL_SECONDS)
        except BaseException:
            _kill_tree(process)
            raise

        out_file.seek(0)
        err_file.seek(0)
        stdout = out_file.read(65536).decode("utf-8", errors="replace")
        stderr = err_file.read(65536).decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, cmd, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, 0, stdout, stderr)
#   Characters of tool output kept in an error message (stderr can be huge or hostile).
_MAX_STDERR = 500


@lru_cache(maxsize=None)
def _is_gnu_tar(command_path: str) -> bool:
    """Return whether *command_path* is GNU tar (``tar --version`` says so)."""
    try:
        result = subprocess.run(
            [command_path, "--version"], capture_output=True, text=True, check=False, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "GNU tar" in result.stdout


def _needs_force_local(command_path: str, args: list[str]) -> bool:
    """GNU tar treats a drive letter as a remote host name; Windows paths need --force-local."""
    return (
        _IS_WINDOWS
        and os.path.splitext(os.path.basename(command_path))[0].lower() in ("tar", "gtar")
        and "--force-local" not in args
        and _is_gnu_tar(command_path)
    )


@contextmanager
def extract_archive(
    archive_path: str,
    extractor_config: dict[str, dict],
    logger: logging.Logger,
    archive_type: str | None = None,
    runner: Callable | None = None,
    verbose: bool = False,
    limits: ExtractionLimits | None = None,
) -> Iterator[str]:
    """Extract *archive_path* into a temporary directory and yield its path.

    The directory (created under the system temp directory) and its contents
    are always removed afterwards.  *archive_type* is the extractor key found
    by content detection; when omitted the file extension is used.

    Raises ``ExtractorUnavailable`` when no usable extractor exists (unknown
    type, no entry, incomplete entry, tool not installed) and ``ExtractorError``
    when the tool runs but fails.
    """
    archive_type = archive_type or detect_archive_type(archive_path)
    if archive_type is None:
        raise ExtractorUnavailable(f"Unsupported archive type: {archive_path}")

    extractor = extractor_config.get(archive_type)
    if not extractor:
        raise ExtractorUnavailable(
            f"No extractor configured for archive type '{archive_type}' ({archive_path}). "
            f"Run the setup script to build {EXTRACTOR_CONFIG_FILENAME}."
        )

    command = extractor.get("command")
    args_template = extractor.get("args", [])
    if not command or not args_template:
        raise ExtractorUnavailable(
            f"Incomplete extractor configuration for '{archive_type}': missing command or args."
        )

    #   Per-extractor values in the YAML override the global limits.
    limits = replace(
        limits or ExtractionLimits(),
        **{field.name: extractor[field.name] for field in fields(ExtractionLimits) if field.name in extractor},
    )
    temp_dir = tempfile.mkdtemp(prefix="find-pan-")
    if runner is None:
        runner = lambda cmd, **_: run_limited(cmd, temp_dir, limits)    # noqa: E731
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
            #   Absolute, so a relative name such as "-evil.zip" can never look like an option.
            archive_for_extractor = os.path.abspath(archive_path)

        command_path = shutil.which(command) or command
        archive_arg, tempdir_arg = archive_for_extractor, temp_dir
        force_local = _needs_force_local(command_path, args_template)
        if force_local:
            #   MSYS-based GNU tar also rejects backslashes in these paths.
            archive_arg, tempdir_arg = archive_arg.replace("\\", "/"), tempdir_arg.replace("\\", "/")
        #   Plain substitution, not str.format: other braces in an argument are literal text.
        args = [arg.replace("{archive}", archive_arg).replace("{tempdir}", tempdir_arg) for arg in args_template]
        if force_local:
            args.insert(0, "--force-local")
        cmd = [command_path] + args
        if verbose:
            logger.info("Extractor command: %s", " ".join(cmd))

        partial_failure = None
        try:
            runner(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            stderr = (error.stderr or "")[:_MAX_STDERR]
            message = f"Extractor failed for {archive_path}: {error} (stderr: {stderr})"
            if not os.listdir(temp_dir):
                raise ExtractorError(message) from error
            #   Tools such as tar and unzip exit non-zero after extracting when a member
            #   was unsafe or damaged.  Scan what was extracted, then report the failure.
            partial_failure = ExtractorError(
                message + " [partial extraction: the extracted members were scanned]"
            )
        except LimitExceeded as error:
            message = f"Extractor stopped for {archive_path}: {error}"
            if not os.listdir(temp_dir):
                raise ExtractorError(message) from error
            partial_failure = ExtractorError(
                message + " [partial extraction: the extracted members were scanned]"
            )
        except FileNotFoundError as error:
            raise ExtractorUnavailable(
                f"Extractor command not found: {command}. "
                f"Update {EXTRACTOR_CONFIG_FILENAME} with the correct path."
            ) from error

        yield temp_dir
        if partial_failure is not None:
            raise partial_failure
    finally:
        try:
            shutil.rmtree(temp_dir)
            logger.info("Cleaned up temporary extraction directory: %s", temp_dir)
        except OSError as error:
            logger.warning("Could not remove temporary extraction directory %s: %s", temp_dir, error)
