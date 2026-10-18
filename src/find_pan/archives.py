"""Archive extraction through external programs.

The extractor commands come from the YAML extractor configuration, so no
Python archive library (and none of its path-traversal pitfalls) is involved.
"""

import logging
import os
import re
import signal
import stat
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import fields, replace
from typing import Callable, Iterator

from find_pan import config
from find_pan.config import EXTRACTOR_CONFIG_FILENAME, detect_archive_type
from find_pan.errors import ExtractorError, ExtractorUnavailable, LimitExceeded
from find_pan.models import ExtractionLimits


_IS_WINDOWS = sys.platform == "win32"
#   How often the watchdog inspects a running extractor, and the shortest interval it will use
#   when a limit is close (a fast disk can write a lot in 100 ms).
_POLL_SECONDS = 0.1
_MIN_POLL_SECONDS = 0.005
#   Worst-case write speeds assumed when sizing the poll delay (fast NVMe or tmpfs).
_ASSUMED_BYTES_PER_SECOND = 2 * 1024 * 1024 * 1024
_ASSUMED_FILES_PER_SECOND = 200_000
_MB = 1024 * 1024
#   Characters of tool output kept in an error message (stderr can be huge or hostile).
_MAX_STDERR = 500


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


def _make_writable_and_retry(function, path, _error) -> None:
    """rmtree error handler: clear read-only flags (extracted members keep their permissions) and retry."""
    parent = os.path.dirname(path)
    os.chmod(parent, stat.S_IRWXU)
    os.chmod(path, stat.S_IRWXU)
    function(path)


def _remove_tree(directory: str) -> None:
    """Delete an extraction directory even when it holds read-only files or directories."""
    if sys.version_info >= (3, 12):
        shutil.rmtree(directory, onexc=_make_writable_and_retry)
    else:
        shutil.rmtree(directory, onerror=_make_writable_and_retry)


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


def _next_poll_delay(
    limits: ExtractionLimits, previous: tuple[float, int, int] | None, now: float, total: int, count: int
) -> float:
    """Return how long the watchdog should wait before looking again.

    Normally ``_POLL_SECONDS``.  The first look comes at once.  Otherwise the delay is half the
    time the tool would need to reach a byte or file-count limit at the fastest rate seen so far
    or the assumed worst-case disk speed, whichever is higher, so the remaining headroom is at
    least halved at each look and the final overshoot is bounded by about ``_MIN_POLL_SECONDS``
    of writing.  A tool that is idle now and bursts later is covered by the assumed rates.
    *previous* is the (time, bytes, entries) of the last look.
    """
    if previous is None:
        return _MIN_POLL_SECONDS
    elapsed = now - previous[0]
    byte_rate, file_rate = _ASSUMED_BYTES_PER_SECOND, _ASSUMED_FILES_PER_SECOND
    if elapsed > 0:
        byte_rate = max(byte_rate, (total - previous[1]) / elapsed)
        file_rate = max(file_rate, (count - previous[2]) / elapsed)
    delay = min(
        _POLL_SECONDS,
        (limits.max_extracted_bytes - total) / byte_rate / 2,
        (limits.max_files - count) / file_rate / 2,
    )
    return max(_MIN_POLL_SECONDS, delay)


def run_limited(cmd: list[str], directory: str, limits: ExtractionLimits,
                cwd: str | None = None) -> subprocess.CompletedProcess:
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
        process = subprocess.Popen(cmd, stdout=out_file, stderr=err_file, cwd=cwd, **options)
        started = time.monotonic()
        previous = None
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
                now = time.monotonic()
                time.sleep(_next_poll_delay(limits, previous, now, total, count))
                previous = (now, total, count)
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


def select_candidate(candidates: list[dict]) -> tuple[dict, str]:
    """Return ``(candidate, command_path)`` for the first candidate whose command exists.

    ``%VAR%`` / ``$VAR`` in a command are expanded first.  When none exists, the first candidate is
    returned with its (expanded) command unchanged, so the failure is reported once, by the attempt
    to run it, listing every command that was tried.
    """
    for candidate in candidates:
        resolved = shutil.which(os.path.expandvars(candidate["command"]))
        if resolved:
            return candidate, resolved
    first = candidates[0]
    return first, os.path.expandvars(first["command"])


_PLACEHOLDER = re.compile(r"\{(archive_posix|tempdir_posix|archive|tempdir)\}")


def fill_placeholders(argument: str, values: dict[str, str]) -> str:
    """Substitute ``{archive}``, ``{tempdir}`` and their ``_posix`` forms in one pass.

    Not ``str.format`` (other braces are literal text) and not repeated replacement (a path that
    happens to contain ``{tempdir}`` is never expanded again).
    """
    return _PLACEHOLDER.sub(lambda match: values[match.group(1)], argument)


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

    entry = extractor_config.get(archive_type)
    if not entry:
        raise ExtractorUnavailable(
            f"No extractor configured for archive type '{archive_type}' ({archive_path}). "
            f"Run the setup script to build {EXTRACTOR_CONFIG_FILENAME}."
        )

    configured = config.extractor_candidates(entry)
    candidates = [c for c in configured if c.get("command") and c.get("args")]
    if not candidates:
        if configured:
            raise ExtractorUnavailable(
                f"Incomplete extractor configuration for '{archive_type}': missing command or args."
            )
        raise ExtractorUnavailable(
            f"No extractor configured for archive type '{archive_type}' on this platform "
            f"({config.platform_key()}) ({archive_path}). Add one to {EXTRACTOR_CONFIG_FILENAME}."
        )

    extractor, command_path = select_candidate(candidates)
    command = extractor["command"]
    tried = ", ".join(candidate["command"] for candidate in candidates)
    args_template = extractor["args"]

    #   Per-extractor (or per-candidate) values in the YAML override the global limits.
    limits = replace(
        limits or ExtractionLimits(),
        **{field.name: extractor[field.name] for field in fields(ExtractionLimits) if field.name in extractor},
    )
    temp_dir = tempfile.mkdtemp(prefix="find-pan-")
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

        values = {
            "archive": archive_for_extractor,
            "tempdir": temp_dir,
            "archive_posix": archive_for_extractor.replace("\\", "/"),
            "tempdir_posix": temp_dir.replace("\\", "/"),
        }
        args = [fill_placeholders(argument, values) for argument in args_template]
        cmd = [command_path] + args
        #   "cwd: tempdir" runs the tool inside the extraction directory (see the Windows tar candidates).
        work_dir = temp_dir if extractor.get("cwd") == "tempdir" else None
        if runner is None:
            runner = lambda cmd, **_: run_limited(cmd, temp_dir, limits, cwd=work_dir)    # noqa: E731
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
                f"Extractor command not found: {tried}. "
                f"Update {EXTRACTOR_CONFIG_FILENAME} with the correct path."
            ) from error

        yield temp_dir
        if partial_failure is not None:
            raise partial_failure
    finally:
        try:
            _remove_tree(temp_dir)
            logger.info("Cleaned up temporary extraction directory: %s", temp_dir)
        except OSError as error:
            logger.warning("Could not remove temporary extraction directory %s: %s", temp_dir, error)
