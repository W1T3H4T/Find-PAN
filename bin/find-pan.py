#!/usr/bin/env -S uv run python
##  ===========================================================================
##  File    :   Find-PAN.py
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   This script scans a file system or archive file for Primary Account
##              Number (PAN) and Track Data patterns using regular expressions.
##              It supports logging, process time tracking, and secure file 
##              deletion.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================

import argparse
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from pan_config import (
    EXTRACTOR_CONFIG_FILENAME,
    compile_regex_patterns,
    compile_regex_patterns_with_prefix,
    detect_archive_type,
    find_extractor_config_path,
    find_json_regex_config,
    load_extractor_config,
    load_json_data,
)

# ===========================================================================
# Disable some pylint warnings
# ===========================================================================
# pylint: disable=too-many-positional-arguments,too-many-arguments
# pylint: disable=possibly-used-before-assignment
# pylint: disable=broad-exception-caught
# pylint: disable=global-statement

# ===========================================================================
# Global variables
# ===========================================================================
_LastReportDelta = 0
_StartTime = 0
_TotalTime = 0
_AverageTime = 0
_ArgParse = {}
_Args = {}

# - Semantic Version Information
_FindPANVersion = "2 3 1"  # Major, Minor, Patch

# - Item Count Array
_MatchCount = defaultdict(int)

#   Regex Pattern Prefix
_RegexPatternPrefix = r"[ '\"{]"

#   Use custom argparse for Visual Studio Debug
_EnableVSArgParams = False

# - Loggers for Trace log and std Log file
_TraceLogObj = None
_DefaultLogObj = None

# - CSV output handle and writer (opened lazily when --csv is requested)
_CsvFileObj = None
_CsvWriter = None


# ===========================================================================
# Print consolidated exception info
# ===========================================================================
def print_exception_info(e: object) -> None:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_stack = traceback.extract_tb(exc_traceback)

    if tb_stack:
        # The innermost frame is where the exception was actually raised.
        frame = tb_stack[-1]
        file_name = frame.filename
        line_number = frame.lineno
        func_name = frame.name
    else:
        file_name = "<unknown>"
        line_number = 0
        func_name = "<unknown>"

    exception_message = str(exc_value) if exc_value is not None else ""
    extra_info = str(e) if e is not None else ""

    print("\nException Information:")
    print("-----------------------------------------------------------------")
    print(f"Function: '{func_name}', on line {line_number}")
    print(f"File    : {file_name}")
    print(f"Type    : {exc_type.__name__ if exc_type else 'Unknown'}")
    print(f"Message : {exception_message}")
    if extra_info and extra_info.lower() != exception_message.lower():
        print(f"Info    : {extra_info}")
    print("-----------------------------------------------------------------")
    sys.exit(1)


# ===========================================================================
# Handle keyboard interrupt
# ===========================================================================
def handle_interrupt(sig: int, frame: object) -> None:
    # Log the signal number
    _TraceLogObj.error("KeyboardInterrupt caught (signal number: %s). Exiting.", sig)

    # Log the stack frame details
    _TraceLogObj.debug("Stack frame at the time of interrupt:")
    _TraceLogObj.debug("".join(traceback.format_stack(frame)))

    print_scan_summary()
    sys.exit(1)


# ===========================================================================
# Set the logfile basename
# ===========================================================================
def generate_logfile_name(basename: str) -> str:
    date_str = datetime.now().strftime("%d%b%Y")
    formatted_basename = f"{basename}-{date_str}.log"
    return formatted_basename


# ===========================================================================
# Create our log file names
# ===========================================================================
def set_log_directory_and_filenames() -> tuple[str, str]:
    pan_logfile = ""
    trace_logfile = ""
    try:
        if not os.path.exists(_Args.log_dir):
            os.makedirs(_Args.log_dir)

        if not os.path.exists(_Args.tar_tmp):
            os.makedirs(_Args.tar_tmp)

        pan_logfile = os.path.join(_Args.log_dir, generate_logfile_name("Find-PAN"))
        trace_logfile = os.path.join(
            _Args.log_dir, generate_logfile_name("Find-PAN-trace")
        )

    except Exception as e:
        print_exception_info(e)
    return pan_logfile, trace_logfile


# ===========================================================================
# Create our logging objects
# ===========================================================================
def setup_custom_loggers() -> Dict[str, logging.Logger]:
    pan_logfile, trace_logfile = set_log_directory_and_filenames()

    #   Remove pre-existing log files
    if os.path.exists(pan_logfile):
        os.remove(pan_logfile)
    if os.path.exists(trace_logfile):
        os.remove(trace_logfile)

    # Trace Logger
    trace_logger = logging.getLogger("_TraceLogObj")
    trace_level = logging.DEBUG if _Args.debug else logging.INFO
    trace_logger.setLevel(trace_level)
    # Trace Console Handler (for stdout)
    trace_console_handler = logging.StreamHandler(sys.stdout)

    trace_formatter = logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s")

    if trace_console_handler:
        trace_console_handler.setLevel(trace_level)
        trace_console_handler.setFormatter(trace_formatter)
        trace_logger.addHandler(trace_console_handler)

    #   The file handler is only used inside the try block, so correctness no
    #   longer depends on print_exception_info() terminating the process.
    try:
        trace_file_handler = logging.FileHandler(trace_logfile)
        trace_file_handler.setLevel(trace_level)
        trace_file_handler.setFormatter(trace_formatter)
        trace_logger.addHandler(trace_file_handler)
    except FileNotFoundError:
        print_exception_info(None)
    except Exception as e:
        print_exception_info(e)

    # PAN Logger
    pan_logger = logging.getLogger("_DefaultLogObj")
    pan_logger.setLevel(logging.DEBUG)

    log_file_handler = logging.FileHandler(pan_logfile)
    log_file_handler.setLevel(logging.DEBUG)

    log_formatter = logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s")
    log_file_handler.setFormatter(log_formatter)
    pan_logger.addHandler(log_file_handler)

    # Console Handler (for stdout)
    if _Args.verbose:
        pan_console_handler = logging.StreamHandler(sys.stdout)
        pan_console_handler.setLevel(logging.DEBUG)
        pan_console_handler.setFormatter(log_formatter)
        pan_logger.addHandler(pan_console_handler)

    return {"Trace": trace_logger, "Log": pan_logger}


# ===========================================================================
# Initialize time tracking
# ===========================================================================
def initialize_time_tracking() -> None:
    global _StartTime
    _StartTime = time.time()


# ===========================================================================
# Stop time tracking and calculate time spent
# ===========================================================================
def stop_time_tracking(files_processed: int) -> tuple:
    end_time = time.time()
    total_time = end_time - _StartTime
    average_time_per_file = total_time / files_processed if files_processed > 0 else 0
    return total_time, average_time_per_file


# ===========================================================================
# Check if file is binary
# ===========================================================================
def is_executable(file_path: str) -> bool:
    #   Import python-magic lazily.  On Windows the import requires the
    #   `libmagic-1.dll` native dependency; if it is missing the interpreter
    #   may segfault.  On Linux/macOS `libmagic` must be installed through the
    #   system package manager.  When either is missing, the --skip-binary flag
    #   falls back to the simple null-byte heuristic in is_binary().
    try:
        import magic
    except ImportError:
        _TraceLogObj.warning(
            "python-magic is not available; install the platform libmagic "
            "dependency to enable MIME-based binary skipping for %s",
            file_path,
        )
        return False

    try:
        if os.path.isfile(file_path):
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)

            # Define magic numbers for executable file types
            # autopep8: off
            executable_mime_types = [
                "application/x-executable",     # Executable
                "application/x-sharedlib",      # shared libraries
                "application/x-shared-library", # Linux shared library
                "application/x-pie-executable", # position-independent executables
                "application/x-mach-binary",    # Mach-O binaries, used in macOS
                "application/x-dosexec",        # DOS/Windows executables, PE format
                "application/vnd.microsoft.portable-executable",  # Portable Executable format
                "application/x-dylib",          # dynamic libraries
            ]
            # autopep8: on

            _TraceLogObj.debug("MIME/Type: %s: %s", file_type, file_path)

            if any(mime_type in file_type for mime_type in executable_mime_types):
                if _Args.verbose:
                    _TraceLogObj.info("Skipped %s: %s", file_type, file_path)
                return True

    except PermissionError:
        _TraceLogObj.warning("Skipping file due to PermissionError: %s", file_path)

    except Exception as e:
        #   libmagic failures are not fatal; fall back to the simple heuristic.
        _TraceLogObj.warning(
            "python-magic failed for %s (%s); using fallback binary detection.",
            file_path,
            e,
        )
    return False


# ===========================================================================
# Check if file is binary
# ===========================================================================
def is_binary(file_path: str) -> bool:
    if _Args.skip_binary:
        if is_executable(file_path):
            _MatchCount["EXEC"] += 1
            return True

        try:
            binary_triggers = {"0x00": [], "0xFF": []}
            with open(file_path, "rb") as f:
                buffer = f.read(1024)
                for index, byte in enumerate(buffer[:-2]):  # Skip the last two bytes
                    if byte == 0x00:
                        binary_triggers["0x00"].append((index, byte))
                        continue
                    if byte == 0xFF:
                        binary_triggers["0xFF"].append((index, byte))
                        continue

                if (
                    len(binary_triggers["0x00"]) >= 1
                    and len(binary_triggers["0xFF"]) >= 1
                ):
                    _MatchCount["BINARY"] += 1
                    return True

        except IOError as e:
            _DefaultLogObj.warning("Error reading file: %s - %s", file_path, e)
    return False


# ===========================================================================
# Sanitize a value for safe ASCII CSV / log output
# ===========================================================================
def sanitize_for_ascii(value: str) -> str:
    """Return an ASCII-only representation of *value* suitable for logs/CSV.

    Non-printable bytes are replaced with '?' so binary data cannot be emitted
    in match output.
    """
    return "".join(
        char if 32 <= ord(char) <= 126 else "?"
        for char in value
    )


# ===========================================================================
# Luhn algorithm check
# ===========================================================================
def luhn_check(num: str) -> bool:
    #   An empty or all-zero string has a zero checksum but is never a PAN.
    if not str(num).strip("0"):
        return False
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0


# ===========================================================================
# Mask PAN digits for logging: keep the first 6 (BIN) and last 4 digits
# ===========================================================================
def mask_pan(pan: str) -> str:
    if len(pan) <= 10:
        return "*" * len(pan)
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


def mask_matched_data(matched: str, pan: str) -> str:
    #   Plain PAN (digits possibly separated): mask in place.  Anything else
    #   (e.g. track data) carries more sensitive fields, so mask every digit.
    if re.sub(r"\D", "", matched) != pan:
        return re.sub(r"\d", "*", matched)
    masked, seen = [], 0
    for char in matched:
        if char.isdigit():
            keep = seen < 6 or seen >= len(pan) - 4
            masked.append(char if keep and len(pan) > 10 else "*")
            seen += 1
        else:
            masked.append(char)
    return "".join(masked)


def mask_text(text: str) -> str:
    """Mask every PAN-length (12-19 digit) run in free text."""
    return re.sub(r"(?<!\d)\d{12,19}(?!\d)", lambda m: mask_pan(m.group(0)), text)


# ===========================================================================
# Validate date timestamp anti-PAN matches
# ===========================================================================
def valid_timestamp(value: str) -> bool:
    if not re.fullmatch(r"[0-9]{14}", value):
        return False

    try:
        timestamp = datetime.strptime(value, "%Y%m%d%H%M%S")
    except ValueError:
        return False

    return 1900 <= timestamp.year <= datetime.now().year + 1


# ===========================================================================
# Calculate delta for reporting
# ===========================================================================
def calculate_delta() -> bool:
    global _LastReportDelta

    this_delta = _MatchCount["FILES"]
    if _LastReportDelta < this_delta and this_delta % _Args.report_delta == 0:
        _LastReportDelta = this_delta
        return True
    return False


# ===========================================================================
# Extract and scan an archive using an external program
# ===========================================================================
def process_archive_file(
    archive_path: str,
    compiled_patterns: list,
    extractor_config: Dict[str, Dict],
) -> None:
    """Extract *archive_path* to a temp directory and scan its contents.

    The temp directory and all extracted contents are removed after scanning,
    regardless of success or failure.  External extraction programs are used
    for all supported archive formats, avoiding the tar path-traversal bugs
    inherent in the previous built-in extraction path.
    """
    archive_type = detect_archive_type(archive_path)
    if archive_type is None:
        _DefaultLogObj.error("Unsupported archive type: %s", archive_path)
        return

    extractor = extractor_config.get(archive_type)
    if not extractor:
        _DefaultLogObj.error(
            "No extractor configured for archive type '%s' (%s). "
            "Run the setup script to build %s.",
            archive_type,
            archive_path,
            EXTRACTOR_CONFIG_FILENAME,
        )
        return

    command = extractor.get("command")
    args_template = extractor.get("args", [])
    copy_archive_to_tempdir = extractor.get("copy_archive_to_tempdir", False)
    if not command or not args_template:
        _DefaultLogObj.error(
            "Incomplete extractor configuration for '%s': missing command or args.",
            archive_type,
        )
        return

    command_path = shutil.which(command) or command
    tar_tmp = _Args.tar_tmp
    if tar_tmp:
        os.makedirs(tar_tmp, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="find-pan-", dir=tar_tmp)

    try:
        _TraceLogObj.info(
            "Archive Scan: extracting %s as %s into %s ...",
            archive_path,
            archive_type,
            temp_dir,
        )

        if copy_archive_to_tempdir:
            #   gzip and similar in-place decompressors need the archive inside
            #   the temp directory so the result lands there as well.
            archive_name = os.path.basename(archive_path)
            archive_in_temp = os.path.join(temp_dir, archive_name)
            shutil.copy2(archive_path, archive_in_temp)
            archive_for_extractor = archive_in_temp
        else:
            archive_for_extractor = archive_path

        formatted_args = [
            arg.format(archive=archive_for_extractor, tempdir=temp_dir)
            for arg in args_template
        ]
        cmd = [command_path, *formatted_args]

        if _Args.verbose:
            _TraceLogObj.info("Extractor command: %s", " ".join(cmd))

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            _DefaultLogObj.error(
                "Extractor failed for %s: %s (stderr: %s)",
                archive_path,
                e,
                e.stderr,
            )
            return
        except FileNotFoundError:
            _DefaultLogObj.error(
                "Extractor command not found: %s. "
                "Update %s with the correct path.",
                command,
                EXTRACTOR_CONFIG_FILENAME,
            )
            return

        scan_directory(temp_dir, compiled_patterns)

    finally:
        try:
            shutil.rmtree(temp_dir)
            _TraceLogObj.info("Cleaned up temporary extraction directory: %s", temp_dir)
        except OSError as e:
            _TraceLogObj.warning(
                "Could not remove temporary extraction directory %s: %s", temp_dir, e
            )


# ===========================================================================
# Scan a filesystem / pathname for PAN data
# ===========================================================================
def process_filesystem(json_data: list) -> None:
    _TraceLogObj.info("Filesystem Scan")
    scan_directory(_Args.path, json_data)


# ===========================================================================
# Scan a directory for files
# ===========================================================================
def scan_directory(dir_name: str, compiled_patterns: list) -> None:
    _TraceLogObj.info("Scanning directory '%s' ...", dir_name)
    for root, _, files in os.walk(dir_name):
        _DefaultLogObj.info("Scanning directory '%s' ...", root)
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isfile(file_path):
                continue
            process_file(file_path, compiled_patterns)


# ===========================================================================
# Process a file for defined patterns
# ===========================================================================
def process_file(file_path: str, compiled_patterns: list) -> None:

    line_count = 0

    if not os.path.isfile(file_path):
        return

    try:
        if calculate_delta():
            _TraceLogObj.info(
                "Scanned %s files; matched %s PANs, %s TRACKs, %s Files Skipped",
                _MatchCount["FILES"],
                _MatchCount["PAN"],
                _MatchCount["TRACK"],
                _MatchCount["SKIPPED"],
            )

        with open(file_path, "rb") as f:
            if is_binary(file_path):
                _DefaultLogObj.info("Binary file skipped: %s", file_path)
                _MatchCount["SKIPPED"] += 1
                return

        _DefaultLogObj.info("Scanning %s", os.path.basename(file_path))
        _MatchCount["FILES"] += 1

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            line_count = 0
            for line_number, line in enumerate(f, 1):
                line_count += 1
                if _Args.line_limit > 0 and line_count > _Args.line_limit:
                    break

                scan_line(file_path, line_number, line, compiled_patterns)

    except (PermissionError, FileNotFoundError, IOError) as e:
        _TraceLogObj.warning("Skipping file due to error: %s - %s", file_path, e)

    except Exception as e:
        print_exception_info(f"{e}")


# ===========================================================================
# Scan one line, reporting every anti-PAN, PAN and TRACK match on it
# ===========================================================================
def _overlaps(span: tuple, spans: list) -> bool:
    return any(span[0] < other[1] and other[0] < span[1] for other in spans)


def scan_line(file_path: str, line_number: int, line: str, compiled_patterns: list) -> None:
    #   Anti-PAN matches only exclude their own span: other numbers on the same
    #   line are still examined.  Candidates overlapping an anti-PAN or an
    #   already accepted match are skipped; a Luhn failure only blocks other
    #   patterns from being counted a second time, not from being validated.
    excluded = []
    failed = []

    for category, pattern_name, compiled_pattern in compiled_patterns:
        if category != "Anti-PAN Pattern":
            continue
        for match in compiled_pattern.finditer(line):
            if pattern_name == "Timestamp" and not valid_timestamp(match.group(0)):
                continue
            span = match.span()
            if _overlaps(span, excluded):
                continue
            excluded.append(span)
            DataReporter(file_path, line_number, match.start(), match.group(0), line,
                         pattern_name, compiled_pattern.pattern, "ANTI-PAN")

    for category, pattern_name, compiled_pattern in compiled_patterns:
        if category == "Anti-PAN Pattern":
            continue
        if category not in ["PAN Pattern", "TRACK Pattern"]:
            # - We shouldn't get here
            raise ValueError(
                "Unexpected match: " +
                f"{file_path}:{line_number} " +
                f"->{pattern_name}={compiled_pattern.pattern} " +
                f"{line}"
            )
        data_type = "PAN" if category == "PAN Pattern" else "TRACK"
        for match in compiled_pattern.finditer(line):
            span = match.span()
            if _overlaps(span, excluded):
                continue
            reporter = DataReporter(
                file_path, line_number, match.start(), match.group(0), line,
                pattern_name, compiled_pattern.pattern, data_type,
                count_failure=not _overlaps(span, failed),
            )
            if reporter.accepted:
                excluded.append(span)
            else:
                failed.append(span)


# ===========================================================================
# Class to report PAN and TRACK data
# ===========================================================================
class DataReporter:  # pylint: disable=too-many-instance-attributes
    def __init__(self, file_path: str, line_number: int, offset: int, matched_data: str,
                 line: str, pattern_name: str, search: str, data_type: str,
                 count_failure: bool = True):
        self.file_path = file_path
        self.line_number = line_number
        self.offset = offset
        self.matched_data = matched_data
        self.line = line
        self.pattern_name = pattern_name
        self.search = search
        self.data_type = data_type

        self.accepted = False

        #   Anti-PANs are known false positives: count them, never Luhn-check
        #   or report them as findings.
        if self.data_type == "ANTI-PAN":
            self.accepted = True    # suppresses further patterns on this line
            self.update_match_count()
            return

        self.pan = self.extract_pan_from_match()
        if not self.pan or not luhn_check(self.pan):
            if count_failure:
                _MatchCount["BAD-LUHN"] += 1
            extracted, matched = self.pan, self.matched_data
            if getattr(_Args, "mask", False):
                extracted = mask_pan(self.pan)
                matched = mask_matched_data(self.matched_data, self.pan)
            _TraceLogObj.debug(
                "Luhn failure: file=%s line=%s offset=%s pattern=%s "
                "extracted=%s matched=%s",
                self.file_path,
                self.line_number,
                self.offset,
                self.pattern_name,
                extracted,
                matched,
            )
            return

        self.accepted = True
        self.update_match_count()
        self.print_info()
        self.write_csv_row()
        if _CsvFileObj is not None:
            _CsvFileObj.flush()

    def extract_pan_from_match(self) -> str:
        # Assuming Track 1 & 2 Data
        if self.matched_data.startswith(
                "%B") or self.matched_data.startswith("%M"):
            return re.sub(r"\D", "", self.matched_data[2:].split("^")[0])

        if self.matched_data.startswith(";"):
            return re.sub(r"\D", "", self.matched_data[1:].split("=")[0])

        # Otherwise, we're not sure what we have,
        # other than a regex match.  Return the digits
        return re.sub(r"\D", "", self.matched_data)

    def update_match_count(self) -> None:
        _MatchCount[self.data_type] += 1

    def print_info(self) -> None:
        line = self.line
        if getattr(_Args, "mask", False):
            line = mask_text(mask_matched_data(self.matched_data, self.pan).join(
                line.split(self.matched_data)))
        _DefaultLogObj.info(
            "%s:%s:%s->%s (%s), %s: %s", self.file_path, self.line_number, self.offset, self.pattern_name, self.data_type, self.search, line
        )

    def write_csv_row(self) -> None:
        if _CsvWriter is None:
            return
        _CsvWriter.writerow({
            "filename": sanitize_for_ascii(os.path.basename(self.file_path)),
            "line_number": self.line_number,
            "offset": self.offset,
            "pattern_name": sanitize_for_ascii(self.pattern_name),
            "data_type": sanitize_for_ascii(self.data_type),
            "matched_data": sanitize_for_ascii(
                mask_matched_data(self.matched_data, self.pan)
                if getattr(_Args, "mask", False) else self.matched_data
            ),
        })


# ===========================================================================
# Enumerate command line arguments
# ===========================================================================
def enumerate_command_line_arguments(arg_parse: argparse.ArgumentParser) -> List[str | None]:
    print_version_info(arg_parse)

    if len(sys.argv) <= 1:
        return None

    argument_list = [""]
    for arg, value in vars(_Args).items():
        arg = str(arg).replace("_", "-")
        argument_list.append(f"--{arg}={value}\n")
    return "\nParameters and Defaults\n" + " ".join(argument_list)


# ===========================================================================
# Version Information
# ===========================================================================
def print_version_info(arg_parse: argparse.ArgumentParser = None) -> None:

    def format_version():
        major, minor, patch = map(int, _FindPANVersion.split())
        return f"{arg_parse.prog} v{major}.{minor}.{patch}"

    print(f"{format_version()}\nPython {sys.version}")

    if len(sys.argv) > 1 and not arg_parse.parse_args().version:
        print("Command-line arguments: ", list(sys.argv[1:]))


# ===========================================================================
# Print Scan Summary Results
# ===========================================================================
def print_scan_summary() -> None:
    # autopep8: off
    total_match_count = _MatchCount["PAN"] + _MatchCount["TRACK"]
    _TraceLogObj.info("")
    _TraceLogObj.info("-- Processing Summary --")
    _TraceLogObj.info("PANs Matched  : %s", f"{_MatchCount['PAN']:8d}")
    _TraceLogObj.info("TRACKs Matched: %s", f"{_MatchCount['TRACK']:8d}")
    _TraceLogObj.info("Total matches : %s", f"{total_match_count:8d}")
    _TraceLogObj.info("Scanned       : %s Files.", f"{_MatchCount['FILES'] - 1:8d}")
    _TraceLogObj.info("Average time  : %s seconds per file", f"{_AverageTime:8.3f}")
    _TraceLogObj.info("Total time    : %s seconds", f"{_TotalTime:8.3f}")
    _TraceLogObj.info("")
    _TraceLogObj.info("-- Skipped Summary --")
    _TraceLogObj.info("Detected %s Luhn Check Failures.", _MatchCount["BAD-LUHN"])
    _TraceLogObj.info("Detected %s Anti-PANs.", _MatchCount["ANTI-PAN"])
    _TraceLogObj.info("Skipped %s Files.", _MatchCount["SKIPPED"])
    _TraceLogObj.info("Skipped %s Executable Files.", _MatchCount["EXEC"])
    _TraceLogObj.info("Skipped %s Binary Files.", _MatchCount["BINARY"])
    _TraceLogObj.info("")
    _TraceLogObj.info("Scan complete.")
    _TraceLogObj.info("")
    _TraceLogObj.info("Log files are located in: %s", _Args.log_dir)
    # autopep8: on


# ===========================================================================
# Configure our command line options
# autopep8: off
# ===========================================================================
def process_cmdline_arguments() -> argparse.ArgumentParser:
    log_dir = os.path.join(os.path.expanduser("~"), "Find-PAN-Logs")
    tar_dir = os.path.join(log_dir, "tar-temp")
    parser = argparse.ArgumentParser(
        description="Scan for PCI PAN and TRACK data patterns.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    #
    #   Mutable processing (change our runtime/detection behavior)
    #
    parser.add_argument( "--path", help="Filesystem pathname to scan.", type=str, default=None)
    parser.add_argument(
        "--tar",
        help="Archive file path (tar, tar.gz, zip, 7z, gz).",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--tar-tmp",
        help="Parent directory for temporary archive extraction directories.",
        default=tar_dir,
    )
    parser.add_argument( "--log-dir", help="Directory for log files.", default=log_dir)
    parser.add_argument( "--rgx-patterns", help="JSON file containing PAN and TRACK regular expressions.",
                        type=str, default=None,)
    parser.add_argument( "--rgx-prefix", help=f"Apply prefixes ({_RegexPatternPrefix}) to regular expressions.",
                        default=False, action="store_true",)
    parser.add_argument( "--skip-binary", help="Skip binary files.", action="store_true", default=False)
    parser.add_argument( "--line-limit", help="Line scan limit per file.", type=int, default=0)
    parser.add_argument( "--report-delta", type=int, default=500,
                        help="Files to process before reporting progress.",)
    parser.add_argument(
        "--csv",
        help="CSV file path for match output. Emits filename, line number, offset, pattern, and sanitized match data.",
        type=str,
        default=None,
    )
    #
    #   Non-functional processing
    #
    parser.add_argument( "--verbose", default=False, action="store_true", help="Verbose output.")
    parser.add_argument( "--debug", default=False, action="store_true", help="Enable debug logging.")
    parser.add_argument( "--mask", default=False, action="store_true",
                        help="Mask PAN digits (keep first 6 and last 4) in the log, CSV and Luhn-failure debug output.")
    parser.add_argument( "--version", default=False, action="store_true", help="Print version information.",)
    parser.add_argument( "--exception-test", default=False, action="store_true", help="Test exception handler.",)

    return parser
# autopep8: on


# ===========================================================================
# Open the CSV output file (if requested) and write the header row.
# ===========================================================================
def open_csv_output(csv_path: str) -> None:
    global _CsvFileObj, _CsvWriter
    if _CsvFileObj is not None:
        return
    _CsvFileObj = open(csv_path, "w", newline="", encoding="utf-8")
    _CsvWriter = csv.DictWriter(
        _CsvFileObj,
        fieldnames=["filename", "line_number", "offset", "pattern_name", "data_type", "matched_data"],
    )
    _CsvWriter.writeheader()


# ===========================================================================
# Close the CSV output file.
# ===========================================================================
def close_csv_output() -> None:
    global _CsvFileObj, _CsvWriter
    if _CsvFileObj is not None:
        _CsvFileObj.close()
        _CsvFileObj = None
        _CsvWriter = None


# ===========================================================================
def main() -> None:
    global _TotalTime, _AverageTime
    _Compiled_Patterns = []

    if _Args.csv:
        open_csv_output(_Args.csv)

    # Load JSON data and compile prefix patterns
    try:
        json_data = load_json_data(_Args.rgx_patterns)
    except (FileNotFoundError, ValueError) as e:
        _DefaultLogObj.error("Failed to load regex patterns: %s", e)
        return

    if json_data and _Args.debug:
        formatted_pan_patterns = json.dumps(json_data, indent=4)
        _TraceLogObj.debug(formatted_pan_patterns)

    if _Args.rgx_prefix:
        _Compiled_Patterns = compile_regex_patterns_with_prefix(json_data)
    else:
        _Compiled_Patterns = compile_regex_patterns(json_data)

    # Scan a filesystem
    if _Args.path:
        initialize_time_tracking()
        process_filesystem(_Compiled_Patterns)
        _TotalTime, _AverageTime = stop_time_tracking(_MatchCount["FILES"])
        return

    # Scan an archive file
    if _Args.tar and _Args.tar_tmp:
        initialize_time_tracking()
        try:
            extractor_config_path = find_extractor_config_path()
            extractor_config = load_extractor_config(extractor_config_path)
        except FileNotFoundError as e:
            _DefaultLogObj.error("Failed to load extractor configuration: %s", e)
            return
        process_archive_file(_Args.tar, _Compiled_Patterns, extractor_config)
        _TotalTime, _AverageTime = stop_time_tracking(_MatchCount["FILES"])
        return

    # Valid arguments not found
    _DefaultLogObj.error("Required arguments not found.")
    print("\n")
    _ArgParse.print_help()
    _ArgParse.exit(1)


# ===========================================================================
# Exception testing
# ===========================================================================
def exception_test() -> None:
    try:
        print(10 / 0)  # pylint: disable=unused-variable
    except ZeroDivisionError:
        print_exception_info("Exception test called")


# ===========================================================================
# MAIN Entry Point
# ===========================================================================
if __name__ == "__main__":
    # -- Set up signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, handle_interrupt)

    # -- Process command line arguments
    _ArgParse = process_cmdline_arguments()
    _Args = _ArgParse.parse_args()

    # -- Handle non-functional flags before touching external configuration.
    #    --version and --help must work even if no JSON config exists.
    if _Args.version:
        print_version_info(_ArgParse)
        _ArgParse.exit()

    # -- Set default values from command line arguments
    ProgramName = _ArgParse.prog

    # - Resolve the JSON regex pattern path lazily so --version and --help work
    #   even when no configuration file is present.
    if _Args.rgx_patterns is None:
        _Args.rgx_patterns = find_json_regex_config()

    # - Test our exception handler
    if _Args.exception_test:
        exception_test()

    # -- Configure our loggers
    loggers = setup_custom_loggers()
    _DefaultLogObj = loggers["Log"]
    _TraceLogObj = loggers["Trace"]

    # -- Enumerate the command line arguments
    UsageInfo = enumerate_command_line_arguments(_ArgParse)
    if UsageInfo is not None:
        _TraceLogObj.info("%s", UsageInfo)

    try:
        # --  Main processing --
        main()
        print_scan_summary()

    except KeyboardInterrupt:
        _TraceLogObj.error("KeyboardInterrupt caught in '__main__'")
    finally:
        close_csv_output()
