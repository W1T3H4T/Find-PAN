#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    find-pan.py
#  Function:    Finds PAN in a file system or tar file
#  Author  :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================
#
#  MIT License
#  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
#  ===========================================================================

import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import traceback
import magic
from collections import defaultdict
from datetime import datetime
from typing import Dict, List
import time

# ===========================================================================
# Global variables
# ===========================================================================
_LastReportDelta = 0
_RegexPatternPrefix = None
_TotalTime = 0
_AverageTime = 0

# - SemVer Information
_FindPANVersion = "2 2 0"  # Major, Minor, Patch

# - Item Count Array
_MatchCount = defaultdict(int)

#   Location of JSON file for REGEX Patterns
_JSONPtrnPrefixPath = "/usr/local/Find-PAN/patterns"

_EnableVSArgParams = False  # Use custom argparse for Visual Studio
_LoggingDebug = False  # Emit debug log messages
_LoggingVerbose = False  # Emit verbose log messagest

# - Loggers for Trace log and std Log file
_TraceLogObj = None
_DefaultLogObj = None


# ===========================================================================
# Print consolidated exception info
# ===========================================================================
def print_exception_info(e):
    # pylint: disable=possibly-used-before-assignment
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_stack = traceback.extract_tb(exc_traceback)

    # Traverse the traceback to find the first call outside the current module
    for frame in reversed(tb_stack):
        if f"{ProgramName}" in frame.filename:
            file_name = frame.filename
            line_number = frame.lineno
            func_name = frame.name
            break
    else:
        # Fallback to the last frame (this shouldn't happen)
        frame = tb_stack[-1]
        file_name = frame.filename
        line_number = frame.lineno
        func_name = frame.name

    exception_message = str(exc_value)

    print("\nException Information:")
    print("-----------------------------------------------------------------")
    print(f"Function: '{func_name}', on line {line_number}")
    print(f"File    : {file_name}")
    print(f"Type    : {exc_type.__name__}")
    print(f"Message : {exception_message}")
    if str(e).lower() != str(exception_message).lower():
        print(f"Info    : {e}")
    print("-----------------------------------------------------------------")
    sys.exit(1)


# ===========================================================================
# Handle keyboard interrupt
# ===========================================================================
def handle_interrupt(sig, frame):
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
def generate_logfile_name(basename):
    date_str = datetime.now().strftime("%d%b%Y")
    formatted_basename = f"{basename}-{date_str}.log"
    return formatted_basename


# ===========================================================================
# Create our log file names
# ===========================================================================
def set_log_directory_and_filenames(args):
    try:
        if not os.path.exists(args.log_dir):
            os.makedirs(args.log_dir)

        if not os.path.exists(args.tar_tmp):
            os.makedirs(args.tar_tmp)

        pan_logfile = os.path.join(args.log_dir, generate_logfile_name("Find-PAN"))
        trace_logfile = os.path.join(
            args.log_dir, generate_logfile_name("Find-PAN-trace")
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(e)

    return pan_logfile, trace_logfile


# ===========================================================================
# Create our logging objects
# ===========================================================================
def setup_custom_loggers(args):
    pan_logfile, trace_logfile = set_log_directory_and_filenames(args)

    #   Remove pre-existing log files
    if os.path.exists(pan_logfile):
        os.remove(pan_logfile)
    if os.path.exists(trace_logfile):
        os.remove(trace_logfile)

    # Trace Logger
    trace_logger = logging.getLogger("_TraceLogObj")
    trace_level = logging.DEBUG if args.debug else logging.INFO
    trace_logger.setLevel(trace_level)
    # Trace Console Handler (for stdout)
    trace_console_handler = logging.StreamHandler(sys.stdout)

    try:
        trace_file_handler = logging.FileHandler(trace_logfile)
        trace_file_handler.setLevel(trace_level)
    except FileNotFoundError:
        print_exception_info(None)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(e)

    trace_formatter = logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s")

    if trace_console_handler:
        trace_console_handler.setLevel(trace_level)
        trace_console_handler.setFormatter(trace_formatter)
        trace_logger.addHandler(trace_console_handler)

    trace_file_handler.setFormatter(trace_formatter)
    trace_logger.addHandler(trace_file_handler)

    # PAN Logger
    pan_logger = logging.getLogger("_DefaultLogObj")
    pan_logger.setLevel(logging.DEBUG)

    log_file_handler = logging.FileHandler(pan_logfile)
    log_file_handler.setLevel(logging.DEBUG)

    log_formatter = logging.Formatter("%(asctime)s [%(levelname)s]: %(message)s")
    log_file_handler.setFormatter(log_formatter)
    pan_logger.addHandler(log_file_handler)

    # Console Handler (for stdout)
    pan_console_handler = logging.StreamHandler(sys.stdout)
    pan_console_handler.setLevel(logging.DEBUG)
    pan_console_handler.setFormatter(log_formatter)

    if _LoggingVerbose:
        pan_logger.addHandler(pan_console_handler)

    pan_logger.addHandler(log_file_handler)

    return {"Trace": trace_logger, "Log": pan_logger}


# ===========================================================================
# Initialize time tracking
# ===========================================================================
def initialize_time_tracking():
    global _StartTime
    _StartTime = time.time()


# ===========================================================================
# Stop time tracking and calculate time spent
# ===========================================================================
def stop_time_tracking(files_processed):
    end_time = time.time()
    total_time = end_time - _StartTime
    average_time_per_file = total_time / files_processed if files_processed > 0 else 0
    return total_time, average_time_per_file


# ===========================================================================
# Check if file is binary
# ===========================================================================
def is_executable(file_path) -> bool | None:
    try:
        if os.path.isfile(file_path):
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)

            # Define magic numbers for executable file types
            executable_mime_types = [
                "application/x-executable",  # Executable
                "application/x-sharedlib",  # shared libraries
                "application/x-shared-library",  # Linux shared library
                "application/x-pie-executable",  # position-independent executables
                "application/x-mach-binary",  # Mach-O binaries, used in macOS
                "application/x-dosexec",  # DOS/Windows executables, PE format
                "application/vnd.microsoft.portable-executable",  # Portable Executable format
                "application/x-dylib",  # dynamic libraries
            ]

            _TraceLogObj.debug("MIME/Type: %s: %s", file_type, file_path)

            if any(mime_type in file_type for mime_type in executable_mime_types):
                if _Args.verbose:
                    _TraceLogObj.info("Skipped %s: %s", file_type, file_path)
                return True

    except PermissionError:
        _TraceLogObj.warning("Skipping file due to PermissionError: %s", file_path)

    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(f"Skipping file due to error: {file_path}, {e}")

    return False


# ===========================================================================
# Check if file is binary
# ===========================================================================
def is_binary(file_path):
    if _Args.skip_binary:  # pylint: disable=possibly-used-before-assignment
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
# Luhn algorithm check
# ===========================================================================
def luhn_check(num):
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0


# ===========================================================================
# Calculate delta for reporting
# ===========================================================================
def calculate_delta():
    # pylint: disable=global-statement,possibly-used-before-assignment
    global _LastReportDelta

    this_delta = _MatchCount["FILES"]
    if _LastReportDelta < this_delta and this_delta % ReportDelta == 0:
        _LastReportDelta = this_delta
        return True
    return False


# ===========================================================================
# Scan a TAR file for PAN and TRACK data
# ===========================================================================
def process_tar_file(args, json_data):
    _TraceLogObj.info("TAR File Scan")
    secure_del_app = find_secure_delete_program()
    _TraceLogObj.info("Scanning %s using %s ...", args.tar, args.tar_tmp)

    with tarfile.open(args.tar, "r:*") as tar:
        for tarinfo in tar:
            if tarinfo.isreg():
                # Define the temp path where the file will be extracted
                temp_path = os.path.join(args.tar_tmp, tarinfo.name)

                tar.extract(tarinfo, path=args.tar_tmp, filter=custom_tar_filter)

                # Process the extracted file
                process_file(temp_path, json_data)

                # Securely delete the file after processing
                secure_delete(secure_del_app, temp_path)


# ===========================================================================
# Tar file filter for safety
# ===========================================================================
def custom_tar_filter(tarinfo, path):
    # Ensure that tarinfo has a safe path (no absolute paths or path traversal)
    if ".." in tarinfo.name or tarinfo.name.startswith("/"):
        _TraceLogObj.warning(
            "Skipping potentially dangerous file: %s in %s", tarinfo.name, path
        )
        return None  # Skip this file

    # Modify tarinfo (e.g., change file permissions)
    tarinfo.mode &= 0o755  # Ensure no world-writable permissions
    return tarinfo  # Return tarinfo to proceed with extraction


# ===========================================================================
# Find the secure delete app for the OS
# ===========================================================================
def find_secure_delete_program():
    nt = ["sdelete64.exe", "sdelete.exe"]
    posix = ["shred", "gshred"]

    if os.name == "posix":
        for tool in posix:
            tool_path = shutil.which(tool)
            if tool_path:
                _TraceLogObj.info("Using %s %s for secure delete", os.name, tool_path)
                return [tool_path, "-u"]

    if os.name == "nt":
        for tool in nt:
            tool_path = shutil.which(tool)
            if tool_path:
                _TraceLogObj.info("Using %s %s for secure delete", os.name, tool_path)
                return [tool_path]

    _TraceLogObj.warning("No Secure delete app found for %s", os.name)
    return None  # Unsupported operating system


# ===========================================================================
# Securely delete a file
# ===========================================================================
def secure_delete(secure_del_app, file_path):
    try:
        if secure_del_app is None:
            os.remove(file_path)
            return

        cmd = secure_del_app.copy()
        cmd.append(file_path)
        if _LoggingVerbose:
            _TraceLogObj.info("Secure delete: %s", file_path)
        subprocess.run(cmd, check=True)

    except subprocess.CalledProcessError as e:
        _TraceLogObj.error("Error securely deleting file: %s, Error: %s", file_path, e)


# ===========================================================================
# Scan a filesystem / pathname for PAN data
# ===========================================================================
def process_filesystem(args, json_data):
    _TraceLogObj.info("Filesystem Scan")
    _TraceLogObj.info("Scanning pathname '%s' ...", args.path)
    scan_directory(args.path, json_data)


# ===========================================================================
# Scan a directory for files
# ===========================================================================
def scan_directory(dir_name, json_data):
    for root, _, files in os.walk(dir_name):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isfile(file_path):
                continue
            process_file(file_path, json_data)


# ===========================================================================
# Process a file for defined patterns
# ===========================================================================
def process_file(file_path, compiled_patterns):
    # pylint: disable=possibly-used-before-assignment,broad-exception-caught
    line_count = 0

    if not os.path.isfile(file_path):
        return

    try:
        _DefaultLogObj.info("Scanning %s", os.path.basename(file_path))
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

        _MatchCount["FILES"] += 1

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            line_count = 0
            for line_number, line in enumerate(f, 1):
                line_count += 1
                if _Args.line_limit > 0 and line_count >= _Args.line_limit:
                    break

                ## Run the PAN & TRACK Data Finder using Pre-Coimpiled Patterns
                for category, pattern_name, compiled_pattern in compiled_patterns:
                    match = compiled_pattern.search(line)
                    if not match:
                        continue

                    if category == "Anti-PAN Pattern":
                        # We have found an Anti-PAN pattern
                        report_antipan_data(
                            file_path,
                            line_number,
                            match.group(0),
                            line,
                            pattern_name,
                            compiled_pattern.pattern,
                        )
                        break

                    if category == "PAN Pattern":
                        # We have found a PAN pattern
                        report_pan_data(
                            file_path,
                            line_number,
                            match.group(0),
                            line,
                            pattern_name,
                            compiled_pattern.pattern,
                        )
                        break

                    if category == "TRACK Pattern":
                        # We have found a TRACK pattern
                        report_track_data(
                            file_path,
                            line_number,
                            match.group(0),
                            line,
                            pattern_name,
                            compiled_pattern.pattern,
                        )
                        break

                    # - We shouldn't get here
                    raise ValueError(
                        "Unexpected match: %s:%s->%s,%s: %s",
                        file_path,
                        line_number,
                        pattern_name,
                        search,
                        line,
                    )

    except (PermissionError, FileNotFoundError, IOError) as e:
        _TraceLogObj.warning("Skipping file due to error: %s - %s", file_path, e)

    except Exception as e:
        print_exception_info(f"{e}")


# ===========================================================================
# Report Anti-PAN
# ===========================================================================
def report_antipan_data(
    file_path, line_number, matched_data, line, pattern_name, search
):

    _MatchCount["ANTI-PAN"] += 1
    _DefaultLogObj.info(
        "%s:%s->%s,%s: %s", file_path, line_number, pattern_name, search, line
    )


# ===========================================================================
# Report track data
# ===========================================================================
def report_track_data(file_path, line_number, matched_data, line, pattern_name, search):

    pan = extract_pan_from_match(matched_data)

    _MatchCount["TRACK"] += 1
    if not luhn_check(pan):
        _MatchCount["BAD-LUHN"] += 1

    _DefaultLogObj.info(
        "%s:%s->%s,%s: %s", file_path, line_number, pattern_name, search, line
    )


# ===========================================================================
# Report pan data
# ===========================================================================
def report_pan_data(file_path, line_number, matched_data, line, pattern_name, search):
    pan = extract_pan_from_match(matched_data)

    _MatchCount["PAN"] += 1
    if not luhn_check(pan):
        _MatchCount["BAD-LUHN"] += 1

    _DefaultLogObj.info(
        "%s:%s->%s,%s: %s", file_path, line_number, pattern_name, search, line
    )


# ===========================================================================
# Extract PAN from track data
# ===========================================================================
def extract_pan_from_match(match_data):
    # Assuming Track 1 & 2 Data
    if match_data.startswith("%B") or match_data.startswith("%M"):
        return re.sub(r"\D", "", match_data[2:].split("^")[0])

    if match_data.startswith(";"):
        return re.sub(r"\D", "", match_data[1:].split("=")[0])

    # Otherwise, we're not sure what we have,
    # other than a regex match.  Return the digits
    return re.sub(r"\D", "", match_data)


# ===========================================================================
# Compile the regex patterns with a prefix
# ===========================================================================
def compile_regex_patterns_with_prefix(json_data) -> []:
    compiled_patterns = []

    for category, patterns in json_data.items():
        if isinstance(patterns, dict):
            for pattern_name, details in patterns.items():
                if "regex" in details:
                    for pattern in details["regex"]:
                        prefix_pattern = f"{_RegexPatternPrefix}{pattern}"
                        compiled_patterns.append(
                            (category, pattern_name, re.compile(prefix_pattern))
                        )

    return compiled_patterns


# ===========================================================================
# Compile the regex patterns
# ===========================================================================
def compile_regex_patterns(json_data: dict) -> []:
    compiled_patterns = []

    for category, patterns in json_data.items():
        # print(f"category: {category}")
        if isinstance(patterns, dict):
            for pattern_name, details in patterns.items():
                if "regex" in details:
                    for pattern in details["regex"]:
                        compiled_patterns.append(
                            (category, pattern_name, re.compile(pattern))
                        )

    return compiled_patterns


# ===========================================================================
# Load JSON File
# ===========================================================================
def load_json_data(filename):
    try:
        with open(filename, "r", encoding="utf-8", errors="replace") as file:
            data = json.load(file)
            return data

    except FileNotFoundError:
        print_exception_info(f"Error: File '{filename}' not found.")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(e)

    return None


# ===========================================================================
# Enumerate command line arguments
# ===========================================================================
def enumerate_command_line_arguments(arg_parse) -> List:
    args = arg_parse.parse_args()
    print_version_info(arg_parse)
    argument_list = [""]
    for arg, value in vars(args).items():
        arg = str(arg).replace("_", "-")
        argument_list.append(f"--{arg}={value}\n")
    return "\nParameters and Defaults\n" + " ".join(argument_list)


# ===========================================================================
# Version Information
# ===========================================================================
def print_version_info(arg_parse: Dict = None) -> str:
    def format_version():
        major, minor, patch = map(int, _FindPANVersion.split())
        return f"{arg_parse.prog} v{major}.{minor}.{patch}"

    print(f"{format_version()}\nPython {sys.version}")

    if not arg_parse.parse_args().version:
        print("Command-line arguments: ", list(sys.argv[1:]))


# ===========================================================================
# Print Scan Summary Results
# ===========================================================================
def print_scan_summary():
    total_match_count = _MatchCount["PAN"] + _MatchCount["TRACK"]
    _TraceLogObj.info("")
    _TraceLogObj.info("-- Processing Summary --")
    _TraceLogObj.info("PANs Matched  : %s", f"{_MatchCount['PAN']:8d}")
    _TraceLogObj.info("TRACKs Matched: %s", f"{_MatchCount['TRACK']:8d}")
    _TraceLogObj.info("Total matches : %s", f"{total_match_count:8d}")
    _TraceLogObj.info("Scanned       : %s Files.", f"{_MatchCount['FILES']-1:8d}")
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


# ===========================================================================
# Configure our command line options
# ===========================================================================
def process_cmdline_arguments():
    log_dir = os.path.join(os.path.expanduser("~"), "Find-PAN-Logs")
    tar_dir = os.path.join(log_dir, "tar-temp")
    parser = argparse.ArgumentParser(
        description="Scan for PCI PAN and TRACK data patterns.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ##
    # Mutable Processing Arguments
    ##
    parser.add_argument(
        "--path", help="Filesystem pathname to scan.", type=str, default=None
    )
    parser.add_argument("--tar", help="TAR file path.", type=str, default=None)
    parser.add_argument(
        "--tar-tmp",
        help="Temporary directory for tar file extraction.",
        default=tar_dir,
    )
    parser.add_argument("--log-dir", help="Directory for log files.", default=log_dir)
    parser.add_argument(
        "--skip-binary", help="Skip binary files.", action="store_true", default=False
    )
    parser.add_argument(
        "--patterns",
        help="JSON file containing PAN and TRACK regular expressions.",
        type=str,
        default=f"{_JSONPtrnPrefixPath}/find-pan-patterns.json",
    )
    parser.add_argument(
        "--line-limit", help="Line scan limit per file.", type=int, default=0
    )

    parser.add_argument(
        "--rgx-prefix",
        help="Prefix for regular expressions.",
        default=False,
        action="store_true",
    )

    parser.add_argument(
        "--report-delta",
        type=int,
        default=500,
        help="Files to process before reporting progress.",
    )
    ##
    # Non-functional Arguments
    ##
    parser.add_argument(
        "--verbose", default=False, action="store_true", help="Verbose output."
    )
    parser.add_argument(
        "--debug", default=False, action="store_true", help="Enable debug logging."
    )
    parser.add_argument(
        "--version",
        default=False,
        action="store_true",
        help="Print version information.",
    )
    parser.add_argument(
        "--exception-test",
        default=False,
        action="store_true",
        help="Test exception handler.",
    )

    #  Parse command line arguments
    if _EnableVSArgParams:
        # args = parser.parse_args(['--version'] )
        # debugging configuration here
        args = parser.parse_args(["--path", os.path.join(os.getcwd(), "test")])
    else:
        args = parser.parse_args()

    if args.version:
        print_version_info(parser)
        parser.exit()

    return parser, args


# ===========================================================================
# MAIN is here
# ===========================================================================
def main(arg_parse):
    global _TotalTime, _AverageTime
    _Compiled_Patterns = []

    # Load JSON data and compile prefix patterns
    json_filename = _Args.patterns
    json_data = load_json_data(json_filename)
    if json_data and _TraceLogObj.debug:
        formatted_pan_patterns = json.dumps(json_data, indent=4)
        _TraceLogObj.debug(formatted_pan_patterns)
    else:
        _TraceLogObj.error("No JSON data file found.")
        return

    if _Args.rgx_prefix:
        _Compiled_Patterns = compile_regex_patterns_with_prefix(json_data)
    else:
        _Compiled_Patterns = compile_regex_patterns(json_data)

    # Scan a filesystem
    if _Args.path:
        initialize_time_tracking()
        process_filesystem(_Args, _Compiled_Patterns)
        _TotalTime, _AverageTime = stop_time_tracking(_MatchCount["FILES"])
        return

    # Scan a tar file
    if _Args.tar and _Args.tar_tmp:
        initialize_time_tracking()
        process_tar_file(_Args, _Compiled_Patterns)
        _TotalTime, _AverageTime = stop_time_tracking(_MatchCount["FILES"])
        return

    # No valid arguments found
    _DefaultLogObj.error("Required arguments not found.")
    print("\n\n")
    arg_parse.print_help()
    arg_parse.exit(1)


# ===========================================================================
# Exception testing
# ===========================================================================
def exception_test():
    try:
        result = 10 / 0  # pylint: disable=unused-variable
    except ZeroDivisionError:
        print_exception_info("Exception test called")


# ===========================================================================
# MAIN Entry Point
# ===========================================================================
if __name__ == "__main__":
    # -- Set up signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, handle_interrupt)

    # -- Process command line arguments
    _ArgParse, _Args = process_cmdline_arguments()

    # -- Set default values from command line arguments
    ProgramName = _ArgParse.prog
    ReportDelta = _Args.report_delta
    _LoggingDebug = _Args.debug
    _LoggingVerbose = _Args.verbose

    # - Test our exception handler
    if _Args.exception_test:
        exception_test()

    # -- Set the regular expression prefix
    if _Args.rgx_prefix:
        _RegexPatternPrefix = r"[ '\"{]"

    # -- Configure our loggers
    loggers = setup_custom_loggers(_Args)
    _DefaultLogObj = loggers["Log"]
    _TraceLogObj = loggers["Trace"]

    # -- Enumerate the command line arguments
    UsageInfo = enumerate_command_line_arguments(_ArgParse)
    _TraceLogObj.info("%s", UsageInfo)

    try:
        # --  Main processing --
        main(_ArgParse)
        print_scan_summary()

    except KeyboardInterrupt:
        _TraceLogObj.error("KeyboardInterrupt caught in '__main__'")
