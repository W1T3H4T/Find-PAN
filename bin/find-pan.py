#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    find-pan.py
#  Function:    Find PAN in a file system or tar file
#  Author  :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================
#
#  MIT License
#
#  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#  ===========================================================================

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tarfile
import traceback
from datetime import datetime

import magic

# ===========================================================================
# Global variables
# ===========================================================================
LastReportDelta = 0
RegexPatternPrefix = None
FindPANVersion = "2 1 0"  # Major, Minor, Patch
# - Version information
MatchCount = {"FILES": 0, "PAN": 0, "TRACK": 0, "ANTI-PAN": 0, "SKIPPED": 0, "EXEC": 0, "BINARY" :0}

#   Location of JSON REGEX Patterns
pattern_prefix_path = \
    "/usr/local/Find-PAN/patterns"  # pylint: disable=invalid-name

#   Global Variables
EnableVSArgParse = False  # Use custom argparse for Visual Studio
LoggingDebug = False  # Emit debug log messages
LoggingVerbose = False  # Emit verbose log messagest

#   Loggers for Trace log and std Log file
TraceLogger = None
PanLogger = None

# ===========================================================================
# Print consolidated exception info
# ===========================================================================
def print_exception_info(e):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_stack = traceback.extract_tb(exc_traceback)

    # Traverse the traceback to find the first call outside the current module
    for frame in reversed(tb_stack):
        if f"{ProgramName}" in frame.filename: # pylint: disable=possibly-used-before-assignment
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

    print(
        f"Exception occurred in function: '{func_name}', at line: {line_number}, in file: '{file_name}'")
    print(f"Exception type: {exc_type.__name__}, Message: {exception_message}")
    if e is not None:
        print(f"Exception Info: {e}")
    sys.exit(1)


# ===========================================================================
# Handle keyboard interrupt
# ===========================================================================
def handle_interrupt(signal, frame):
    # Log the signal number
    TraceLogger.error(f"KeyboardInterrupt caught (signal number: {signal}). Exiting.")

    # Log the stack frame details
    TraceLogger.debug("Stack frame at the time of interrupt:")
    TraceLogger.debug(''.join(traceback.format_stack(frame)))

    PrintScanSummary()
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
def set_log_directory_and_filenames(MyArgs):
    try:
        if not os.path.exists(MyArgs.log_dir):
            os.makedirs(args.log_dir)

        if not os.path.exists(MyArgs.tar_tmp):
            os.makedirs(MyArgs.tar_tmp)

        pan_logfile = os.path.join(
            MyArgs.log_dir, generate_logfile_name("Find-PAN"))
        trace_logfile = os.path.join(
            args.log_dir, generate_logfile_name("Find-PAN-trace"))

    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(e)

    return pan_logfile, trace_logfile

# ===========================================================================
# Create our logging objects
# ===========================================================================
def setup_custom_loggers(MyArgs):
    pan_logfile, trace_logfile = set_log_directory_and_filenames(args)

    #   Remove pre-existing log files
    if os.path.exists(pan_logfile):
        os.remove(pan_logfile)
    if os.path.exists(trace_logfile):
        os.remove(trace_logfile)

    # Trace Logger
    trace_logger = logging.getLogger("TraceLogger")
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

    trace_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s]: %(message)s')

    if trace_console_handler:
        trace_console_handler.setLevel(trace_level)
        trace_console_handler.setFormatter(trace_formatter)
        trace_logger.addHandler(trace_console_handler)

    trace_file_handler.setFormatter(trace_formatter)
    trace_logger.addHandler(trace_file_handler)

    # PAN Logger
    pan_logger = logging.getLogger("PANLogger")
    pan_logger.setLevel(logging.DEBUG)

    log_file_handler = logging.FileHandler(pan_logfile)
    log_file_handler.setLevel(logging.DEBUG)

    log_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s]: %(message)s')
    log_file_handler.setFormatter(log_formatter)
    pan_logger.addHandler(log_file_handler)

    # Console Handler (for stdout)
    pan_console_handler = logging.StreamHandler(sys.stdout)
    pan_console_handler.setLevel(logging.DEBUG)
    pan_console_handler.setFormatter(log_formatter)

    if LoggingVerbose:
        pan_logger.addHandler(pan_console_handler)

    pan_logger.addHandler(log_file_handler)

    return {'Trace': trace_logger, 'Log': pan_logger}


# ===========================================================================
# Check if file is binary
# ===========================================================================
def is_executable(file_path) -> bool | None:
    global MatchCount
    
    try:
        if os.path.isfile(file_path):
            file_type = magic.from_file(file_path, mime=True)

            # Define magic numbers for executable file types
            executable_mime_types = [
                'application/x-executable',     # (Executable)
                'application/x-sharedlib',      # (shared libraries)
                'application/x-shared-library', # Linux shared library
                'application/x-pie-executable', # (position-independent executables)
                'application/x-mach-binary',    # (Mach-O binaries, used in macOS)
                'application/x-dosexec',        # (DOS/Windows executables, PE format)
                'application/vnd.microsoft.portable-executable', # (Portable Executable format)
                'application/x-dylib'           # (dynamic libraries)
            ]

            if any(magic_number in file_type for magic_number in executable_mime_types):
                return True
            else:
                if LoggingVerbose:
                    TraceLogger.info(f"Mime: {file_type}: {file_path}")
        else:
            return False

    except PermissionError:
        TraceLogger.warning(
            f"Skipping file due to PermissionError: {file_path}")

    except Exception as e:  # pylint: disable=broad-exception-caught
        TraceLogger.error(f"Skipping file due to error: {file_path}: {e}")
    return False

# ===========================================================================
# Check if file is binary
# ===========================================================================
def is_binary(file_path):
    global MatchCount
    binary_triggers = {"0x00" : 0, "0xFF" : 0 }

    if not args.skip_binary:
        return False     # Skip binary check

    if is_executable(file_path):
        MatchCount['EXEC'] += 1
        return True

    try:
        with open(file_path, 'rb') as f:
            buffer = f.read(1024)
            for index, byte in enumerate(
                    buffer[:-2]):  # Skip the last two bytes
                if byte == 0x00:
                    binary_triggers['0x00'] += 1
                    continue
                if byte == 0xFF:
                    binary_triggers['0xFF'] += 1
                    continue

        if binary_triggers['0x00'] >=1 and binary_triggers['0xFF'] >= 1:
            MatchCount['BINARY'] += 1
            return True

    except FileNotFoundError:
        PanLogger.warning(f"Skipping file due to FileNotFoundError: {file_path}")
        return False

    except PermissionError:
        PanLogger.warning(f"Skipping file due to PermissionError: {file_path}")
        return False

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
    global LastReportDelta

    thisDelta = MatchCount['FILES']
    if LastReportDelta < thisDelta and thisDelta % ReportDelta == 0:
        LastReportDelta = thisDelta
        return True
    return False


# ===========================================================================
# Process a file for credit card patterns
# ===========================================================================
def process_file(file_path, json_data):
    global MatchCount
    global LastReportDelta
    line_count = 0

    if not os.path.isfile(file_path):
        return

    try:
        PanLogger.info(f"Scanning {os.path.basename(file_path)}")
        if calculate_delta():
            TraceLogger.info(
                f"Scanned {
                    MatchCount['FILES']} files; matched {
                    MatchCount['PAN']} PANs, {
                    MatchCount['TRACK']} TRACKs, {
                    MatchCount['SKIPPED']} Skipped")

        with open(file_path, 'rb') as f:
            if is_binary(file_path) == True:
                PanLogger.info(f"Binary file skipped: {file_path}")
                MatchCount['SKIPPED'] += 1
                return

        MatchCount['FILES'] += 1

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            line_count = 0

            for line_number, text_line in enumerate(f, 1):
                line_count += 1
                if args.line_limit > 0 and line_count >= args.line_limit:
                    TraceLogger.warning(
                        f"Line Limit reached: stopped after {line_count} lines.")
                    break

                matched_info, match_data = scan_text_line(
                    text_line, line_number, json_data)
                if match_data is None:
                    continue

                if matched_info.lower().startswith('pan'):
                    pan = extract_pan_from_match(match_data)
                    if luhn_check(pan):
                        MatchCount['PAN'] += 1
                        PanLogger.info(
                            f"{file_path}:{line_count}->{pan}: {matched_info}")
                    else:
                        PanLogger.info(
                            f"{file_path}:{line_count}->{pan} (Luhn Check: Failed)")
                    continue

                if matched_info.lower().startswith('track'):
                    pan = extract_pan_from_match(match_data)
                    if luhn_check(pan):
                        MatchCount['TRACK'] += 1
                        PanLogger.info(
                            f"{file_path}:{line_count}->{match_data}: {matched_info}")
                    else:
                        PanLogger.info(
                            f"{file_path}:{line_count}->{match_data}: {matched_info} (Luhn Check: Failed)")
                    continue

                if matched_info.lower().startswith('anti-pan'):
                    MatchCount['ANTI-PAN'] += 1

    except PermissionError:
        TraceLogger.warning(
            f"Skipping file due to PermissionError: {file_path}")
    except FileNotFoundError:
        TraceLogger.warning(
            f"Skipping file due to FileNotFoundError: {file_path}")
    except Exception as e:
        print_exception_info(e)


# ===========================================================================
# Scan a directory for files
# ===========================================================================
def scan_directory(dir_name, json_data):
    for root, dirs, files in os.walk(dir_name):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isfile(file_path):
                continue
            process_file(file_path, json_data)


# ===========================================================================
# Match REGEX patterns from the JSON data
# ===========================================================================
def scan_text_line(text_line, line_number, json_data):
    try:
        for section_name, section_data in json_data.items():
            if LoggingDebug:
                TraceLogger.debug(f"Checking section: {section_name}")

            for pattern_name, pattern_info in section_data.items():
                if RegexPatternPrefix is not None:
                    #  If we have a prefix, add it to the regex pattern
                    regex_pattern = RegexPatternPrefix + pattern_info['regex']
                else:
                    #  Otherwise, just use the regex pattern
                    regex_pattern = pattern_info['regex']

                #  Perform the match
                match = re.search(regex_pattern, text_line)

                if match:
                    regex_info = f"{section_name} '{pattern_name}': {regex_pattern}"
                    if LoggingDebug:
                        TraceLogger.debug(
                            f"{regex_info} in line: {line_number}")
                    return regex_info, match.group(0)

    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(e)

    if LoggingDebug:
        TraceLogger.debug(f"No match found for {text_line}")
    return None, None


# ===========================================================================
# Extract PAN from track data
# ===========================================================================
def extract_pan_from_match(match_data):
    # Assuming Track 1 & 2 Data
    if match_data.startswith('%B'):
        return re.sub(r'\D', '', match_data[2:].split('^')[0])

    if match_data.startswith(';'):
        return re.sub(r'\D', '', match_data[1:].split('=')[0])

    # Otherwise, we're not sure what we have,
    # other than a regex match.  Return the digits
    return re.sub(r'\D', '', match_data)


# ===========================================================================
# Securely delete a file
# ===========================================================================
def secure_delete(file_path):
    if os.name == 'posix':  # Linux, using shred, which is part of GNU coreutils
        subprocess.run(['shred', '-u', file_path])
        return

    # Windows, using SysInternals sdelete; download from
    # https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
    if os.name == 'nt':
        subprocess.run(['sdelete64.exe', file_path])


# ===========================================================================
# Load JSON REGEX patterns
# ===========================================================================
def load_json_data(filename):
    try:
        with open(filename, 'r') as file:
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
def enumerate_command_line_arguments(argParse):
    args = argParse.parse_args()
    printVersionInfo(argParse)
    argument_list = ['']
    for arg, value in vars(args).items():
        argument_list.append(f'--{arg}={value}\n')
    return '\nParameters and Defaults\n' + ' '.join(argument_list)


# ===========================================================================
# Load REGEX from JSON file
# ===========================================================================
def load_json_data(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            return data

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None

    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(None)


# ===========================================================================
# Version Information
# ===========================================================================
def printVersionInfo(argParse):

    def format_version():
        major, minor, patch = map(int, FindPANVersion.split())
        return f"{argParse.prog} v{major}.{minor}.{patch}"

    print(f"{format_version()}\nPython {sys.version}")

    if not argParse.parse_args().version:
        print("Command-line arguments: ", list(sys.argv[1:]))


# ===========================================================================
# Print Scan Summary Results
# ===========================================================================
def PrintScanSummary():
    total_match_count = MatchCount['PAN'] + MatchCount['TRACK']
    TraceLogger.info("")
    TraceLogger.info("-- Processing Summary --")
    TraceLogger.info(f"Matched {MatchCount['PAN']} PANs.")
    TraceLogger.info(f"Matched {MatchCount['TRACK']} TRACKs.")
    TraceLogger.info("")
    TraceLogger.info(f"Skipped {MatchCount['SKIPPED']} Files")
    TraceLogger.info(f"Skipped {MatchCount['ANTI-PAN']} Anti-PANs.")
    TraceLogger.info(f"Skipped {MatchCount['EXEC']} Executable Files")
    TraceLogger.info(f"Skipped {MatchCount['BINARY']} Binary Files")
    TraceLogger.info("")
    TraceLogger.info(f"Scanned      : {MatchCount['FILES'] - 1} files.")
    TraceLogger.info(f"Total matches: {total_match_count}")
    # TraceLogger.info(f"{MatchCount}")

# ===========================================================================
# Get the number of arguments passed
# ===========================================================================


def get_num_args():
    return len(sys.argv) - 1

# ===========================================================================
# Configure our command line options
# ===========================================================================


def process_cmdline_arguments():
    log_dir = os.path.join(os.path.expanduser("~"), "Find-PAN-Logs")
    tar_dir = os.path.join(log_dir, "tar-temp")
    parser = argparse.ArgumentParser(
        description='Scan for PCI PAN and TRACK data patterns.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    ##
    # Processing Switches
    ##
    parser.add_argument(
        '--path',
        help='Filesystem pathname to scan.',
        type=str,
        default=None)
    parser.add_argument('--tar', help='TAR file path.', type=str, default=None)
    parser.add_argument(
        '--tar-tmp',
        help='Temporary directory for tar file extraction.',
        default=tar_dir)
    parser.add_argument(
        '--log-dir',
        help='Directory for log files.',
        default=log_dir)
    parser.add_argument(
        '--skip-binary',
        help='Skip binary files.',
        action='store_true',
        default=False)
    parser.add_argument(
        '--patterns',
        help='JSON file containing pattern regular expressions.',
        type=str,
        default=f'{pattern_prefix_path}/find-pan-patterns.json')
    parser.add_argument(
        '--line-limit',
        help='Line scan limit per file.',
        type=int,
        default=0)
    parser.add_argument(
        '--rgx-prefix',
        help='Prefix for regular expressions.',
        default=False,
        action='store_true')
    ##
    # Non-functional arguments
    ##
    parser.add_argument(
        '--report-delta',
        type=int,
        default=500,
        help='Files to process before reporting progress.')
    parser.add_argument(
        '--verbose',
        default=False,
        action='store_true',
        help='Verbose output.')
    parser.add_argument(
        '--debug',
        default=False,
        action='store_true',
        help='Enable debug logging.')
    parser.add_argument(
        '--version',
        default=False,
        action='store_true',
        help='Print version information.')

    #  Parse command line arguments
    if EnableVSArgParse:
        # debugging configuration here
        args = parser.parse_args(['--path', os.path.join(os.getcwd(),'test')
        # args = parser.parse_args(['--version'] )
    else:
        args = parser.parse_args()

    if get_num_args() == 0:
        parser.print_help()
        parser.exit()

    if args.version:
        printVersionInfo(parser)
        parser.exit()

    return parser, args


# ===========================================================================
# Tar file filter for safety
# ===========================================================================
def custom_tar_filter(tarinfo, path):
    # Ensure that tarinfo has a safe path (no absolute paths or path traversal)
    if ".." in tarinfo.name or tarinfo.name.startswith("/"):
        TraceLogger.warning(
            f"Skipping potentially dangerous file: {
                tarinfo.name}")
        return None  # Skip this file

    # Modify tarinfo (e.g., change file permissions)
    tarinfo.mode &= 0o755  # Ensure no world-writable permissions
    return tarinfo  # Return tarinfo to proceed with extraction

# ===========================================================================
# Scan a TAR file for PAN and TRACK data
# ===========================================================================


def process_tar_file(args, json_data):
    TraceLogger.info("TAR File Scan")
    TraceLogger.info(f"Scanning {args.tar} using {args.tar_tmp} ...")
    with tarfile.open(args.tar, 'r:*') as tar:
        for tarinfo in tar:
            if tarinfo.isreg():
                # Define the temp path where the file will be extracted
                temp_path = os.path.join(args.tar_tmp, tarinfo.name)

                tar.extract(
                    tarinfo,
                    path=args.tar_tmp,
                    filter=custom_tar_filter)

                # Process the extracted file
                process_file(temp_path, json_data)

                # Securely delete the file after processing
                secure_delete(temp_path)


# ===========================================================================
# Scan a filesystem / pathname for PAN data
# ===========================================================================
def process_filesystem(args, json_data):
    TraceLogger.info(f"Filesystem Scan")
    TraceLogger.info(f"Scanning {args.path} ...")
    scan_directory(args.path, json_data)


# ===========================================================================
# MAIN is here
# ===========================================================================
def main(argParse):
    args = argParse.parse_args()

    # Load JSON data and compile prefix patterns
    json_filename = args.patterns
    json_data = load_json_data(json_filename)
    if json_data:
        pan_patterns = {}
        if LoggingDebug:
            formatted_pan_patterns = json.dumps(json_data, indent=4)
            print(formatted_pan_patterns)
    else:
        TraceLogger.error("No JSON data file found.")
        return

    # Scan a filesystem
    if args.path:
        process_filesystem(args, json_data)
        return

    # Scan a tar file
    if args.tar and args.tar_tmp:
        process_tar_file(args, json_data)
        return

    # No valid arguments found
    PanLogger.error("Required arguments not found.")
    print("\n\n")
    argParse.print_help()
    argParse.exit(1)


# ===========================================================================
# MAIN Entry Point
# ===========================================================================
if __name__ == '__main__':
    # -- Set up signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, handle_interrupt)

    # -- Process command line arguments
    argParse, args = process_cmdline_arguments()

    # -- Set default values from command line arguments
    ProgramName = argParse.prog
    ReportDelta = args.report_delta
    LoggingDebug = args.debug
    LoggingVerbose = args.verbose

    # -- Set the regular expression prefix
    if args.rgx_prefix:
        RegexPatternPrefix = r"[ '\"{]"

    # -- Configure our loggers
    loggers = setup_custom_loggers(args)
    PanLogger = loggers['Log']
    TraceLogger = loggers['Trace']

    # -- Enumerate the command line arguments
    usage_info = enumerate_command_line_arguments(argParse)
    TraceLogger.info(f"{usage_info}")

    try:
        # --  Main processing --
        main(argParse)
        PrintScanSummary()

    except KeyboardInterrupt:
        TraceLogger.error("KeyboardInterrupt caught in main()")
