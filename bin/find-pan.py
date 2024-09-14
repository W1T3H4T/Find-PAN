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
from datetime import datetime
import json
import logging
import magic
import os
import platform
import re
import sys
import tarfile
import subprocess
import traceback

##  ===========================================================================
##  Global variables
##  ===========================================================================
global _VSDEBUG, _DEBUG, _VERBOSE
global TraceLog, PanLog
global total_matches, TRACK_Match_count, PAN_Match_count, Match_Count, FILE_Count
global compiled_patterns, reportDelta, _DEBUG, ProgramName
global major, minor, patch, rgx_prefix 

# - Version information
major, minor, patch = map(int, '1 4 0'.split()) 

Match_Count = { "PAN" : 0, "TRACK" : 0 }

_VSDEBUG = False
TraceLog = None
PanLog   = None
total_matches     = 0
TRACK_Match_count = 0 
PAN_Match_count   = 0
FILE_Count        = 0
compiled_patterns = {}

##  ===========================================================================
##  Print consolidated exception info
##  ===========================================================================
def print_exception_info(e):
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

    print(f"Exception occurred in function: '{func_name}', at line: {line_number}, in file: '{file_name}'")
    print(f"Exception type: {exc_type.__name__}, Message: {exception_message}")
    if not e is None:
        print(f"Exception Info: {e}")
    sys.exit(1)

##  ===========================================================================
##  Set the logfile basename
##  ===========================================================================
def generate_logfile_name(basename):
    date_str = datetime.now().strftime("%d%b%Y")
    formatted_basename = f"{basename}-{date_str}.log"
    return formatted_basename


##  ===========================================================================
##  Create our log file names
##  ===========================================================================
def set_log_directory_and_filenames(args):
    try:
        if not os.path.exists(args.log_dir):
            os.makedirs(args.log_dir)

        if not os.path.exists(args.tar_tmp):
            os.makedirs(args.tar_tmp)

        pan_logfile = os.path.join(args.log_dir, generate_logfile_name("Find-PAN"))
        trace_logfile = os.path.join(args.log_dir, generate_logfile_name("Find-PAN-trace"))

    except Exception as e:
        print_exception_info(e)

    return pan_logfile, trace_logfile

## ===========================================================================
##  Create our logging objects
## ===========================================================================
def setup_custom_loggers(args):
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

    # Console Handler (for stdout) - Added check for --verbose
    trace_console_handler = logging.StreamHandler(sys.stdout) if args.verbose else None

    try:
        trace_file_handler = logging.FileHandler(trace_logfile)
        trace_file_handler.setLevel(trace_level)
    except FileNotFoundError:
        print_exception_info(None)
    except Exception as e:
        print_exception_info(e)


    trace_formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')

    if trace_console_handler:
        trace_console_handler.setLevel(trace_level)
        trace_console_handler.setFormatter(trace_formatter)
        trace_logger.addHandler(trace_console_handler)

    trace_file_handler.setFormatter(trace_formatter)
    trace_logger.addHandler(trace_file_handler)

    # Log Logger
    pan_logger = logging.getLogger("LogLogger")
    pan_logger.setLevel(logging.DEBUG)

    log_file_handler = logging.FileHandler(pan_logfile)
    log_file_handler.setLevel(logging.DEBUG)

    log_formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s')
    log_file_handler.setFormatter(log_formatter)

    # Console Handler (for stdout)
    pan_console_handler = logging.StreamHandler(sys.stdout)
    pan_console_handler.setLevel(logging.DEBUG)
    pan_console_handler.setFormatter(log_formatter)
    
    pan_logger.addHandler(log_file_handler)
    pan_logger.addHandler(pan_console_handler)

    return {'Trace': trace_logger, 'Log': pan_logger}

##  ===========================================================================
##  Check if file is binary
##  ===========================================================================
def is_executable(file_path) -> bool | None:
    try:
        def is_executable(file_path) -> bool | None:
            if os.path.isfile(file_path):
                mime = magic.Magic()
                file_type = mime.from_file(file_path)

                # Define magic numbers for executable file types
                executable_magic_numbers = [
                    'application/x-executable',
                    'application/x-shared-library',  # Linux shared library
                    'application/x-dosexec',    # Windows executable (PE format)
                ]

                return any(magic_number in file_type for magic_number in executable_magic_numbers)
            else:
                return None
    
    except PermissionError:
        TraceLog.warning(f"Skipping file due to PermissionError: {file_path}")
        return None
    
    except Exception as e:
        TraceLog.error(f"Skipping file due to error: {file_path}: {e}")
        return None


##  ===========================================================================
##  Check if file is binary
##  ===========================================================================
def is_binary(file_path):
    binary_offsets = []

    if (args.skip_binary == False):
        return None     # Skip binary check
    
    if is_executable(file_path) == True:
        return True
    
    try:
        with open(file_path, 'rb') as f:
            buffer = f.read(1024)
            for index, byte in enumerate(buffer[:-2]):  # Skip the last two bytes
                if byte == 0x00 or byte == 0xFF:
                    binary_offsets.append((hex(byte), index))
                    continue

        if len(binary_offsets) >= 2:
            return True

    except PermissionError:
        PanLog.warning(f"Skipping file due to PermissionError: {file_path}")
        return None
    
    except Exception as e:
        PanLog.error(f"Skipping file due to error: {file_path}: {e}")
    
    return None


##  ===========================================================================
##  Luhn algorithm check
##  ===========================================================================
def luhn_check(num):
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0  
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0


##  ===========================================================================
##  Scan a directory for files
##  ===========================================================================
def scan_directory(dir_name, compiled_patterns, json_data ):
    for root, dirs, files in os.walk(dir_name):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isfile(file_path):
                continue
            process_file(file_path, compiled_patterns, json_data )


##  ===========================================================================
##  Process a file for credit card patterns
##  ===========================================================================
def process_file(file_path, search_patterns, json_data ):
    global FILE_Count, PAN_Match_count, TRACK_Match_count
    global total_matches, Match_Count
    line_count = 0

    if not os.path.isfile(file_path):
        return

    try:
        FILE_Count += 1
        TraceLog.info(f"Scanning {os.path.basename(file_path)}")
        PanLog.info(f"Scanning {os.path.basename(file_path)}")

        with open(file_path, 'r') as f:
            if is_binary(file_path) is not None:
                TraceLog.info(f"Binary file skipped: {file_path}")
                return

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            line_count = 0

            for line_number, text_line in enumerate(f, 1):
                line_count += 1
                if args.line_limit > 0 and line_count >= args.line_limit:
                    TraceLog.warning(f"Line Limit reached: stopped after {line_count} lines.")
                    break
                
                # match_data = scan_text_line(text_line, search_patterns)
                matched_info, match_data = match_regex(text_line, line_number, json_data)
                if match_data is None:
                    continue

                total_matches += 1

                if matched_info.lower().startswith('track'):
                    type='TRACK'
                    TRACK_Match_count += 1
                else:
                    type='PAN'
                    PAN_Match_count += 1

                if type == "PAN":
                    pan = extract_pan_from_match(match_data)                    
                    if luhn_check(pan):
                        Match_Count[type] += 1
                        if _VERBOSE: 
                            PanLog.info(f"{file_path}:{line_count}->{pan}: {matched_info}")
                    else:
                        if _VERBOSE: 
                            PanLog.info(f"{file_path}:{line_count}->{pan} (Luhn Check: Failed)")
                else:
                    pan = extract_pan_from_match(match_data)                    
                    if luhn_check(pan):
                        Match_Count[type] += 1
                        if _VERBOSE: 
                            PanLog.info(f"{file_path}:{line_count}->{match_data}: {matched_info}")
                    else:
                        if _VERBOSE: 
                            PanLog.info(f"{file_path}:{line_count}->{match_data}: {matched_info} (Luhn Check: Failed)")

                if FILE_Count % reportDelta == 0:
                    PanLog.info(f"Scanned {FILE_Count} files; matched {PAN_Match_count} PANs, {TRACK_Match_count} TRACKs")

    except PermissionError:
        TraceLog.warning(f"Skipping file due to PermissionError: {file_path}")


##  ===========================================================================
##  Match REGEX patterns from the JSON data
##  ===========================================================================
def match_regex(text_line, line_number, json_data):

    try:
        for section_name, section_data in json_data.items():
            if _DEBUG:
                TraceLog.debug(f"Checking section: {section_name}")

            for pattern_name, pattern_info in section_data.items():
                if rgx_prefix is not None:
                    #  If we have a prefix, add it to the regex pattern
                    regex_pattern = rgx_prefix + pattern_info['regex']
                else:
                    #  Otherwise, just use the regex pattern
                    regex_pattern = pattern_info['regex']

                #  Perform the match
                match = re.search(regex_pattern, text_line)

                if match:
                    regex_info = f"{section_name} '{pattern_name}': {regex_pattern}"
                    if _DEBUG:
                        TraceLog.debug(f"{regex_info} in line: {line_number}")
                    return regex_info,match.group(0)

    except Exception as e:
        print_exception_info(e)

    if _DEBUG:
        TraceLog.debug(f"No match found for {text_line}")
    return None , None


##  ===========================================================================
##  Scan a line for credit card patterns
##  ===========================================================================
def scan_text_line(text_line, patterns_data):

    anti_pan_patterns = compiled_patterns.get('Anti-PAN Patterns', {})
    track_data = {key: value['pattern'] for key, value in compiled_patterns.items() if key.lower().startswith('track')}
    pan_patterns = {key: value['pattern'] for key, value in compiled_patterns.items() if key.lower().startswith('pan')}
    
    # Check for anti-PAN patterns
    for pattern_name, pattern_info in anti_pan_patterns.items():
        if re.search(pattern_info['pattern'], text_line):
            print(f"Anti-PAN pattern '{pattern_name}' detected. Dismissing line.")
            return None
    
    # Check for track data
    for track_name, track_pattern in track_data.items():
        match = re.search(track_pattern, text_line)
        if match:
            print(f"Track data '{track_name}' detected.")
            return match.group()
    
    # Check for PAN data
    for pan_name, pan_pattern in pan_patterns.items():
        match = re.search(pan_pattern, text_line)
        if match:
            print(f"PAN data '{pan_name}' detected.")
            return match.group()
    
    # No match found
    print("No track or PAN data detected.")
    return None


##  ===========================================================================
##  Extract PAN from track data
##  ===========================================================================
def extract_pan_from_match(match_data):
    # Assuming Track 1 & 2 Data
    if match_data.startswith('%B'):
        return re.sub(r'\D', '', match_data[2:].split('^')[0])
    
    if match_data.startswith(';'):
        return re.sub(r'\D', '', match_data[1:].split('=')[0])
    
    # Otherwise, we're not sure what we have, 
    # other than a regex match.  Return the digits
    return re.sub(r'\D', '', match_data)


##  ===========================================================================
##  Securely delete a file
##  ===========================================================================
def secure_delete(file_path):
    if os.name == 'posix': # Linux, using shred, which is part of GNU coreutils
        subprocess.run(['shred', '-u', file_path])
        return
    
    # Windows, using SysInternals sdelete; download from https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
    if os.name == 'nt': 
        subprocess.run(['sdelete64.exe', file_path])


##  ===========================================================================
##  Load JSON REGEX patterns
##  ===========================================================================
def load_json_data(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            return data

    except FileNotFoundError:
        print_exception_info(f"Error: File '{filename}' not found.")
    except Exception as e:
        print_exception_info(e)

    return None


##  ===========================================================================
##  Enumerate command line arguments
##  ===========================================================================
def enumerate_command_line_arguments(args):
    argument_list = ['']
    for arg, value in vars(args).items():
        argument_list.append(f'--{arg}={value}\n')
    return '\nParameters and Defaults\n' + ' '.join(argument_list)


##  ===========================================================================
##  Load REGEX from JSON file
##  ===========================================================================
def load_json_data(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            return data
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None

    except Exception as e:
        print_exception_info(None)


##  ===========================================================================
##  Version Information
##  ===========================================================================
def printVersionInfo(argParse):
    platform_name = platform.system()
    python_version = f"Python {sys.version}"
    print(f"{argParse.prog} v{major}.{minor}.{patch}\n{python_version}")

##  ===========================================================================
##  Print scan results
##  ===========================================================================
def print_scan_results():
    global total_matches, Match_Count, FILE_Count
    PanLog.info(f"Scanned {FILE_Count} files.")
    PanLog.info(f"Matched {Match_Count['PAN']} PANs.")
    PanLog.info(f"Matched {Match_Count['TRACK']} TRACKs.")
    PanLog.info(f"Total matches: {total_matches}")
    
    
##  ===========================================================================
##  Configure our command line options
##  ===========================================================================
def setupArgParse():
    log_dir=os.path.join(os.path.expanduser("~"),"Find-PAN-Logs")
    tar_dir=os.path.join(log_dir, "tar-temp")
    parser = argparse.ArgumentParser(
            description='Scan for PCI PAN and TRACK data patterns.',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    ##
    ##  Processing Switches
    ##
    parser.add_argument('--path',       help='Filesystem pathname to scan.', type=str, default=None)
    parser.add_argument('--tar',        help='TAR file path.', type=str, default=None)
    parser.add_argument('--tar-tmp',    help='Temporary directory for tar file extraction.', default=tar_dir)
    parser.add_argument('--log-dir',    help='Directory for log files.', default=log_dir)
    parser.add_argument('--skip-binary',help='Skip binary files.', action='store_true', default=False )
    parser.add_argument('--patterns',   help='JSON file containing pattern regular expressions.', type=str, default='patterns/find-pan-patterns.json')
    parser.add_argument('--line-limit', help='Line scan limit per file.', type=int, default=0)
    parser.add_argument('--rgx-prefix', help='Prefix for regular expressions.', default=False, action='store_true') 
    ##
    ##  Non-functional arguments
    ##
    parser.add_argument('--report-delta', type=int, default=100, help='Files to process before reporting progress.')
    parser.add_argument('--verbose', default=False, action='store_true', help='Verbose output.')
    parser.add_argument('--debug',   default=False, action='store_true', help='Enable debug logging.')
    parser.add_argument('--version', default=False, action='store_true', help='Print version information.')

    #  Parse command line arguments
    if not _VSDEBUG:
        args = parser.parse_args()
    else:
        # debuging configuration here
        test_data_path = os.path.join(os.getcwd(),'test')
        # args = parser.parse_args(['--path', test_data_path, '--verbose'] )
        args = parser.parse_args(['--path', test_data_path] )

    if args.version:
        printVersionInfo(parser)
        parser.exit()

    return parser, args


##  ===========================================================================
##  MAIN is here
##  ===========================================================================
def main(argsParse, args):

    # Load JSON data and compile prefix patterns
    json_filename = args.patterns
    json_data = load_json_data(json_filename)
    if json_data:
        pan_patterns = {}
        if _DEBUG:
            formatted_pan_patterns = json.dumps(json_data, indent=4)
            print(formatted_pan_patterns)
    else:
        TraceLog.error("No JSON data file found.")
        return

    if args.path:
        TraceLog.info(f"Scanning {args.path} ...")
        scan_directory(args.path, pan_patterns, json_data )
        return
    
    if args.tar and args.temp:
        TraceLog.info(f"Scanning {args.tar} ...")
        with tarfile.open(args.tar, 'r:*') as tar:
            for tarinfo in tar:
                if tarinfo.isreg():
                    temp_path = os.path.join(args.temp, tarinfo.name)
                    tar.extract(tarinfo, path=args.temp)
                    process_file(temp_path, compiled_patterns, json_data )
                    secure_delete(temp_path)
        return
    
    PanLog.error("Required arguments not found.")
    print("\n\n")
    argsParse.print_help()
    argsParse.exit(1)


##  ===========================================================================
##  MAIN Entry Point
##  ===========================================================================
if __name__ == '__main__':
    global ProgramName, reportDelta, _DEBUG, rgx_prefix, _VERBOSE

    # -- Process command line arguments
    argsParse, args = setupArgParse()

    # -- set default values
    ProgramName  = argsParse.prog
    reportDelta  = args.report_delta
    _DEBUG       = args.debug
    _VERBOSE     = args.verbose

    if args.rgx_prefix:
        rgx_prefix = r"[ '\"{]"
    else:
        rgx_prefix = None

    # -- set loggers
    loggers = setup_custom_loggers(args)
    PanLog = loggers['Log']
    TraceLog = loggers['Trace']

    # -- Enumerate parameters
    usage_info = enumerate_command_line_arguments(args)
    TraceLog.info(f"{usage_info}")

    # -- Run the finders
    main(argsParse, args)
    print_scan_results()
