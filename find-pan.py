#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    find-pan.py
#  Function:    Find PAN in a file system or tar file
#  Author  :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================
#  MIT License
#  
#  Copyright (c) 2023 David Means
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

import os
import re
import sys
import magic
import logging
import tarfile
import argparse
import mimetypes
import subprocess
from datetime import datetime

##  ===========================================================================
##  Global variables
##  ===========================================================================
_DEBUG      = False
_TraceLog   = None
_PanLog     = None
total_matches = 0
TRACK_match_count = 0 
PAN_match_count = 0
FILE_count = 0

##  ===========================================================================
##  Set the logfile basename 
##  ===========================================================================
def generate_logfile_name(basename):
    """
    Generate a formatted logfile name based on the given basename and the current date.

    Args:
        basename (str): The base name of the logfile.

    Returns:
        str: The formatted logfile name.

    """
    date_str = datetime.now().strftime("%d%b%Y")
    formatted_basename = f"{basename}-{date_str}.log"
    return formatted_basename


##  ===========================================================================
##  Create our log file names
##  ===========================================================================
def set_log_directory_and_filenames(args):
    """
    Set the log directory and filenames based on the given command line arguments.

    Args:
        args (argparse.Namespace): The command line arguments.

    Returns:
        tuple: A tuple containing the PAN logfile name and the trace logfile name.

    """
    log_dir = args.log_dir if args.log_dir else os.getcwd()

    pan_logfile = os.path.join(log_dir, generate_logfile_name("Find-PAN"))
    trace_logfile = os.path.join(log_dir, generate_logfile_name("Find-PAN-trace"))

    return pan_logfile, trace_logfile

## ===========================================================================
##  Create our logging objects
## ===========================================================================
def setup_custom_loggers(args):
    """
    Set up custom loggers based on the given command line arguments.

    Args:
        args (argparse.Namespace): The command line arguments.

    Returns:
        dict: A dictionary containing the trace logger and the log logger.

    """
    pan_logfile, trace_logfile = set_log_directory_and_filenames(args)

    # Trace Logger
    trace_logger = logging.getLogger("TraceLogger")
    trace_level = logging.DEBUG if args.debug else logging.INFO
    trace_logger.setLevel(trace_level)

    # Console Handler (for stdout) - Added check for --verbose
    trace_console_handler = logging.StreamHandler(sys.stdout) if args.verbose else None

    trace_file_handler = logging.FileHandler(trace_logfile)
    trace_file_handler.setLevel(trace_level)

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
def is_executable(file_path):
    """
    Check if a file is an executable.

    Args:
        file_path (str): The path to the file to be checked.

    Returns:
        bool: True if the file is an executable, False otherwise.
        None: If an error occurs during file processing.

    """
    try:
        if os.path.isfile(file_path):
            mime = magic.Magic()
            file_type = mime.from_file(file_path)

            # Define magic numbers for executable file types
            executable_magic_numbers = [
                'application/x-executable',
                'application/x-sharedlib',  # Linux shared library
                'application/x-dosexec',    # Windows executable (PE format)
            ]

            return any(magic_number in file_type for magic_number in executable_magic_numbers)
        else:
            return None
    
    except PermissionError:
        _TraceLog.warn(f"Skipping file due to PermissionError: {file_path}")
        return None
    
    except Exception as e:
        _TraceLog.error(f"Skipping file due to error: {file_path}: {e}")
        return None
    

##  ===========================================================================
##  Check if file is binary
##  ===========================================================================
def is_binary(file_path):
    """
    Check if a file is binary by analyzing its contents.

    Args:
        file_path (str): The path to the file to be checked.

    Returns:
        bool: True if the file is binary, False otherwise.
        None: If an error occurs during file processing.

    """
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
        _PanLog.warn(f"Skipping file due to PermissionError: {file_path}")
        return None
    
    except Exception as e:
        _PanLog.error(f"Skipping file due to error: {file_path}: {e}")
    
    return None


##  ===========================================================================
##  Luhn algorithm check
##  ===========================================================================
def luhn_check(num):
    """
    Performs the Luhn algorithm to check the validity of a given number.

    Args:
        num (int): The number to be checked.

    Returns:
        bool: True if the number passes the Luhn algorithm, False otherwise.
    """
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0  
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0


##  ===========================================================================
##  Scan a directory for files
##  ===========================================================================
import os

def scan_directory(dir_name, compiled_patterns, suspect_patterns):
    """
    Recursively scans a directory and its subdirectories for files and processes each file.

    Args:
        dir_name (str): The directory to scan.
        compiled_patterns (list): A list of compiled regular expression patterns.
        suspect_patterns (list): A list of suspect patterns to match against the file contents.

    Returns:
        None
    """
    for root, dirs, files in os.walk(dir_name):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isfile(file_path):
                continue
            process_file(file_path, compiled_patterns, suspect_patterns)


##  ===========================================================================
##  Process a file for credit card patterns 
##  ===========================================================================
def process_file(file_path, compiled_patterns, suspect_patterns):
    """
    Process a file and scan its contents for patterns.

    Args:
        file_path (str): The path to the file to be processed.
        compiled_patterns (list): A list of compiled regular expression patterns.
        suspect_patterns (list): A list of regular expression patterns to be checked against each line.

    Returns:
        None

    Raises:
        None
    """
    global total_matches
    global FILE_count
    line_count = 0

    if not os.path.isfile(file_path):
        return

    try:
        FILE_count += 1
        _TraceLog.info(f"Scanning {os.path.basename(file_path)}")

        with open(file_path, 'r') as f:
            if is_binary(file_path) is not None:
                _TraceLog.info(f"-> Binary file skipped: {file_path}")
                return

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, 1):
                line_count += 1
                if args.line_limit > 0 and line_count >= args.line_limit:
                    _TraceLog.info(f"-> Line Limit reached: stopped after {line_count} lines.")
                    break
                
                if not any(pattern.match(line) for pattern in suspect_patterns):
                    scan_line(line, line_number, file_path, compiled_patterns)

                if line_number % 100 == 0:
                    _PanLog.info(f"Scanned {FILE_count} files; matched {PAN_match_count} PANs, {TRACK_match_count} TRACKs")

    except PermissionError:
        _TraceLog.warn(f"Skipping file due to PermissionError: {file_path}")

##  ===========================================================================
##  Extract PAN from track data
##  ===========================================================================
def extract_pan_from_match(match_data):
    """
    Extracts the PAN (Primary Account Number) from the given match_data.

    Parameters:
    match_data (str): The data to extract the PAN from.

    Returns:
    str: The extracted PAN.

    """
    # Assuming Track 1 & 2 Data
    if match_data.startswith('%B'):
        return re.sub(r'\D', '', match_data[2:].split('^')[0])
    
    if match_data.startswith(';'):
        return re.sub(r'\D', '', match_data[1:].split('=')[0])
    
    # Otherwise, we're not sure what we have, 
    # other than a regex match.  Return the digits
    return re.sub(r'\D', '', match_data)

##  ===========================================================================
##  Scan a line for credit card patterns
##  ===========================================================================
def scan_line(line, line_number, file_path, patterns):
    """
    Scans a line of text for patterns and extracts PAN (Primary Account Number) matches.

    Args:
        line (str): The line of text to scan.
        line_number (int): The line number in the file.
        file_path (str): The path of the file being scanned.
        patterns (dict): A dictionary of patterns to match against.

    Returns:
        None

    Raises:
        None
    """
    global TRACK_match_count
    global PAN_match_count

    for label, compiled_patterns in patterns.items():
        for pattern in compiled_patterns:
            for match in pattern.findall(line):
                if label == 'TRACK' or label == 'PAN':
                    match_info = f"Type: {label}, File: {file_path}, Line: {line_number}, Pattern: {pattern.pattern}, Match: {match}"
                    match = extract_pan_from_match(match)
                    if match is None:
                        continue

                    if luhn_check(match):
                        if label == 'TRACK':
                            TRACK_match_count += 1
                            _TraceLog.info(f"{match_info}")
                            return  # We found a match, so we're done with this line
                        elif label == 'PAN':
                            PAN_match_count += 1
                            _TraceLog.info(f"{match_info}")
                            return   # We found a match, so we're done with this line


##  ===========================================================================
##  Compile PAN regex patterns
##  ===========================================================================
def compile_pan_patterns():
    """
    Compile PAN and Track patterns into regular expressions.

    Returns:
        dict: A dictionary containing compiled regular expressions for PAN and Track patterns.
            The 'PAN' key maps to a list of compiled PAN patterns.
            The 'TRACK' key maps to a list of compiled Track patterns.
    """
    # PAN patterns
    pan_patterns = [
        r'3[47][0-9]{13}',                              # American Express
        r'5[1-5][0-9]{14}|2[2-7][0-9]{14}',             # Mastercard
        r'4[0-9]{12}(?:[0-9]{3})?',                     # Visa
        r'6011[0-9]{12}|65[0-9]{14}|64[4-9][0-9]{13}',  # Discover
        r'3(?:0[0-5]|[68][0-9])[0-9]{11}',              # Diners Club International
        r'(?:2131|1800[0-9]{11}|35[0-9]{14})'           # JCB
    ]
    
    # Track patterns
    track_patterns = [
        r'%B\d{13,19}\^\w{1,26}\^\d{1,19}|\d{1,19}\?',  # Track 1 Data
        r';\d{13,19}=\d{1,19}|\d{1,19}\?'               # Track 2 Data
    ]

    ## The order here is important.  We want to detect 'TRACK' patterns first, then 'PAN' patterns
    return {'TRACK': [re.compile(t) for t in track_patterns], 'PAN': [re.compile(p) for p in pan_patterns] }

##  ===========================================================================
##  Compile NOT PAN (suspect) patterns
##  ===========================================================================
def compile_suspect_patterns():
    """
    Compiles a list of regular expression patterns that match suspect PAN (Primary Account Number) patterns.

    Returns:
        list: A list of compiled regular expression patterns.
    """
    anti_pan_patterns = [
        r'^(123456|654321)\d*|\d*(123456|654321)$',     #   Sequential numbers
        r'([3456]\d{3,5})\1+',                          #   Repeated numbers
        r'^(?=.{12,19}$)6?5?4321[0]+',                  #   654321 with trailing zeros
        r'[34356](\d)\1{2}(([0-9](\d)\1{2}){2})',       #   Repeated numbers
        r'^(123456|654321)\d*|\d*(123456|654321)$'      #   Sequential numbers
    ]
    return [re.compile(p) for p in anti_pan_patterns]

##  ===========================================================================
##  Securely delete a file
##  ===========================================================================
def secure_delete(file_path):
    """
    Securely deletes a file by overwriting its contents.

    Args:
        file_path (str): The path to the file to be securely deleted.

    Returns:
        None
    """
    if os.name == 'posix': # Linux, using shred, which is part of GNU coreutils
        subprocess.run(['shred', '-u', file_path])
        return
    
    if os.name == 'nt': # Windows, using SysInternals sdelete; download from https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
        subprocess.run(['sdelete', file_path])

##  ===========================================================================
##  Enumerate command line arguments
##  ===========================================================================
def enumerate_command_line_arguments(args):
    # command_line = ' '.join(sys.argv)
    argument_list = ['']
    for arg, value in vars(args).items():
        argument_list.append(f'--{arg}={value}\n')
    return '\nParameters and Defaults\n' + ' '.join(argument_list)

##  ===========================================================================
##  Main
##  ===========================================================================
def main(args):

    compiled_patterns = compile_pan_patterns()
    suspect_patterns = compile_suspect_patterns()

    if args.path:
        _TraceLog.info(f"Scanning {args.path} ...")
        scan_directory(args.path, compiled_patterns, suspect_patterns)
        return
    
    if args.tar and args.temp:
        _TraceLog.info(f"Scanning {args.tar} ...")
        with tarfile.open(args.tar, 'r:*') as tar:
            for tarinfo in tar:
                if tarinfo.isreg():
                    temp_path = os.path.join(args.temp, tarinfo.name)
                    tar.extract(tarinfo, path=args.temp)
                    process_file(temp_path, compiled_patterns, suspect_patterns)
                    secure_delete(temp_path)
        return
    
    _PanLog.error('Please provide a valid path or tar file and temporary directory.')
    sys.exit(1)

##  ====================================
##  Entry point
##  ====================================
CWD = os.getcwd()
parser = argparse.ArgumentParser(description='Scan for credit card patterns.')
parser.add_argument('--path', help='File system path.')
parser.add_argument('--skip-binary', default=False, action='store_true', help='Skip binary files (optional).')
parser.add_argument('--tar', help='Tar file path.')
parser.add_argument('--temp', help='Temporary directory for tar file extraction.')
parser.add_argument('--log-dir', help='Directory for log files (optional).')
parser.add_argument('--line-limit', type=int, default=-1, help='Line limit per file (optional).')
parser.add_argument('--verbose', default=False, action='store_true', help='Verbose output (optional).')
parser.add_argument('--debug', default=False, action='store_true', help='Debug output (optional).')

##  ===========================================================================
##  Parse command line arguments
##  ===========================================================================
if not _DEBUG:
    args = parser.parse_args()
else:
    ##  If we're debugging, we'll use the following test data
    args = parser.parse_args(['--path', './test-data/', '--verbose'] )

##  Validate command line arguments
if ( not args.path and not args.tar ) or ( args.path and args.tar ):
    print(f"[ --path {args.path} ] [ --tar {args.tar} --temp {args.temp} ]")
    parser.error('Please provide a valid path or tar file.')

if ( not args.temp and args.tar ):
    parser.error('Please provide a temporary directory for tar file extraction.')

##  Initialize loggers
loggers = setup_custom_loggers(args)
_PanLog = loggers['Log']
_TraceLog = loggers['Trace']

## Show our command line arguments
print(f"{enumerate_command_line_arguments(args)}")

if __name__ == '__main__':
    main(args)


