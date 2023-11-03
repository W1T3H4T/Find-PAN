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
import logging
import tarfile
import argparse
import mimetypes
import subprocess
from datetime import datetime

##  ===========================================================================
##  Global variables
##  ===========================================================================
_VERBOSE = True
_Trace = None
_PanLog = None

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
    log_dir = args.log_dir if args.log_dir else os.getcwd()

    pan_logfile = os.path.join(log_dir, generate_logfile_name("Find-PAN"))
    trace_logfile = os.path.join(log_dir, generate_logfile_name("Find-PAN-trace"))

    return pan_logfile, trace_logfile

##  ===========================================================================
##  Create our logging objects
##  ===========================================================================
def setup_custom_loggers(args):

    pan_logfile, trace_logfile = set_log_directory_and_filenames(args)

    # Trace Logger
    trace_logger = logging.getLogger("TraceLogger")
    trace_logger.setLevel(logging.DEBUG)

    trace_console_handler = logging.StreamHandler()
    trace_console_handler.setLevel(logging.DEBUG)

    trace_file_handler = logging.FileHandler(trace_logfile)
    trace_file_handler.setLevel(logging.DEBUG)

    trace_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    trace_console_handler.setFormatter(trace_formatter)
    trace_file_handler.setFormatter(trace_formatter)

    trace_logger.addHandler(trace_console_handler)
    trace_logger.addHandler(trace_file_handler)

    # Log Logger
    log_logger = logging.getLogger("LogLogger")
    log_logger.setLevel(logging.DEBUG)

    log_file_handler = logging.FileHandler(pan_logfile)
    log_file_handler.setLevel(logging.DEBUG)

    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_file_handler.setFormatter(log_formatter)

    log_logger.addHandler(log_file_handler)

    return {'Trace': trace_logger, 'Log': log_logger}


##  ===========================================================================
##  Check if file is binary
##  ===========================================================================
def is_binary(file_path, _VERBOSE=False):
    binary_offsets = []

    try:
        with open(file_path, 'rb') as f:
            buffer = f.read(1024)
            for index, byte in enumerate(buffer[:-2]):  # Skip the last two bytes
                if byte == 0x00 or byte == 0xFF:
                    binary_offsets.append((hex(byte), index))
                    continue

        if len(binary_offsets) >= 2:
            return binary_offsets
        return None

    except Exception as e:
        _Trace.info(f"WARN: skipped ({file_path}): {e}")
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
def scan_directory(dir_name, compiled_patterns, suspect_patterns):
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
    total_matches = 0
    line_count = 0

    if not os.path.isfile(file_path):
        return

    try:
        _Trace.info(f"Scanning {os.path.basename(file_path)}")

        with open(file_path, 'r') as f:
            if is_binary(file_path, False) is not None:
                _Trace.info(f"-> is binary; skipped")
                return

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, 1):
                line_count += 1
                if line_count > 1000:
                    _Trace.info(f"-> stopped after {line_count} lines.")
                    break

                if _VERBOSE:
                    _Trace.debug(f"line_count:{line_count}")

                if not any(pattern.match(line) for pattern in suspect_patterns):
                    if scan_line(line, line_number, file_path, compiled_patterns, total_matches) > 0:
                        _Trace.info(f"-> PAN matched")

    except PermissionError:
        _Trace.warn(f"Skipping file due to PermissionError: {file_path}")

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
##  Scan a line for credit card patterns
##  ===========================================================================
def scan_line(line, line_number, file_path, patterns, total_matches):
    for label, compiled_patterns in patterns.items():
        for pattern in compiled_patterns:
            for match in pattern.findall(line):
                if label == 'TRACK' or label == 'PAN':
                    match = extract_pan_from_match(match)
                    if match is None:
                        continue

                if match.isdigit():
                    if luhn_check(match):
                        _PanLog.info(f"Type: {label}, Pattern: {pattern.pattern}, Match: {match}, File: {file_path}, Line: {line_number}")
                        _Trace.info(f"[LUNH] Success.")
                        total_matches += 1
                        if total_matches >= 10:
                            return total_matches
                    else:
                        _Trace.info(f"[LUNH] Failed.")
                else:
                    _Trace.info(f"[match.isgitit()] Failed.")
    return total_matches


##  ===========================================================================
##  Compile PAN regex patterns
##  ===========================================================================
def compile_pan_patterns():
    pan_patterns = [
        r'3[47][0-9]{13}',
        r'5[1-5][0-9]{14}|2[2-7][0-9]{14}',
        r'4[0-9]{12}(?:[0-9]{3})?',
        r'6011[0-9]{12}|65[0-9]{14}|64[4-9][0-9]{13}',
        r'3(?:0[0-5]|[68][0-9])[0-9]{11}',
        r'(?:2131|1800[0-9]{11}|35[0-9]{14})'
    ]
    
    track_patterns = [
        r'%B\d{13,19}\^\w{1,26}\^\d{1,19}|\d{1,19}\?',
        r';\d{13,19}=\d{1,19}|\d{1,19}\?'
    ]
    
    return {'PAN': [re.compile(p) for p in pan_patterns], 'TRACK': [re.compile(t) for t in track_patterns]}

##  ===========================================================================
##  Compile NOT PAN (suspect) patterns
##  ===========================================================================
def compile_suspect_patterns():
    anti_pan_patterns = [
        r'^(123456|654321)\d*|\d*(123456|654321)$',
        r'([3456]\d{3,5})\1+',
        r'^(?=.{12,19}$)6?5?4321[0]+',
        r'[34356](\d)\1{2}(([0-9](\d)\1{2}){2})',
        r'^(123456|654321)\d*|\d*(123456|654321)$'
    ]
    return [re.compile(p) for p in anti_pan_patterns]

##  ===========================================================================
##  Securely delete a file
##  ===========================================================================
def secure_delete(file_path):
    if os.name == 'posix':
        subprocess.run(['shred', '-u', file_path])
    elif os.name == 'nt':
        subprocess.run(['sdelete', file_path])

##  ===========================================================================
##  Main
##  ===========================================================================
def main(args):

    compiled_patterns = compile_pan_patterns()
    suspect_patterns = compile_suspect_patterns()

    if args.path:
        _Trace.info(f"Scanning {args.path} ...")
        scan_directory(args.path, compiled_patterns, suspect_patterns)
        return
    
    if args.tar and args.temp:
        _Trace.info(f"Scanning {args.tar} ...")
        with tarfile.open(args.tar, 'r*') as tar:
            for tarinfo in tar:
                if tarinfo.isreg():
                    temp_path = os.path.join(args.temp, tarinfo.name)
                    tar.extract(tarinfo, path=args.temp)
                    process_file(temp_path, compiled_patterns, suspect_patterns)
                    secure_delete(temp_path)
        return
    
    _Trace.error('Please provide a valid path or tar file and temporary directory.')
    _PanLog.error('Wrong command line parameters.')
    sys.exit(1)

##  ====================================
##  Entry point
##  ====================================
parser = argparse.ArgumentParser(description='Scan for credit card patterns.')
parser.add_argument('--path', help='File system path.')
parser.add_argument('--tar', help='Tar file path.')
parser.add_argument('--temp', help='Temporary directory for tar file extraction.')
parser.add_argument('--log-dir', help='Directory for log files (optional).')
args = parser.parse_args()

loggers = setup_custom_loggers(args)
_PanLog = loggers['Log']
_Trace = loggers['Trace']

if __name__ == '__main__':
    main(args)


