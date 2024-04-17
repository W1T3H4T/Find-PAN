#!/usr/local/bin/python3
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
import json
import logging
import tarfile
import argparse
import subprocess
from datetime import datetime
import os
import magic

##  ===========================================================================
##  Global variables
##  ===========================================================================
global _DEBUG
global _TraceLog
global _PanLog
global total_matches
global TRACK_Match_count
global PAN_Match_count
global Match_Count
global FILE_count
global compiled_patterns

Match_Count = { "PAN" : 0, "TRACK" : 0 }
_DEBUG      = False
_TraceLog   = None
_PanLog     = None
total_matches = 0
TRACK_Match_count = 0 
PAN_Match_count = 0
FILE_count = 0
compiled_patterns = {}

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

## ===========================================================================
##  Create our logging objects
## ===========================================================================
def setup_custom_loggers(args):
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
        _TraceLog.warn(f"Skipping file due to PermissionError: {file_path}")
        return None
    
    except Exception as e:
        _TraceLog.error(f"Skipping file due to error: {file_path}: {e}")
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
        _PanLog.warn(f"Skipping file due to PermissionError: {file_path}")
        return None
    
    except Exception as e:
        _PanLog.error(f"Skipping file due to error: {file_path}: {e}")
    
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
    global total_matches
    global FILE_count
    global PAN_Match_count
    global TRACK_Match_count
    global Match_Count
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

            for line_number, text_line in enumerate(f, 1):
                line_count += 1
                if args.line_limit > 0 and line_count >= args.line_limit:
                    _TraceLog.info(f"-> Line Limit reached: stopped after {line_count} lines.")
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

                pan = extract_pan_from_match(match_data)                    
                if luhn_check(pan):
                    Match_Count[type] += 1
                    _TraceLog.info(f"-> {type}: {pan} (Luhn Check: Passed)")
                    _PanLog.info(f"-> {type}: {pan}: {matched_info}")
                else:
                    _TraceLog.info(f"-> TRACK: {pan} (Luhn Check: Failed)")

                if line_number % 100 == 0:
                    _PanLog.info(f"Scanned {FILE_count} files; matched {PAN_Match_count} PANs, {TRACK_Match_count} TRACKs")

    except PermissionError:
        _TraceLog.warn(f"Skipping file due to PermissionError: {file_path}")


##  ===========================================================================
##  Match REGEX patterns from the JSON data
##  ===========================================================================
def match_regex(text_line, line_number, json_data):
    for section_name, section_data in json_data.items():
        # print(f"Checking section: {section_name}")
        for pattern_name, pattern_info in section_data.items():
            regex_pattern = pattern_info['regex']
            match = re.search(regex_pattern, text_line)
            if match:
                regex_info = f"{section_name} '{pattern_name}': {regex_pattern}"
                # print(f"{regex_info} in line: {line_number}")
                return regex_info,match.group(0)

    ## print(f"No match found for {text_line}")
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
    
    if os.name == 'nt': # Windows, using SysInternals sdelete; download from https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
        subprocess.run(['sdelete64.exe', file_path])


##  ===========================================================================
##  Compile JSON prefix patterns
##  ===========================================================================
def load_json_data(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None

##  ===========================================================================
##  Compile Patterns
##  ===========================================================================
def compile_pan_patterns(data):
    global compiled_data
    compiled_data = {}
    anti_pan_data = {}
    track_data = {}
    pan_data = {}

    for category, patterns in data.items():
        if category.lower().startswith('anti-pan'):
            for pattern_name, info in patterns.items():
                pattern = re.compile(info['regex'])
                anti_pan_data[pattern_name] = {'pattern': pattern, 'length': info['length']}
        
        if category.lower().startswith('track'):
            for pattern_name, info in patterns.items():
                pattern = re.compile(info['regex'])
                track_data[pattern_name] = {'pattern': pattern, 'length': info['length']}
        
        if category.lower().startswith('pan'):
            for pattern_name, info in patterns.items():
                pattern = re.compile(info['regex'])
                pan_data[pattern_name] = {'pattern': pattern, 'length': info['length']}
    
    # Merge track data, anti-PAN data, and PAN data at the beginning of the dictionary
    compiled_data = {**anti_pan_data, **track_data, **pan_data}
    return compiled_data


##  ===========================================================================
##  Enumerate command line arguments
##  ===========================================================================
def enumerate_command_line_arguments(args):
    # command_line = ' '.join(sys.argv)
    argument_list = ['']
    for arg, value in vars(args).items():
        argument_list.append(f'--{arg}={value}\n')
    return '\nParameters and Defaults\n' + ' '.join(argument_list)


def load_json_data(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            return data
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None


##  ===========================================================================
##  Main
##  ===========================================================================
def main(args):

    # Load JSON data and compile prefix patterns
    json_filename = os.path.join(os.getcwd(), 'patterns/find-pan-patterns.json')
    json_data = load_json_data(json_filename)
    if json_data:
        # pan_patterns = compile_pan_patterns(json_data)
        pan_patterns = {}
        if _DEBUG:
            formatted_pan_patterns = json.dumps(json_data, indent=4)
            print(formatted_pan_patterns)
    else:
        print("Error: No JSON data found.")
        return

    if args.path:
        _TraceLog.info(f"Scanning {args.path} ...")
        scan_directory(args.path, pan_patterns, json_data )
        return
    
    if args.tar and args.temp:
        _TraceLog.info(f"Scanning {args.tar} ...")
        with tarfile.open(args.tar, 'r:*') as tar:
            for tarinfo in tar:
                if tarinfo.isreg():
                    temp_path = os.path.join(args.temp, tarinfo.name)
                    tar.extract(tarinfo, path=args.temp)
                    process_file(temp_path, compiled_patterns )
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
    ##  =========================================================================== 
    ##  Debugging configuration here
    ##  ===========================================================================
    # args = parser.parse_args(['--path', test_data_path, '--verbose'] )
    test_data_path = os.path.join(os.getcwd(), 'test-data')
    args = parser.parse_args(['--path', test_data_path] )

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


