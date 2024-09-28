#!/usr/bin/env python3
#  ===========================================================================
#  File    :    regex-test.py
#  Function:    Regular expression test
#  Who     :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================

"""
Module regex_test

This script assists in identifying false-positive and true-positive patterns
by making use of a JSON file containing regex patterns, and manually configured
test data.
"""

import argparse
import json
import os
import re
import sys
import traceback

# - Declare and initialize
ProgramName = None
_Parser = None
_Args = None

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

    print("-----------------------------------------------------------------")
    print("Exception Information:")
    print(f"Function: '{func_name}', on line {line_number}")
    print(f"File    : {file_name}")
    print(f"Type    : {exc_type.__name__}")
    print(f"Message : {exception_message}")
    if str(e).lower() != str(exception_message).lower():
        print(f"Info    : {e}")
    print("-----------------------------------------------------------------")
    sys.exit(1)


# ===========================================================================
# Get a REGEX pattern from our JSON file
# ===========================================================================
def get_regex_from_json(json_data: dict, key: str) -> list:
    """
    This function returns the regex patterns associated with a given key from the JSON data.

    :param json_data: The loaded JSON data in dictionary format
    :param key: The key for which to retrieve the regex patterns (e.g., "VISA")
    :return: A list of regex patterns associated with the key
    """
    # Navigate to the "PAN Pattern" section of the JSON
    pan_pattern = json_data.get("PAN Pattern", {})

    # Get the regex associated with the given key, default to an empty list if the key is not found
    if key in pan_pattern:
        return pan_pattern[key].get("regex", [])

    return []


# ===========================================================================
# Load JSON REGEX patterns
# ===========================================================================
def load_json_data(filename: str = None):

    data = {}
    if filename is not None:
        try:
            with open(filename, 'r', encoding="utf-8", errors="replace") as file:
                data = json.load(file)

        except FileNotFoundError:
            print_exception_info(f"Error: File '{filename}' not found.")
        except Exception as e:  # pylint: disable=broad-exception-caught
            print_exception_info(e)

    return data

# ===========================================================================
# Checking a matched return value
# ===========================================================================


def check_matched(MyRc):
    return 'Matched' if MyRc else 'No match'

# ===========================================================================
# Match a 'suspect' pattern
# ===========================================================================


def match_suspect_pattern(test_str: str = None, pattern: str = None) -> str:
    if (test_str is not None) and (pattern is not None):
        matches = re.search(pattern, str(test_str))
        return matches[0]
    return None


# Patterns
false_positive_patterns = {
    'X': r"(\d)\1{3,}",  # 1230000123
    '1': r'([3456]\d{3,5})\1+',  # 112233445566
    '2': r'[3456](\d)\1{2}(([0-9](\d)\1{2}){3})',  # 112233444455555666666
    '3': r'^(?=.{12,19}$)6?5?4321[0]+'  # 6543210000000000000
}

# Example usage
test_patterns = [
    "1230000123",
    "112233445566",
    "112233444455555666666",
    "4112344112344113",
    "4000300020001000",
    "6543210000000000000",
    "654321777777777777",
    "6543219999999999",
    "543218888888888",
    "43210000000000",
    "4321321321321",
    "432100000000",
    "43210000000",
    "65432100000333311111"
]

# ===========================================================================
# Process a file for credit card patterns
# ===========================================================================


def process_file(json_data: dict = None, file: str = None, key: str = None):

    regex = ""
    match_count = 0
    matched = None

    try:
        print(f"Scanning {os.path.basename(file)}")
        patterns = get_regex_from_json(json_data, key)

        with open(file, "r", encoding="utf-8", errors="replace") as f:
            for line_number, text_line in enumerate(f, 1):
                for regex in patterns:
                    matched = re.match(regex, text_line)

                    if matched:
                        print(f"-> {line_number}: Matched {regex}: {text_line.strip()}")
                        match_count += 1
                        break

        if match_count == 0:
            print(f"-> No matches for '{key.strip()}' pattern")

    except PermissionError:
        print("Skipping file due to PermissionError: %s", file)

    except FileNotFoundError:
        print("Skipping file due to FileNotFoundError: %s", file)

    except IOError as e:
        print("Skipping file due to IOError: %s - %s", file, e)

    except Exception as e:  # pylint: disable=broad-exception-caught
        print_exception_info(f'{e}')


# ===========================================================================
# Check parameters for processing via JSON regex
# ===========================================================================
def validate_process_requirements() -> bool:
    if _Args.file is None:
        print("Error: --file is a required parameter.")
        return False

    if not os.path.exists(_Args.file):
        print(f"Error: file {_Args.file} does not exist.")
        return False

    if _Args.json is None:
        print("Error: --json is a required parameter.")
        return False

    if not os.path.exists(_Args.json):
        print(f"Error: file {_Args.json} does not exist.")
        return False

    if _Args.key is None:
        print("Error: --key is a required parameter.")
        return False

    return True


# ===========================================================================
#   __main__
# ===========================================================================
_Parser = argparse.ArgumentParser(
    description='Testing Regex for PCI PAN and TRACK data patterns.',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
_Parser.add_argument('--file', help='File to scan.', type=str, default=None)
_Parser.add_argument('--json', help='JSON Regex data.', type=str, default=None)
_Parser.add_argument('--key', help='The key in the JSON data file to test', type=str, default=None)
_Parser.add_argument('--test', help='Run test patterns', action='store_true', default=False)
_Args = _Parser.parse_args()
ProgramName = _Parser.prog

if _Args.test:
    for p in test_patterns:
        print("")
        print("Testing False Positive Patterns")
        print("")
        for pattern_key, pattern_val in false_positive_patterns.items():
            rc = match_suspect_pattern(p, pattern_val)
            print(
                f"Suspect Pattern {rc} ({check_matched(rc)}): "
                f"{pattern_key} ({p} {pattern_val})")
        print("")

else:
    if validate_process_requirements():
        print("")
        print("Testing JSON Regex Pattern(s)")
        print("")
        process_file(load_json_data(_Args.json), _Args.file, _Args.key)
    else:
        _Parser.print_help()
        sys.exit(1)

sys.exit(0)
