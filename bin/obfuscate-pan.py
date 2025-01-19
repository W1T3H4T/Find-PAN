#!/usr/bin/env python3
#   ===========================================================================
#   File    :   obfuscate-pan.py
#   Function:   Apply PCI PAN obfuscation rules.
#   Who     :   David Means <w1t3h4t@gmail.com>
#   What    :   This script reads a file containing PAN numbers and obfuscates
#               them according to PCI rules. The script reads the file line by
#               line and extracts the PAN numbers. It then obfuscates the PAN
#               numbers by replacing the middle digits with asterisks and
#               adding two hyphens evenly spaced. The script then prints the
#               obfuscated PAN numbers to stdout.
#   ===========================================================================

import argparse
import json
import os
import re
import sys

_Compiled_Patterns = []
_Json_Data = {}
_Args = None
_Parser = None

#   =================================================================
#   Load the JSON file and return its contents.
#   =================================================================


def load_json(json_file):
    # pylint: disable=broad-exception-caught
    try:
        with open(json_file, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)

    except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
        print(f"Error loading JSON file: {e}")
    except Exception as e:
        print(
            f"An unexpected error occurred while loading the JSON file {json_file}: {e}"
        )
    return {}


# ===========================================================================
# Extract PAN from track data
# ===========================================================================
def extract_pan_from_match(match_data) -> str:
    # Assuming Track 1 & 2 Data
    if match_data.startswith("%B") or match_data.startswith("%M"):
        return re.sub(r"\D", "", match_data[2:].split("^")[0])

    if match_data.startswith(";"):
        return re.sub(r"\D", "", match_data[1:].split("=")[0])

    # Otherwise, we probably have a matching pan.
    # Return the digits we find.
    return re.sub(r"\D", "", match_data)


#   =================================================================
#   Compile the regex patterns found in the JSON data.
#   =================================================================
def compile_regex_patterns(json_data: dict) -> []:
    # pylint: disable=broad-exception-caught,too-many-nested-blocks
    try:
        compiled_patterns = []
        for category, patterns in json_data.items():
            print(f"{os.path.basename(_Args.json)} category: {category}")
            if isinstance(patterns, dict):
                for pattern_name, details in patterns.items():
                    if "regex" in details:
                        for pattern in details["regex"]:
                            compiled_patterns.append(
                                (category, pattern_name, re.compile(pattern))
                            )
        return compiled_patterns

    except (re.error, TypeError, KeyError) as e:
        print(f"Error compiling regex patterns: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return []


#   =================================================================
#   Recursively find all files in a directory.
#   =================================================================
def get_files_in_directory(directory: str) -> []:
    # pylint: disable=broad-exception-caught
    try:
        files = []
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files

    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(
            f"An unexpected error occurred while accessing the directory {directory}: {e}"
        )
    return []


#   =================================================================
#   Process all files in a directory.
#   =================================================================
def process_files_in_directory(directory: str, compiled_patterns: list):
    # pylint: disable=broad-exception-caught
    try:
        files = get_files_in_directory(directory)
        for file in files:
            process_file(file, compiled_patterns)
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(
            f"An unexpected error occurred while processing the directory {directory}: {e}"
        )


#   =================================================================
#   Search for PAN and TRACK data in the file.
#   =================================================================
def process_file(file_path, compiled_patterns):
    # pylint: disable=broad-exception-caught,too-many-nested-blocks
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                for category, pattern_name, compiled_pattern in compiled_patterns:
                    match_data = compiled_pattern.search(line)
                    if match_data:
                        m_data = extract_pan_from_match(match_data.group())
                        print(
                            f"{file_path} line {line_num}: {category} {pattern_name} obfuscated PAN: "
                            f"{m_data[:6]}{'*' * 6}{m_data[-4:]}"  # noqa: E501
                        )
                        break

    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(
            f"An unexpected error occurred while processing the file {file_path}: {e}"
        )


#   =================================================================
#   Parse command line arguments
#   =================================================================
def parse_arguments():
    parser = argparse.ArgumentParser(description="Obfuscate PAN in one or more files.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Input file")
    group.add_argument("--dir", help="Input Directory")
    parser.add_argument("--json", required=True, help="JSON file")
    return parser


#   =================================================================
#   MAIN: Read from file or directory and process each line
#   =================================================================
if __name__ == "__main__":
    _Compiled_Patterns = []
    _Parser = parse_arguments()
    _Args = _Parser.parse_args()
    _Json_Data = load_json(_Args.json)
    _Compiled_Patterns = compile_regex_patterns(_Json_Data)

    if _Args.file:
        process_file(_Args.file, _Compiled_Patterns)

    elif _Args.dir:
        process_files_in_directory(_Args.dir, _Compiled_Patterns)

    else:
        _Parser.print_help()
        sys.exit(1)
