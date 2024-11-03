#!/usr/bin/env python3
import json
import os
import re
import sys
import traceback
ProgramName = None
# pylint: disable=broad-exception-caught

# ===========================================================================
# Print consolidated exception info
# ===========================================================================


def print_exception_info(e: Exception) -> None:
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
# Find the JSON pattern file
# ===========================================================================
def find_json_regex_config() -> str:
    try:
        config_paths = [
            os.environ.get("XDG_CONFIG_HOME"),
            os.path.join(os.path.expanduser("~"), ".config"),
            os.path.join(os.path.expanduser("~"), ".local"),
            os.path.join(os.path.expanduser("~"), ".local/share"),
            "/usr/local"
        ]

        # Find the first valid config path
        for config_path in config_paths:
            find_pan_dir = os.path.join(config_path, "find-pan")
            json_file_path = os.path.join(find_pan_dir, "find-pan.json")

            if os.path.exists(json_file_path):
                print(f"Using configuration file: {json_file_path}\n")
                return json_file_path

        # Raise error if none of the paths exist
        raise FileNotFoundError("JSON configuration file not found")
    except (FileNotFoundError, IOError, Exception) as e:
        print_exception_info(e)

    return None


# ===========================================================================
# Load JSON File
# ===========================================================================
def load_json_data(filename: str) -> dict | None:
    try:
        with open(filename, "r", encoding="utf-8", errors="replace") as file:
            data = json.load(file)
            return data

    except (FileNotFoundError, IOError, Exception) as e:
        print_exception_info(e)
    return None


# ===========================================================================
# Calculate pattern_1 size
# ===========================================================================
def calculate_pattern1_size(pattern, pattern_name):
    try:
        def calculate_subpattern_size(subpattern):
            # Count length, treating anything inside [] as a single character
            size = 0
            # Find parts outside brackets and count their length
            parts = re.findall(r'[a-zA-Z0-9]+|\[.*?\]', subpattern)
            for part in parts:
                if '[' in part:
                    size += 1  # Count bracketed part as 1 character
                else:
                    size += len(part)  # Count literal characters
            return size

        # Extract the part inside the parentheses for pattern1
        match = re.search(r"\(([^)]+)\)", pattern)
        if match:
            # Split by '|' to find alternatives inside parentheses
            options = match.group(1).split('|')
            # Get the size of the first pattern as the base length
            base_length = calculate_subpattern_size(options[0])
            # Ensure all other options have the same length
            for option in options[1:]:
                option_length = calculate_subpattern_size(option)
                if option_length != base_length:
                    raise ValueError(
                        f"Pattern length mismatch in {pattern_name}: {pattern}")
            return base_length
    except Exception as e:
        print_exception_info(e)

    return 0


# ===========================================================================
# Calculate pattern_2 size
# ===========================================================================
def calculate_pattern2_size(pattern):
    # For digit ranges like [0-9], it always represents a single
    # digit (1 character)
    return 1


# ===========================================================================
# Calculate pattern_3 size
# ===========================================================================
def calculate_pattern3_size(pattern):
    # Find the range inside the curly braces {min,max}
    match = re.search(r"\{(\d+),(\d+)\}", pattern)
    if match:
        # The second number (max) is the largest possible length
        return int(match.group(2))
    # Handle the case where there is only one number inside braces {min}
    match = re.search(r"\{(\d+)\}", pattern)
    if match:
        return int(match.group(1))
    return 0


# ===========================================================================
# Calculate total regex pattern size
# ===========================================================================
def calculate_total_size(pattern, pattern_name):
    # Calculate sizes of each component
    pattern1_size = calculate_pattern1_size(pattern, pattern_name)
    pattern2_size = calculate_pattern2_size(pattern)
    pattern3_size = calculate_pattern3_size(pattern)

    # Sum the sizes
    # total_size = pattern1_size + pattern2_size + pattern3_size
    total_size = pattern1_size + pattern2_size * pattern3_size
    return total_size, pattern1_size, pattern2_size, pattern3_size


# ===========================================================================
# Validate the regular expression size against length
# ===========================================================================
# Function to validate the regex patterns against the specified length
def validate_pan_patterns(json_data):
    pan_patterns = json_data.get("PAN Pattern", {})
    for card_type, card_data in pan_patterns.items():
        regex_patterns = card_data.get("regex", [])
        specified_length = card_data.get("length")
        for p in regex_patterns:
            total_size, pattern1_size, pattern2_size, pattern3_size = calculate_total_size(
                p, card_type)
            print(f"Card Type: {card_type}\n"
                  f"Regex: {p}\n"
                  f"Expected: {specified_length}\n"
                  f"Actual: {total_size} = sum(P1={pattern1_size}, P2={pattern2_size} * P3={pattern3_size})\n")


if __name__ == "__main__":
    # Validate the patterns
    ProgramName = os.path.basename(sys.argv[0])
    validate_pan_patterns(load_json_data(find_json_regex_config()))
    print("Success")
