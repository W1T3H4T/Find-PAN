#!/usr/bin/env python3
#  ===========================================================================
#  File    :    speed-test.py
#  Function:    Compiled vs. Non-compiled speed test
#  Who     :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================

"""
Module speed_test

This script performs a pattern matching speed test between compiled and 
non-compile regular expressions.
"""
import os
import re
import sys
import json
import time

_RegexPatternPrefix = r"[ '\"{]"


def load_json(json_file):
    """Load the JSON file and return its contents."""
    with open(json_file, "r") as f:
        return json.load(f)


def get_files_in_directory(directory):
    """Get all files from the given directory."""
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_list.append(os.path.join(root, file))
    return file_list


def compile_regex_patterns_with_prefix(json_data):
    """Compile the regex patterns found in the JSON data."""
    compiled_patterns = []

    for category, patterns in json_data.items():
        if isinstance(patterns, dict):
            for pattern_name, details in patterns.items():
                if "regex" in details:
                    for pattern in details["regex"]:
                        prefix_pattern = f"{_RegexPatternPrefix}{pattern}"
                        compiled_patterns.append((category, pattern_name, re.compile(prefix_pattern)))

    return compiled_patterns


def compile_regex_patterns(json_data:dict) -> []:
    """Compile the regex patterns found in the JSON data."""
    compiled_patterns = []

    for category, patterns in json_data.items():
        print(f"category: {category}")
        if isinstance(patterns, dict):
            for pattern_name, details in patterns.items():
                if "regex" in details:
                    for pattern in details["regex"]:
                        compiled_patterns.append((category, pattern_name, re.compile(pattern)))

    return compiled_patterns


def test_precompiled_patterns(file_path, compiled_patterns):
    """Test each line of the file against pre-compiled regex patterns."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            for category, pattern_name, compiled_pattern in compiled_patterns:
                if compiled_pattern.search(line):
                    # For benchmarking purposes, we avoid printing the matches.
                    break


def test_noncompiled_patterns(file_path, json_data):
    """Test each line of the file against non-compiled regex patterns."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            for category, patterns in json_data.items():
                if isinstance(patterns, dict):
                    for pattern_name, details in patterns.items():
                        if "regex" in details:
                            for pattern in details["regex"]:
                                if re.search(pattern, line):
                                    # For benchmarking purposes, we avoid printing the matches.
                                    break


def benchmark(function, file_path, *args):
    """Benchmark the execution time of a given function."""
    start_time = time.time()
    function(file_path, *args)
    end_time = time.time()
    return end_time - start_time


def print_patterns(patterns):
    """
    Prints the contents of a list of tuples containing pattern names, descriptions, and compiled regex patterns in a human-readable format.

    Args:
        patterns (list): A list of tuples where each tuple contains a pattern name, description, and a compiled regex pattern.
    """
    name = None
    desc = None
    pattern = None
    lastDesc = "start"

    for name, desc, pattern in patterns:

        if desc != lastDesc:
            print("-" * 40)
            print(f"Pattern Name: {name}, Description: {desc}")
            lastDesc = desc
        print(f"Regex Pattern: {pattern.pattern}")



# Function to calculate Delta Percent between runs
def delta_percent(first, second):
    if first > second:
        change = first - second 
        delta = ( change / second ) * 100 
        return round(delta, 2)  # Round to two decimal places for percentage
    elif second > first:
        change = second - first
        delta = ( change / first ) * 100 
        return round(delta * -1, 2)  # Round to two decimal places for percentage
    else:
        raise ValueError("Both pre and post-observation times must be positive.")

def main(json_file, directory):
    """Main function to load JSON, compile regex, and benchmark performance."""
    # Load JSON data
    json_data = load_json(json_file)

    # Compile regex patterns
    compiled_patterns = compile_regex_patterns(json_data)
    compiled_prefix_patterns = compile_regex_patterns_with_prefix(json_data)

    # Get all files in the directory
    files = get_files_in_directory(directory)

    #print("=" * 50)
    #print_patterns(compiled_patterns)
    #print("=" * 50)
    #print_patterns(compiled_prefix_patterns)
    #print("=" * 50)

    # Benchmark the pre-compiled regex performance
    precompiled_time: float = 0.0
    noncompiled_time: float = 0.0
    count: int = 0
    for file_path in files:
        precompiled_time += benchmark(test_precompiled_patterns, file_path, compiled_patterns)
        noncompiled_time += benchmark(test_noncompiled_patterns, file_path, json_data)

        count += 1
        if count % 10 == 0:
            print(f"Processed {count} files...")
        # print(f"File: {file_path}")
        # print(f"Precompiled regex time: {precompiled_time:.4f} seconds")
        # print(f"Non-compiled regex time: {noncompiled_time:.4f} seconds")
        # print("-" * 50)

    print("")
    print("-" * 50)
    print(f"Precompiled regex time  : {precompiled_time:.4f} seconds")
    print(f"Non-compiled regex time : {noncompiled_time:.4f} seconds")
    delta  = delta_percent(noncompiled_time, precompiled_time)
    print("-" * 50)
    print(f"Pre-compiled improvement: {delta:6.2f}%")
    print("-" * 50)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py <json_file> <directory>")
        sys.exit(1)

    json_file = sys.argv[1]
    directory = sys.argv[2]

    main(json_file, directory)
