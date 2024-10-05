#!/usr/bin/env python3
import json
import os
# import sys
import re

# Function to generate a dictionary of regexes from a JSON file
def generate_regex_dict(json_data):
    try:
        # Initialize an empty dictionary to store regexes for this pattern
        pattern_dict: dict = {}

        # Iterate over each pattern name in the data
        for pattern_name, patterns in json_data.items():
            print(f"Pattern name=[{pattern_name}]")

            # Skip patterns with less than 2 regexes
            if len(patterns) < 2:
                print(f"SKIPPING: [{pattern_name}]")
                continue

            pattern_dict[pattern_name] = patterns
            print(f"\n1: pattern_dict[{pattern_name}] size: {len(pattern_dict[pattern_name])}")

            # Iterate over each regex for this pattern
            for name, value in pattern_dict[pattern_name].items():
                print(f" -> NAME  = {name}")
                expressions = value['regex']

                print(f"2: expressions size: {len(expressions)}")
                print(f"2: expressions = {expressions}")

                compiled_expressions = []
                for regex in expressions:
                    # print(f"   -> {name}:regex = {regex}")

                    # Compile the regex and store it under the 'compile' key
                    compiled_regex = re.compile(regex)
                    compiled_expressions.append(compiled_regex)
                    print(f"   -> {name}:compiled = {compiled_regex}")

                # Add the compiled regex list under the 'compile' key
                pattern_dict[pattern_name][name]['compile'] = compiled_expressions

        return pattern_dict

    except Exception as e:
        print(f"Error: {e}")
        return None

##  --------------------------------------------
##  --------------------------------------------


json_file = os.path.join(os.environ["HOME"], "Projects/W1T3H4T/Find-PAN/etc/find-pan-patterns.json")
if not json_file.endswith(".json"):
    raise ValueError("main: Invalid JSON file format")

try:
    with open(json_file, "r", encoding="utf-8", errors="replace") as f:
        json_data = json.load(f)
except Exception as e:
    print(f"main: Error reading JSON file: {e}")

# Generate regex dictionary
_JSON_Patterns_Dict = generate_regex_dict(json_data)
print(f"3: Dictionary Size: {len(_JSON_Patterns_Dict)}")



