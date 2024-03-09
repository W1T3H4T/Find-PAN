#!/usr/bin/env python3
import re
import sys

# Function to replace the middle digits with '*' and add two hyphens evenly spaced
def replace_with_asterisks_and_hyphens(match):
    first_group, second_group, third_group = match.groups()
    # Insert two hyphens
    hyphens = '*' * len(second_group)
    return f"{first_group}-{hyphens}-{third_group}"


def process_line(input_text):
    # Obfuscate card numbers and remove the match pattern from the output
    if input_text[0] == ";": return None
    cleaned_text = re.sub(r"^.+match='", "", input_text)
    cleaned_text = re.sub(r"[>'\n\r]", "", cleaned_text)
    return cleaned_text


# Store unique obfuscated numbers
unique_numbers = set()
card_pattern = r"(\d{6})(\d+)(\d{4}$)"

# Read from stdin and process each line
for line in sys.stdin:
    # Extract numbers and sort uniquely
    number = process_line(line)
    if not number is None:
        unique_numbers.add(number)

for number in unique_numbers:
    obfuscated_text = re.sub( card_pattern, replace_with_asterisks_and_hyphens, number )
    print(f"{obfuscated_text}")


