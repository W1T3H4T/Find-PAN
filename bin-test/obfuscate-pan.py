#!/usr/bin/env python3
#   ===========================================================================
#   File    :   obfuscate-pan.py
#   Function:   Apply PCI PAN obfuscation rules.
#   Who     :   David Means <w1t3h4t@gmail.com>
#   ===========================================================================

import re
import sys

unique_numbers = set()  # Store unique obfuscated numbers
card_pattern = r"(\d{6})(\d+)(\d{4}$)"  # Regex for card pattern


#   =================================================================
#   Function to replace the middle digits with '*' and add two
#   hyphens evenly spaced
#   =================================================================
def replace_with_asterisks_and_hyphens(match):
    first_group, second_group, third_group = match.groups()
    # Insert two hyphens
    hyphens = '*' * len(second_group)
    return f"{first_group}-{hyphens}-{third_group}"


#   =================================================================
#   Obfuscate card numbers and remove the match pattern from the output
#   =================================================================
def process_line(input_text):
    if input_text[0] == ";":
        return None
    cleaned_text = re.sub(r"^.+match='", "", input_text)
    cleaned_text = re.sub(r"[>'\n\r]", "", cleaned_text)
    return cleaned_text


#   =================================================================
#   MAIN: Read from stdin and process each line
#   =================================================================
def main():
    for line in sys.stdin:
        # Extract numbers and sort uniquely
        number = process_line(line)
        if number is not None:
            unique_numbers.add(number)

    #   Generate and print the obfuscated PAN
    for number in unique_numbers:
        obfuscated_text = re.sub(
            card_pattern,
            replace_with_asterisks_and_hyphens,
            number)
        print(f"{obfuscated_text}")


#   =================================================================
#   Call our main function
#   =================================================================
if __name__ == '__main__':
    main()
