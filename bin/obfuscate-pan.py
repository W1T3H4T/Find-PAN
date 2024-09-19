#!/usr/bin/env python3
#   ===========================================================================
#   File    :   obfuscate-pan.py
#   Function:   Apply PCI PAN obfuscation rules.
#   Who     :   David Means <w1t3h4t@gmail.com>
#   ===========================================================================
#   MIT License
#
#   Copyright (c) 2023 David Means
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#   ===========================================================================import re
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
