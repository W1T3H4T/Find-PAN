#!/usr/bin/env python3
#  ===========================================================================
#  File    :    regex-test.py
#  Function:    Remove log files of a certain age
#  Who     :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================
#  MIT License
#  
#  Copyright (c) 2023 David Means <w1t3h4t@gmail.com>
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

"""
This script identifies suspect patterns within a list of strings using regular expressions.

The script defines a set of suspect patterns and iterates over a list of strings to find matches.
Each string is checked against all the suspect patterns, and for each match found, a message is printed.
"""
import re

def match_suspect_pattern(test_str, pattern):
    """
    Searches for a suspect pattern within a given string.
    
    Args:
        test_str (str): The string to search within.
        pattern (str): The regular expression pattern to search for.
        
    Returns:
        str or None: The first match found or None if no match is found.
    """
    matches = re.search(pattern, str(test_str))
    return matches[0] if matches else None

def matched(rc):
    """
    Determines the match status based on the input.

    Args:
        rc (str or None): The result from match_suspect_pattern.
        
    Returns:
        str: 'Matched' if rc is not None, 'No match' otherwise.
    """
    return 'Matched' if rc else 'No match'

# Patterns
false_positive_patterns = {
    'X': r"(\d)\1{3,}",
    '1': r'([3456]\d{3,5})\1+',
    '2': r'[3456](\d)\1{2}(([0-9](\d)\1{2}){3})',
    '3': r'^(?=.{12,19}$)6?5?4321[0]+'
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

for p in test_patterns:
    for pattern_key, pattern_val in false_positive_patterns.items():
        rc = match_suspect_pattern(p, pattern_val)
        print(f"str: Suspect Pattern {rc} ({matched(rc)}): {pattern_key} ({p} {pattern_val})")
    print("")

