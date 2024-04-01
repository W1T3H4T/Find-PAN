#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    create-pan-data.py
#  Function:    Create test patterns for credit card numbers
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

import random
import re
import json
import os
global MAX_COUNT
MAX_COUNT = 100


##  ===========================================================================
##  Pattern generation functions
##  ===========================================================================
def process_pattern_data(pattern_data, card_type):
    integers_array = []
    ## print(f"## Processing {card_type} with pattern {pattern_data}")

    patterns = pattern_data.split('|')

    for pattern in patterns:
        if '[' in pattern and ']' in pattern:
            # Extract the integer and range from the pattern using a corrected regular expression
            match = re.match(r'(\d+)\[(\d+)-(\d+)\]', pattern)
            if match:
                integer_part, start, end = match.groups()
                # Convert to integers
                integer = int(integer_part)
                start, end = int(start), int(end)
                # Append the integer and the range values to the array
                integers_array.extend([integer * 10 + num for num in range(start, end + 1)])
        elif pattern.isdigit():
            # Append the integer to the array
            integers_array.append(int(pattern))

    return integers_array

##  ===========================================================================
##  Pattern generation functions
##  ===========================================================================
def get_card_prefix_digits(json_data, card_type):
    card_regex = json_data['PAN Patterns'][card_type]['regex']
    
    # Regular expression to match a string surrounded by parentheses
    regex_pattern = r'\((.*?)\)'

    # Search for the pattern within parentheses
    match = re.search(regex_pattern, card_regex)

    # If a match is found, return the string inside parentheses, otherwise return the pattern as is
    return match.group(1) if match else pattern


##  ===========================================================================
##  PAN generation functions
##  ===========================================================================
def generate_numbers(pattern):
    ## print(f"Pattern: {pattern}")
    if isinstance(pattern, str):
        if '-' in pattern:
            start, end = map(int, pattern.split('-'))
            numbers = [num for num in range(start, end + 1)]
    else:
        numbers = [int(pattern)]

    ## print(f"Numbers: {numbers}")
    return numbers

##  ===========================================================================
##  PAN generation functions
##  ===========================================================================

def generate_pan_numbers(json_data, card_type):
    card_pattern = json_data['PAN Patterns'][card_type]['regex']
    card_len_pattern = json_data['PAN Patterns'][card_type]['length']
    numbers = generate_numbers(card_len_pattern)
    prefix_string = get_card_prefix_digits(json_data, card_type)
    prefixes = process_pattern_data( prefix_string, card_type)

    i = 0
    j = 0
    pan_array = []
    while j < len(prefixes):
        i = 0
        while i < len(numbers):
            card_length = numbers[i]
            pan = ""
            while len(str(pan)) < card_length-1 :
                pan = prefixes[j]
                # Generate random numbers for the PAN
                pan = str(pan) 
                pan += ''.join(random.choice('0123456789') for _ in range(card_length - 1))
                ## print(f"Generated PAN: {pan} with length: {card_length}")
                
                # If the PAN is too long, remove the last digit
                pan = pan[:card_length - 1]
        
                # Append the Luhn check digit to complete the PAN
                pan += calculate_luhn_digit(str(pan))
                if not luhn_check(pan):
                    continue
        
                # Check if the generated PAN matches the VISA pattern
                # Match the PAN against the regular expression
                ## print(f"Checking PAN: {pan} with pattern: {card_pattern}")
                if re.match(card_pattern, pan):
                    ## print(f"Valid PAN: {pan}")
                    pan_array.append(pan)
                else:
                    ## print(f"Invalid PAN: {pan}")
                    continue
            i += 1
        j += 1

    return pan_array


def luhn_check(num):
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0  
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0

def calculate_luhn_digit(pan):
    ## print(f"Calculating Luhn digit for {pan}")
    digits = list(map(int, pan))
    checksum = sum(digits[-1::-2]) + sum(sum(divmod(2 * d, 10)) for d in digits[-2::-2])
    return str((10 - checksum % 10) % 10)

##  ===========================================================================
##  Helper functions
##  ===========================================================================

def load_json_data(file_path):
    with open(file_path, 'r') as json_file:
        return json.load(json_file)

def get_pan_pattern_sections(json_data):
        if 'PAN Patterns' in json_data:
            pan_patterns = json_data['PAN Patterns']
            return list(pan_patterns.keys())
        else:
            return []

##  ===========================================================================
##  Main
##  ===========================================================================

# Load JSON data from file
json_file_path = os.path.join(os.getcwd(), 'patterns/find-pan-patterns.json')
json_data = load_json_data(json_file_path)

# Print the generated VISA PAN numbers
for card_name in get_pan_pattern_sections(json_data):
    integer_pattern = get_card_prefix_digits(json_data, card_name)
    card_prefixes = process_pattern_data(integer_pattern, card_name)

    print( "##  ====================================================================")
    print(f"##  {card_name} - {integer_pattern} - {card_prefixes}")
    print( "##  ====================================================================")
    count = 0
    while count < MAX_COUNT:
        pan_data = generate_pan_numbers(json_data, card_name)
        for pan in pan_data:
            print(pan)
        count += 1
    
