#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    create-pan-data.py
#  Function:    Create test patterns for credit card numbers
#  Author  :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================

import argparse
import json
import os
import random
import re
import sys
import traceback

# _JSONPtrnPrefixPath = "/usr/local/Find-PAN/patterns"
_JSONPtrnPrefixPath = "/Users/dmeans/Library/CloudStorage/OneDrive-Personal/Projects/W1T3H4T/Find-PAN/patterns"
_EnableVSArgParams = False
_Parse_Arge = ""

# ===========================================================================
# log_debug()
# ===========================================================================
def log_debug(message: str, myFile=sys.stderr) -> None:
    if message is None:
        return

    if _Parse_Args.debug == True:
        if message[0] != '-':
            print("",file=myFile)
        print(message, file=myFile)


# ===========================================================================
# Print consolidated exception info
# ===========================================================================
def print_exception_info(e):
    # pylint: disable=possibly-used-before-assignment
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_stack = traceback.extract_tb(exc_traceback)

    # Traverse the traceback to find the first call outside the current module
    for frame in reversed(tb_stack):
        if f"{_ProgramName}" in frame.filename:
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

    print(f"Exception occurred in function: '{func_name}', at line: {line_number}, in file: '{file_name}'")
    print(f"Exception type: {exc_type.__name__}, Message: {exception_message}")
    sys.exit(1)


# ===========================================================================
# Pattern generation functions
# ===========================================================================
def get_card_prefix_values(pattern_data: list[str], card_type: str) -> list[int]:
    """
    Return the discrete prefix values as a list

    :param: pattern_data    The pattern data related to card type
    :param: card_type       The card brand, e.g., Visa, Mastercard, American Express, etc
    """
    integers_array = []
    log_debug(f"get_card_prefix_values(pattern_data={pattern_data}, card_type={card_type})")

    for data in  pattern_data:
        patterns = data.split('|')

        for pattern in patterns:
            if '[' in pattern and ']' in pattern:
                # Extract the integer and range from the pattern using a corrected
                # regular expression
                match = re.match(r'(\d+)\[(\d+)-(\d+)\]', pattern)
                if match:
                    integer_part, start, end = match.groups()
                    # Convert to integers
                    integer = int(integer_part)
                    start, end = int(start), int(end)
                    # Append the integer and the range values to the array
                    integers_array.extend(
                        [integer * 10 + num for num in range(start, end + 1)])
            elif pattern.isdigit():
                # Append the integer to the array
                integers_array.append(int(pattern))

    return integers_array


# ===========================================================================
# get_card_prefix_pattern
# ===========================================================================
def get_card_prefix_pattern(JsonData, card_type):
    """
    This function returns the PAN prefix digits for card_type

    :param dict JsonData:   This variable contains the JSON data.
    :param str card_type:   credit card type, such as Visa, Mastercard, etc
    :return:                The prefix digits associated with 'card_type'
    :rtype: list
    """
    log_debug(f"get_card_prefix_pattern('JsonData', card_type={card_type})")

    card_regex_patterns = []
    json_cardtype_regex = []
    json_cardtype_regex = JsonData['PAN Pattern'][card_type]['regex']
    log_debug(f"-> Got REGEX {json_cardtype_regex} for {card_type}")

    # Extract the PAN/CARD prefix data from the regular expression(s)
    # used to detect the PAN data: extract the pattern surrounded by '()'
    regex_finder = r'\((.*?)\)'

    # Retrieve the prefix pattern data from within parentheses
    for data in json_cardtype_regex:
        match = re.search(regex_finder, data)
        if match:
            log_debug(f"-> Found: {match.group(1)}")
            card_regex_patterns.append(match.group(1))
        else:
            print(f"-> Couldn't find a '(pattern)' in {data} for {card_type}", file=sys.stderr)
            sys.exit(1)

    return card_regex_patterns


# ===========================================================================
# get_pan_length_values
# ===========================================================================
def get_pan_length_values( pattern=None ) ->list:
    """
    Returns a list PAN prefix numbers based on the pattern provided.

    :param str pattern: The pattern for generating numbers. The pattern can be a single
                        number or a range specified using a hyphen (e.g., "1-10" for numbers 1 to 10)
    :return: This function returns a list of numbers based on the input pattern. If
            the input pattern is a string containing a range separated by a hyphen (e.g., "1-5"), it generates a
            list of numbers within that range (inclusive). If the input pattern is a single number, it returns a
            list containing that single number.
    :rtype: list of int
    """
    log_debug(f"get_pan_length_values(pattern={pattern})")

    if pattern is None:
        print(f"Error: 'pattern' is {pattern}")
        sys.exit(1)

    numbers = []
    if isinstance(pattern, str):
        if '-' in pattern:
            numbers = []
            start, end = map(int, pattern.split('-'))
            numbers = list(range(start, end + 1))
        else:
            numbers.append(int(pattern))

    log_debug(f"-> Numbers='{numbers}'")
    return numbers


#   =================================================================
#   test_pan_with_pattern
#   =================================================================
def test_pan_with_pattern(pan: str, pattern: list[str], card_type: str) -> bool:
    """
    :param str pan:     The PAN to check
    :param str pattern: The regex to check the PAN
    :return:            True (pass) or False (faile)
    :rtype:             bool
    """
    log_debug(f"test_pan_with_pattern(pan={pan}, pattern={pattern})")
    if pan is None or pattern is None:
        print("-> Error: Required parameters for 'test_pan_with_pattern()' not found", file=sys.stderr)
        print(f"-> Error: 'pan' = [{pan}], 'pattern' = [{pattern}]'", file=sys.stderr)
        sys.exit(1)

    for regex in pattern:
        matches = re.search(regex, pan)

        if matches:
            log_debug(f"-> Found a valid PAN: {pan}!!")
            return True

    print(f"Error: No pattern match for pan={pan}, length={len(pan)}", file=sys.stderr)
    print(f"card type= {card_type}")
    print(f"pattern  = {regex}", file=sys.stderr)
    print(f"matches  = {matches}", file=sys.stderr)
    sys.exit(1)

#   =================================================================
#   generate_pan_for_length
#   =================================================================
def generate_pan_for_length(prefix=None, pan_length=0) -> str:
    """
    Create a PAN using a Prefix and a Length.

    :params prefix:     The card-type prefix
    :params length:     The length of the card type
    :returns:           The PAN
    :rtype:             The PAN as a string
    """

    log_debug(f"generate_pan_for_length(prefix={prefix}, length={pan_length})")

    if prefix is None or pan_length == 0: 
        print("Error: generate_pan_for_length() parameters invalid")
        print("Error: 'prefix' = [{prefix}], 'length' = [{length}]'")
        sys.exit(1)

    pan_length = int(pan_length)
    local_pan = str(prefix)

    # Generate random numbers for the PAN
    num_random_digits = pan_length - len(local_pan) - 1 
    if num_random_digits < 0:
        print("Error: Length is less than the prefix length.")
        sys.exit(1)

    for _ in range(num_random_digits):
        local_pan += random.choice('0123456789')

    log_debug(f"--> Generated PAN, value: {local_pan}") 

    # Append the Luhn check digit to complete the PAN
    local_pan += calculate_luhn_digit(str(local_pan))
    
    # Validate the length
    if len(local_pan) != pan_length:
        print(f"Error: PAN failed length check: expected {length}, derived {len(local_pan)}", file=sys.stderr)
        sys.exit(1)

    return local_pan


#   =================================================================
#   generate_pan_for_card_type 
#   =================================================================
def generate_pan_for_card_type(JsonData = None, card_type = None) -> list:
    """
    Generate valid PAN numbers based the provided card type and PAN pattern data.

    :param dict JsonData:   The JSON data of the PAN numbers
    :param str card_type:   The card-type being generated
    :return:                A list of PANs for the card-type 
    :rtype:                 List
    """
    log_debug(f"generate_pan_for_card_type(jsonData, card_type={card_type})") 

    pan_array = []
    try:
        pan_regex           = JsonData['PAN Pattern'][card_type]['regex']
        pan_length_pattern  = JsonData['PAN Pattern'][card_type]['length']
        pan_length_values   = get_pan_length_values(pan_length_pattern)
        pan_prefix_pattern  = get_card_prefix_pattern(JsonData, card_type)
        pan_prefix_values   = get_card_prefix_values(pan_prefix_pattern, card_type)

        message=""
        message =  f"-> pan_regex           : {pan_regex}\n" 
        message += f"-> pan_length_pattern  : {pan_length_pattern}\n" 
        message += f"-> pan_length_values   : {pan_length_values}\n"
        message += f"-> pan_prefix_pattern  : {pan_prefix_pattern}\n"
        message += f"-> pan_prefix_values   : {pan_prefix_values}"
        log_debug(message)
    
        prefix_index = 0
        pan_length_index = 0

        # -----------------------------------------------------
        # - Iterate through the PAN regex pan_prefix_values
        # -----------------------------------------------------
        for pan_prefix in pan_prefix_values:

            # -----------------------------------------------------
            # - Iterate through the PAN lengths for this pattern
            # -----------------------------------------------------
            for pan_length in pan_length_values: 

                local_pan = '4111111111111112' #  bad value
                while not luhn_check(local_pan):
                    local_pan = generate_pan_for_length(pan_prefix, pan_length)
                    if test_pan_with_pattern(local_pan, pan_regex, card_type):
                        log_debug(f"-> Saved {local_pan}")
                        pan_array.append(local_pan)
                    else:
                        local_pan = '4111111111111112' #  bad value

        return pan_array

    except Exception as e:
        print_exception_info(e)

    
def luhn_check(num):
    """
    Validate a given number using the Luhn algorithm to determine if it is a 
    valid credit card number.

    :param str num: A credit card number to validate.
    :return:        A boolean value indicating whether the input number passes the Luhn algorithm check.
    :rtype: bool
    """
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0


def calculate_luhn_digit(pan):
    """
    The function `calculate_luhn_digit` calculates the Luhn check digit for a given Primary Account
    Number (PAN).

    :param pan: The `pan` parameter in the `calculate_luhn_digit` function is expected to be a string
                representing a Primary Account Number (PAN). The function calculates and returns the Luhn check
                digit for the given PAN
    :return:    The function `calculate_luhn_digit` returns a string representing the Luhn digit calculated
                based on the input Primary Account Number (PAN).
    """
    digits = list(map(int, pan))
    checksum = sum(digits[-1::-2]) + sum(sum(divmod(2 * d, 10)) for d in digits[-2::-2])
    return str((10 - checksum % 10) % 10)


def load_json_data(file_path):
    """
    The function `load_json_data` reads and loads JSON data from a file specified by the `file_path`
    parameter.

    :param file_path:   The `file_path` parameter in the `load_json_data` function is a string that
                        represents the path to the JSON file that you want to load and read.
    :return:            The function `load_json_data` is returning the data loaded from the JSON file located at
                        the `file_path`.
    """
    with open(file_path, 'r') as json_file:
        return json.load(json_file)


def get_pan_pattern_sections(JsonData, section='PAN Pattern'):
    """
    The function `get_pan_pattern_sections` extracts keys (card brandss) from the 'PAN Pattern' section of a JSON data
    object.

    :param JsonData:   The JSON data itself.
    :return:            Thee list of regular expressions associated with 'PAN Pattern'
    """
    log_debug(f"get_pan_pattern_secions('JsonData', {section})")
    if section in JsonData:
        pan_patterns = JsonData[section]
        log_debug(f"-> PAN Card Brands='{pan_patterns.keys()}")
        return list(pan_patterns.keys())
    else:
        return []


def format_pan(pan):
    """
    The function `format_pan` formats a PAN (Primary Account Number) based on the provided arguments,
    including whether to use delimiters.

    :param _Parse_Args: The command-line arguments provided to the script, which includes
                the --delimited  option to format the PAN with delimiters.
    :param pan: The `pan` is the Primary Account Number (PAN) generated by the script, which is a
                unique number used to identify the cardholder and is typically found on
                the front of credit and debit cards.
    :return:    Pan pattern with a random character from a list of characters associated with
                --delimited
    """
    if _Parse_Args.delimited:
        rgx_prefix = r"[ '\"{]"
        rgx_rejected = r"[]\\"
        char = random.choice([c for c in rgx_prefix if c not in rgx_rejected])
        pattern = f"{char}{pan}"
    else:
        pattern = f"{pan}"
    return pattern


# ===========================================================================
# Main script
# ===========================================================================
try:
    parser = argparse.ArgumentParser(
        description='Create test PAN data',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--debug", action="store_true", default=False)
    parser.add_argument("--delimited", action="store_true", default=False)
    parser.add_argument("--count", type=int, default=100, help="Number of patterns to create for each PAN type.")
    parser.print_help(file=sys.stderr)
    if not _EnableVSArgParams:
        _Parse_Args = parser.parse_args()
    else:
        _Parse_Args = parser.parse_args( ["--count","1","--debug"] )

    _ProgramName = os.path.basename(sys.argv[0])

    # Load JSON data from file
    json_file_path = os.path.join(os.getcwd(), f'{_JSONPtrnPrefixPath}/find-pan-patterns.json')
    json_data = load_json_data(json_file_path)

    # Print the generated VISA PAN numbers
    for card_name in get_pan_pattern_sections(json_data):
        pan_prefix_pattern  = get_card_prefix_pattern(json_data, card_name)
        pan_prefix_values   = get_card_prefix_values(pan_prefix_pattern, card_name)

        print( "##  ====================================================================")
        print(f"##  PCI Brand   : {card_name}")
        print(f"##  BIN Prefixes: {pan_prefix_pattern}")
        print(f"##  BIN Values  : {pan_prefix_values}")
        print( "##  ====================================================================")

        count = 0
        while count < _Parse_Args.count:
            pan_data = generate_pan_for_card_type(json_data, card_name)
            for pan in pan_data:
                print(format_pan(pan))
            count += 1

except Exception as e:
    print(f"Exception: {e}", file=sys.stderr)
