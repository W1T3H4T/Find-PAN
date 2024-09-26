#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    make-test-track.py
#  Function:    Create test patterns for track data
#  Author  :    David Means <w1t3h4t@gmail.com>
#  ===========================================================================

import argparse
import random
import string
from datetime import datetime

import names
from random_address import real_random_address

_Parse_Args = None

# =======================================================
# Calculate LUHN Checksum
# =======================================================


def luhn_checksum(card_number: str) -> int:
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10

# =======================================================
# Generate PAN
# =======================================================


def generate_luhn_valid_pan(length: int) -> str:
    pan = "111111"  # default value used initially fail luhn_checksum
    while not luhn_checksum(pan) == 0:
        pan = random.choice(['3', '4', '5', '6'])
        # Generate a random PAN of length-2
        pan += ''.join(str(random.randint(0, 9)) for _ in range(length - 2))
        # Calculate Luhn checksum
        checksum_digit = (10 - luhn_checksum(pan + '0')) % 10
        pan = pan + str(checksum_digit)  # Append checksum digit to the PAN
    return pan


# =======================================================
# Generate random name
# =======================================================
def generate_random_name():
    first_name = names.get_first_name()
    last_name = names.get_last_name()
    return f"{last_name}/{first_name}"


# =======================================================
# Generate Random Address
# =======================================================
def generate_random_address():
    try:
        data = real_random_address()
        # return f"{data['address1']} {data['city']} {data['state']}
        # {data['postalCode']}"
        return f"{data['postalCode']}"

    # pylint: disable=W0718
    except Exception:
        pass
    return "30308"


# =======================================================
# Generate expiration date
# =======================================================
def generate_valid_date():
    future_year = random.randint(
        datetime.now().year %
        100, (datetime.now().year + 10) %
        100)
    future_month = random.randint(1, 12)
    return f"{future_year:02d}{future_month:02d}"


# =======================================================
# Generate service code
# =======================================================
def generate_service_code():
    digit1 = random.choice(['1', '2', '5', '6'])  # Use typical values
    digit2 = random.choice(['0', '2', '4'])  # For card-present options
    # PIN and other restrictions
    digit3 = random.choice(['0', '1', '2', '3', '5', '6', '7'])
    return f"{digit1}{digit2}{digit3}"


# =======================================================
# Generate random discretionary data
# =======================================================
def generate_discretionary_data(length=10):
    return ''.join(random.choices(string.digits, k=length))


# =======================================================
# Get a random format code of B or M
# =======================================================
def generate_format_code():
    number = random.randint(0, 99)  # Generate a random number between 0 and 99
    return 'B' if number >= 50 else 'M'


# =======================================================
# Generate a full Track 1 data
# =======================================================
def generate_track1_data():
    pan_lengths = [13, 15, 16, 19]
    pan = generate_luhn_valid_pan(random.choice(pan_lengths))
    name = generate_random_name()
    address = generate_random_address()
    expiration_date = generate_valid_date()
    service_code = generate_service_code()
    discretionary_data = generate_discretionary_data()
    name_addr = f"{name},{address}"
    # Build Track 1 data
    track1_data = f"%{
        generate_format_code()}{pan}^{
        name_addr[
            :26]}^{expiration_date}{service_code}{discretionary_data}?"
    return track1_data


# =======================================================
# Generate a full Track 2 data
# =======================================================
def generate_track2_data():
    pan_lengths = [13, 15, 16, 19]
    pan = generate_luhn_valid_pan(random.choice(pan_lengths))
    # name = generate_random_name()
    expiration_date = generate_valid_date()
    service_code = generate_service_code()
    discretionary_data = generate_discretionary_data()

    # Build Track 1 data
    track2_data = f";{pan}={expiration_date}{service_code}{discretionary_data}?"
    return track2_data


# ==========================================================================
# Select a REGEX prefix character
# ==========================================================================
def format_track(args, pan):
    if args.delimited:
        rgx_prefix = r"[ '\"{]"
        rgx_rejected = r"[]\\"
        char = random.choice([c for c in rgx_prefix if c not in rgx_rejected])
        pattern = f"{char}{pan}"
    else:
        pattern = f"{pan}"
    return pattern


# =======================================================
# Main is here
# =======================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate random track data based on provided patterns.")
    parser.add_argument("--delimited", default=False, action="store_true",
                        help="Create data with prefix anchors")
    parser.add_argument("--count", type=int, required=True,
                        help="Number of patterns to create for each track type")
    _Parse_Args = parser.parse_args()

    # Generate and print N track data for each track pattern
    track_generators = [generate_track1_data, generate_track2_data]
    for generator in track_generators:
        print("##  ====================================================================")
        print(f"##  Generated data for {generator.__name__}")
        print("##  ====================================================================")
        for _ in range(_Parse_Args.count):
            track_data = generator()
            print(format_track(track_data))
