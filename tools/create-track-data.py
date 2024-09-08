#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    create-track-data.py
#  Function:    Create test patterns for track data
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

import argparse
from datetime import datetime
import names
import random
from random_address import real_random_address
import re
import string

##  =======================================================
##  Calculate LUHN Checksum
##  =======================================================
def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10

##  =======================================================
##  Generate PAN
##  =======================================================
def generate_luhn_valid_pan(length):
    pan="111111"
    while not ( luhn_checksum(pan) == 0):
        pan = random.choice(['3', '4', '5', '6'])
        pan += ''.join(str(random.randint(0, 9)) for _ in range(length - 2))  # Generate a random PAN of length-2
        checksum_digit = (10 - luhn_checksum(pan + '0')) % 10  # Calculate Luhn checksum
        pan = pan + str(checksum_digit)  # Append checksum digit to the PAN
    return pan

##  =======================================================
##  Generate random name
##  =======================================================
def generate_random_name():
    first_name = names.get_first_name()
    last_name = names.get_last_name()
    return f"{last_name}/{first_name}"

##  =======================================================
##  Generate Random Address
##  =======================================================
def generate_random_address():
    try:
        data=real_random_address()
        # return f"{data['address1']} {data['city']} {data['state']} {data['postalCode']}"
        return f"{data['postalCode']}"
    except Exception:
        pass
    return "30308"

##  =======================================================
##  Generate expiration date
##  =======================================================
def generate_valid_date():
    future_year = random.randint(datetime.now().year % 100, (datetime.now().year + 10) % 100)
    future_month = random.randint(1, 12)
    return f"{future_year:02d}{future_month:02d}"

##  =======================================================
##  Generate service code
##  =======================================================
def generate_service_code():
    digit1 = random.choice(['1', '2', '5', '6'])  # Use typical values
    digit2 = random.choice(['0', '2', '4'])  # For card-present options
    digit3 = random.choice(['0', '1', '2', '3', '5', '6', '7'])  # PIN and other restrictions
    return f"{digit1}{digit2}{digit3}"

##  =======================================================
##  Generate random discretionary data
##  =======================================================
def generate_discretionary_data(length=10):
    return ''.join(random.choices(string.digits, k=length))

##  =======================================================
##  Get a random format code of B or M
##  =======================================================
def generate_format_code():
    number = random.randint(0, 99)  # Generate a random number between 0 and 99
    return 'B' if number >= 50 else 'M'

##  =======================================================
##  Generate a full Track 1 data
##  =======================================================
def generate_track1_data():
    pan_lengths = [13, 15, 16, 19]
    pan = generate_luhn_valid_pan(random.choice(pan_lengths))
    name = generate_random_name()
    address = generate_random_address()
    expiration_date = generate_valid_date()
    service_code = generate_service_code()
    discretionary_data = generate_discretionary_data()
    name_addr=f"{name},{address}"
    # Build Track 1 data
    track1_data = f"%{generate_format_code()}{pan}^{name_addr[:26]}^{expiration_date}{service_code}{discretionary_data}?"
    return track1_data

##  =======================================================
##  Generate a full Track 2 data
##  =======================================================
def generate_track2_data():
    pan_lengths = [13, 15, 16, 19]
    pan = generate_luhn_valid_pan(random.choice(pan_lengths))
    name = generate_random_name()
    expiration_date = generate_valid_date()
    service_code = generate_service_code()
    discretionary_data = generate_discretionary_data()

    # Build Track 1 data
    track2_data = f";{pan}={expiration_date}{service_code}{discretionary_data}?"
    return track2_data


##  =======================================================
##  MAIN
##  =======================================================
def main():
    parser = argparse.ArgumentParser(description="Generate random track data based on provided patterns.")
    parser.add_argument("--count", type=int, default=200, help="Number of patterns to create for each track type")
    args = parser.parse_args()

    # Generate and print N track data for each track pattern
    track_generators = [generate_track1_data, generate_track2_data]
    for generator in track_generators:
        print(f"##\n## Generated data for {generator.__name__}\n##")
        for _ in range(args.count):
            track_data = generator()
            print(track_data)

if __name__ == "__main__":
    main()
