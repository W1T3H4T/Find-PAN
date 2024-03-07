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
import argparse

def luhn_check(card_number):
    digits = [int(digit) for digit in str(card_number)]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits) + sum(sum(divmod(2 * digit, 10)) for digit in even_digits)
    return checksum % 10 == 0

def generate_amex():
    while True:
        card_number = [3, 4, 7] + [random.randint(0, 9) for _ in range(13)]
        # Ensure the first digit is not zero for Luhn check
        card_number[0] = random.randint(3, 9)
        # Generate the last digit using Luhn algorithm
        total = sum((card_number[i] * (2 - i % 2)) % 10 + card_number[i] // 5 for i in range(14))
        checksum = (10 - total % 10) % 10
        card_number.append(checksum)
        generated_number = "".join(map(str, card_number))
        if luhn_check(generated_number):
            return generated_number

def generate_mastercard():
    while True:
        prefix = random.choice(["51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27"])
        card_number = [int(digit) for digit in prefix] + [random.randint(0, 9) for _ in range(12)]
        # Ensure the first digit is not zero for Luhn check
        card_number[0] = random.randint(1, 9)
        # Generate the last digit using Luhn algorithm
        total = sum((card_number[i] * (2 - i % 2)) % 10 + card_number[i] // 5 for i in range(14))
        checksum = (10 - total % 10) % 10
        card_number.append(checksum)
        generated_number = "".join(map(str, card_number))
        if luhn_check(generated_number):
            return generated_number

def generate_visa():
    while True:
        card_number = [4] + [random.randint(0, 9) for _ in range(12)]
        # Ensure the first digit is not zero for Luhn check
        card_number[0] = random.randint(1, 9)
        # Generate the last digit using Luhn algorithm
        total = sum((card_number[i] * (2 - i % 2)) % 10 + card_number[i] // 5 for i in range(13))
        checksum = (10 - total % 10) % 10
        card_number.append(checksum)
        generated_number = "".join(map(str, card_number))
        if luhn_check(generated_number):
            return generated_number

def generate_discover():
    while True:
        prefix = random.choice(["6011", "65", "644", "645", "646", "647", "648", "649"])
        card_number = [int(digit) for digit in prefix] + [random.randint(0, 9) for _ in range(12)]
        # Ensure the first digit is not zero for Luhn check
        card_number[0] = random.randint(1, 9)
        # Generate the last digit using Luhn algorithm
        total = sum((card_number[i] * (2 - i % 2)) % 10 + card_number[i] // 5 for i in range(14))
        checksum = (10 - total % 10) % 10
        card_number.append(checksum)
        generated_number = "".join(map(str, card_number))
        if luhn_check(generated_number):
            return generated_number

def generate_diners_club():
    while True:
        prefix = random.choice(["30", "36", "38", "54", "55"])
        card_number = [int(digit) for digit in prefix] + [random.randint(0, 9) for _ in range(12)]
        # Ensure the first digit is not zero for Luhn check
        card_number[0] = random.randint(3, 9)
        # Generate the last digit using Luhn algorithm
        total = sum((card_number[i] * (2 - i % 2)) % 10 + card_number[i] // 5 for i in range(14))
        checksum = (10 - total % 10) % 10
        card_number.append(checksum)
        generated_number = "".join(map(str, card_number))
        if luhn_check(generated_number):
            return generated_number

def generate_jcb():
    while True:
        prefix = random.choice(["2131", "1800", "35"])
        card_number = [int(digit) for digit in prefix] + [random.randint(0, 9) for _ in range(12)]
        # Ensure the first digit is not zero for Luhn check
        card_number[0] = random.randint(1, 9)
        # Generate the last digit using Luhn algorithm
        total = sum((card_number[i] * (2 - i % 2)) % 10 + card_number[i] // 5 for i in range(14))
        checksum = (10 - total % 10) % 10
        card_number.append(checksum)
        generated_number = "".join(map(str, card_number))
        if luhn_check(generated_number):
            return generated_number

def main():
    parser = argparse.ArgumentParser(description="Generate random credit card numbers based on provided PAN patterns.")
    parser.add_argument("--count", type=int, default=10, help="Number of patterns to create for each credit card type")
    parser.add_argument("--retry", type=int, default=3, help="Number of retry iterations if Luhn check fails")
    args = parser.parse_args()

    # Specify the PAN patterns for credit card types
    pan_generators = {
        "American Express": generate_amex,
        "Mastercard": generate_mastercard,
        "Visa": generate_visa,
        "Discover": generate_discover,
        "Diners Club International": generate_diners_club,
        "JCB": generate_jcb
    }

    # Generate and print N credit card numbers for each PAN pattern
    for card_type, generator in pan_generators.items():
        print(f"##  Generated numbers for {card_type}:")
        for _ in range(args.count):
            for _ in range(args.retry):
                credit_card_number = generator()
                if luhn_check(credit_card_number):
                    print(credit_card_number)
                    break
            else:
                print(f"Retry limit reached for {card_type}. Unable to generate a valid number.")

if __name__ == "__main__":
    main()

