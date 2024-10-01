#!/usr/bin/env python3
"""
Module to validate numbers using the Luhn algorithm.

This module contains a function to check if a number is valid according to the Luhn algorithm.
"""
import os
import sys


def luhn_check(num):
    """
    Validate a number using the Luhn algorithm.

    The Luhn algorithm is a simple checksum formula used to validate various identification numbers,
    such as credit card numbers. This function takes an integer or string representing a number
    and returns True if the number passes the Luhn check, False otherwise.

    :param num: The number to be validated. Can be an integer or a string.
    :type num: int or str
    :return: True if the number is valid according to the Luhn algorithm, False otherwise.
    :rtype: bool
    """
    rev_digits = [int(x) for x in str(num)][::-1]
    checksum = 0
    for i, d in enumerate(rev_digits):
        n = d if i % 2 == 0 else 2 * d
        checksum += n if n < 10 else n - 9
    return checksum % 10 == 0


try:
    # Test cases with valid numbers
    assert luhn_check(
        4111111111111111) is True, "Test failed for a valid number: 4111111111111111"
    assert luhn_check(
        5500000000000004) is True, "Test failed for a valid number: 5500000000000004"
    assert luhn_check(
        340000000000009) is True, "Test failed for a valid number: 340000000000009"
    assert luhn_check(
        6011000000000004) is True, "Test failed for a valid number: 6011000000000004"
    assert luhn_check(
        3530111333300000) is True, "Test failed for a valid number: 3530111333300000"

    # Test cases with invalid numbers
    assert luhn_check(
        4111111111111112) is False, "Test failed for an invalid number: 4111111111111112"
    assert luhn_check(
        5500000000000005) is False, "Test failed for an invalid number: 5500000000000005"
    assert luhn_check(
        340000000000008) is False, "Test failed for an invalid number: 340000000000008"
    assert luhn_check(
        6011000000000005) is False, "Test failed for an invalid number: 6011000000000005"
    assert luhn_check(
        3530111333300001) is False, "Test failed for an invalid number: 3530111333300001"

    # Test case with a number that has a checksum of 0
    assert luhn_check(0), "Test failed for a number with checksum of 0"

except AssertionError as e:
    print(f"{os.path.basename(sys.argv[0])}: assert: {e}")
    sys.exit(1)

print(f"{os.path.basename(sys.argv[0])}: All test cases passed!")
