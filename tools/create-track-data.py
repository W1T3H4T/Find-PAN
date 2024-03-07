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

import random
import re
import argparse

def generate_track_1_data():
    while True:
        card_number = random.randint(10**12, 10**19)
        name = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ ') for _ in range(random.randint(1, 26)))
        discretionary_data = random.randint(10**1, 10**19)
        track_1_data = f'%B{card_number}^{name}^{discretionary_data}?'
        if re.match(r'%B\d{13,19}\^\w{1,26}\^\d{1,19}|\d{1,19}\?', track_1_data):
            return track_1_data

def generate_track_2_data():
    while True:
        card_number = random.randint(10**12, 10**19)
        discretionary_data = random.randint(10**1, 10**19)
        track_2_data = f';{card_number}={discretionary_data}?'
        if re.match(r';\d{13,19}=\d{1,19}|\d{1,19}\?', track_2_data):
            return track_2_data

def main():
    parser = argparse.ArgumentParser(description="Generate random track data based on provided patterns.")
    parser.add_argument("--count", type=int, default=10, help="Number of patterns to create for each track type")
    args = parser.parse_args()

    # Specify the track patterns
    track_patterns = [
        r'%B\d{13,19}\^\w{1,26}\^\d{1,19}|\d{1,19}\?',  # Track 1 Data
        r';\d{13,19}=\d{1,19}|\d{1,19}\?'               # Track 2 Data
    ]

    # Generate and print N track data for each track pattern
    track_generators = [generate_track_1_data, generate_track_2_data]
    for generator in track_generators:
        print(f"## Generated data for {generator.__name__}:")
        for _ in range(args.count):
            track_data = generator()
            print(track_data)

if __name__ == "__main__":
    main()
