#!/usr/bin/env python3
#  ===========================================================================
#  Name    :    create-logs-for-purge-test.py
#  Function:    Create log files to test purge tool
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


import os
import time
from datetime import timedelta, datetime

def create_and_set_time(file_name, days_ago):
    with open(file_name, 'w') as f:
        f.write("Sample content.")

    # Modify the file's time attributes
    current_time = datetime.now() - timedelta(days=days_ago)
    file_time = time.mktime(current_time.timetuple())
    os.utime(file_name, (file_time, file_time))

def main():
    base_name = "file-"
    extension = ".log"
    
    for i in range(1, 51):
        file_name = f"{base_name}{str(i).zfill(3)}{extension}"
        create_and_set_time(file_name, i-1)

if __name__ == "__main__":
    main()

