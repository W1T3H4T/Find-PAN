#!/usr/bin/env python3
"""
Create log files to test purge tool.

This script generates a series of log files with modified timestamps to
simulate aging files for testing a purge tool. Each file's name is prefixed
with "file-" followed by a zero-padded three-digit index and the ".log"
extension. The timestamps of the files are set to be sequentially older,
starting from one day ago up to 50 days ago.

Functionality:
- Generate log files with specific timestamps for purge testing.
- Set the file's modification and access times to simulate aged files.

Usage:
Run this script directly to create the log files in the current directory.

Issues:
Not all Operating Systems will allow this script to change the create date.
The companion script is purge-log-files.py
"""

import os
import time
from datetime import datetime, timedelta


def create_and_set_time(file_name: str, days_ago: int) -> None:
    """
    Create a log file and set its timestamp to a specified number of days ago.

    This function creates an empty log file with the given file name. It then sets
    both the modification and access times of the file to simulate a file that was
    last modified and accessed a certain number of days ago, based on the `days_ago` parameter.

    Parameters:
    - file_name (str): The path to the file to be created.
    - days_ago (int): The number of days in the past for which the timestamp should be set.
    """
    with open(file_name, 'w', encoding='utf-8') as f:  # Explicitly specify encoding as UTF-8
        f.write("Sample content.")

    current_time = datetime.now() - timedelta(days=days_ago)
    file_time = time.mktime(current_time.timetuple())
    os.utime(file_name, (file_time, file_time))


def main() -> None:
    """
    Main function to orchestrate the creation of log files with varying timestamps.

    This function iterates from 1 to 50 and creates a corresponding number of log files. Each
    file's timestamp is set to be one day older than the previous, starting with the most
    recent file being one day old and the oldest being 50 days old.
    """
    base_name = "file-"
    extension = ".log"

    for i in range(1, 51):
        file_name = f"{base_name}{str(i).zfill(3)}{extension}"
        create_and_set_time(file_name, i - 1)


if __name__ == "__main__":
    main()
