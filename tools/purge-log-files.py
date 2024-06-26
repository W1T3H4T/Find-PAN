#!/usr/bin/env python3
#   ===========================================================================
#   File    :   purge-log-files.py
#   Function:   Remove log files of a certain age
#   Who     :   David Means <w1t3h4t@gmail.com>
#   ===========================================================================
#   MIT License
#   
#   Copyright (c) 2023 David Means
#   
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#   
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#   
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#   ===========================================================================

import argparse
import os
import time
import logging
from shutil import which
from datetime import datetime
from subprocess import call, CalledProcessError

_REPORTED = None

#   ===========================================================================
#   Initialize the Logger
#   ===========================================================================
def init_logger():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format)
    logger = logging.getLogger(__name__)

    log_file = f"{os.path.basename(__file__).split('.')[0]}_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(file_handler)
    return logger

#   ===========================================================================
#   Delete old files
#   ===========================================================================
def delete_file(file_path):
    global _REPORTED

    cmd_map = {
        'Linux': ['shred'],
        'Windows': ['sdelete.exe', 'sdelete64.exe'],
        'Darwin': ['srm']
    }

    platform = os.name if os.name != 'posix' else os.uname()[0]
    secure_del_cmd = None
    available_cmds = cmd_map.get(platform, [])

    for cmd in available_cmds:
        if which(cmd):
            secure_del_cmd = cmd
            break

    if secure_del_cmd:
        try:
            call([secure_del_cmd, file_path])
            logger.info(f"Securely removed {file_path}")
        except CalledProcessError as e:
            logger.warning(f"Error during secure delete: {e}")
    else:
        os.remove(file_path)
        if _REPORTED is None:
            logger.warning(f"Secure delete application not found.")
            _REPORTED = True
        logger.info(f"Removed {file_path}")

#   ===========================================================================
#   Main
#   ===========================================================================
def main(path, age, prefix):

    for file_name in os.listdir(path):
        if file_name.startswith(prefix):
            full_path = os.path.join(path, file_name)
            file_stat = os.stat(full_path)
            file_age = (time.time() - file_stat.st_mtime) // (24 * 3600)

            if file_age > age:
                delete_file(full_path)
            else:
                logger.info(f"Retained {full_path}")

logger = init_logger()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File deletion based on age and prefix.")
    parser.add_argument("--path", type=str, required=True, help="Log file directory to process.")
    parser.add_argument("--age", type=int, required=True, help="Age in days for file retention.")
    parser.add_argument("--prefix", type=str, required=True, default='file-', help="The required log file prefix pattern.")
    args = parser.parse_args()

    main(args.path, args.age, args.prefix)

