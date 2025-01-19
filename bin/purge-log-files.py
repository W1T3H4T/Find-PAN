#!/usr/bin/env python3
##  ===========================================================================
##  File    :   purge-log-files.py
##  Function:   Remove log files of a certain age
##  Who     :   David Means <w1t3h4t@gmail.com>
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================

import argparse
import logging
import os
import platform
import time
from datetime import datetime
from shutil import which
from subprocess import CalledProcessError, call

_LogObj = None
secure_del_app = None


#   ===========================================================================
#   Initialize the Logger
#   ===========================================================================
def init_logger():
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=log_format)
    log_instance = logging.getLogger(__name__)

    # pylint: disable=consider-using-f-string
    log_file = "%s_%s.log" % (os.path.basename(__file__).split(".")[0], datetime.now().strftime("%Y%m%d"))
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(log_format))
    log_instance.addHandler(file_handler)
    return log_instance


#   ==========================================================================
#   Get the file age in days
#   ==========================================================================
def get_file_age_in_days(file_path):
    stat_info = os.stat(file_path)

    # On Windows, use st_ctime as the creation time
    if platform.system() == "Windows":
        creation_time = stat_info.st_ctime
    # On Unix-like systems, use st_birthtime if available
    elif hasattr(stat_info, "st_birthtime"):
        creation_time = stat_info.st_birthtime
    else:
        # Fallback to last modification time
        creation_time = stat_info.st_mtime

    # Calculate age in days
    current_time = time.time()
    age_in_seconds = current_time - creation_time
    return age_in_seconds / (60 * 60 * 24)


# ===========================================================================
# Find the secure delete app for the OS
# ===========================================================================
def find_secure_delete_program():

    nt = ["sdelete64.exe", "sdelete.exe"]
    posix = ["shred", "gshred"]

    if os.name == "posix":
        for tool in posix:
            tool_path = which(tool)
            if tool_path:
                _LogObj.info("Using %s %s for secure delete.", os.name, tool_path)
                return [tool_path, "-u"]

    if os.name == "nt":
        for tool in nt:
            tool_path = which(tool)
            if tool_path:
                _LogObj.info("Using %s %s for secure delete.", os.name, tool_path)
                return [tool_path]

    _LogObj.warning("No Secure delete app found for %s", os.name)
    return None  # Unsupported operating system


#   ===========================================================================
#   Delete old files
#   ===========================================================================
def delete_file(file_path: str, reported_flag: list[bool]) -> None:
    # Mapping of platforms to secure delete tools

    if len(secure_del_app):
        try:
            call([secure_del_app, file_path])
            if os.path.exists(file_path):
                os.remove(file_path)
            _LogObj.info("Removed %s", file_path)

        except CalledProcessError as e:
            _LogObj.warning("Error during secure delete: %s", e)
    else:
        os.remove(file_path)
        if not reported_flag[0]:
            _LogObj.warning("Secure delete application not found.")
            reported_flag[0] = True
        _LogObj.info("Removed %s", file_path)


# =======================================================
# Process the Log Directory
# =======================================================
def process_log_dir(path: str, age: int, prefix: str) -> None:
    reported_flag = [False]
    for file_name in os.listdir(path):

        if file_name.startswith(prefix):
            full_path = os.path.join(path, file_name)
            file_age = get_file_age_in_days(full_path)

            if file_age > age:
                delete_file(full_path, reported_flag)
            else:
                _LogObj.info("Retained %s", full_path)


# =======================================================
# Call to Main is here
# =======================================================
if __name__ == "__main__":
    _LogObj = init_logger()

    parser = argparse.ArgumentParser(description="File deletion based on age and prefix.")
    parser.add_argument("--path", type=str, required=True, help="Log file directory to process.")
    parser.add_argument("--age", type=int, required=True, help="Age in days for file retention.")
    parser.add_argument(
        "--prefix", type=str, required=False, default="file-", help="The required log file prefix pattern."
    )
    args = parser.parse_args()

    secure_del_app = find_secure_delete_program()
    process_log_dir(args.path, args.age, args.prefix)
