# find-pan.py
[[TOC]]

## Description
**find-pan.py** is a Python script designed to search for Primary Account Numbers (PANs) and TRACK data in a file system or a tar file.

The script was originally designed for Payments Information System projects.  It leverages regular expressions to identify patterns associated with credit card numbers and track data.  This version of the tool has been highly refactored from the original version, and it supports the easy maintenance of regular expressions through a JSON file.

## Features
- Fast file system processing.
- TAR file scanning also supported.
- Regular expressions are stored in an external JSON file.
- Supports Anti-Patterns as regular expressions to help reduce false-alarms.
- Performs Luhn algorithm checks on identified potential PANs.
- Logs findings with file name, line number, and match type.
- Clean, non-encumbered output while running.
- Can detect and skip executable files.
- Tools provided to purge logs files, generate test data, etc.

## License
This script is released under the MIT License. See the [LICENSE](LICENSE) file for details.

# Installation
## Application File
Download and extract the ZIP file, or clone the project.
Example:
<pre>
$ git clone https://github.com/W1T3H4T/Find-PAN.git
$ echo "export PATH=$PATH:$HOME/Find-PAN/bin" >> ~/.bashrc
</pre>

## Configuration File
Find-PAN uses `find-pan.json` as its configuration file. Find-PAN will attempt to load this file from
the following locations:
  <pre>
  $XDG_CONFIG_HOME
  $HOME/.config
  $HOME/.local
  $HOME/.local/share
  /usr/local </pre>

## Modules and Libraries
These are the commands necessary to install `pip, libmagic` and the modules specified by `requirements.txt.`
<pre>
$ sudo apt update
$ sudo app upgrade -y
$ sudo apt install -y libmagic python3-pip 
$ pip install -r requirements.txt
</pre>

These are the commands to install all necessary bits, including support for a virtual environment.
<pre>
$ sudo apt update
$ sudo app upgrade -y
$ sudo apt install -y libmagic python3-full python3-venv python3-pip
$ pip install -r requirements.txt
</pre>

### Virtual Python Environment
While it is not required to use a Python Virtual Environment, it does reduce the complexities assocatied with maintaining a usable Python solution for the system and a solution that works for your everyday tasks.

For complete instructions, see here: [Python Virtual Environment](https://docs.python.org/3/library/venv.html)

Briefly:
<pre>
$ python -m venv /path/to/new/virtual/environment
</pre>

#### Configuration
Next, activate the environment.  I use the following in my bash profile script: 
<pre>
export VIRTUAL_ENV_DISABLE_PROMPT=True
source $HOME/.pyenv/bin/activate
</pre>


# Usage

<pre>
find-pan.py [--path PATH] [--tar TAR] [--temp TEMP] [--log-dir LOG_DIR]
            [--skip-binary]  [--verbose] [--debug]
</pre>

## Command-line Arguments:
|Switch|Description|
|-------------------|:-------------------------------------------------------|
|**-h,--help**      |Show this information and exit.|
|**--path**         |The filesystem path to scan for PAN and TRACK data (required when no --tar). |
|**--tar**          |The tar file to scan for PAN and TRACK data (required when no --path).|
|**--tar-tmp**      |The temporary directory for extracting files from the tar archive (required w/ --tar).|
|**--log-dir**      |The directory for log files.|
|**--skip-binary**  |Do not scan (skip) binary files.|
|**--patterns**     |The JSON file containing PAN and TRACK regular expressions.|
|**--line-limit**   |The number of lines to scan per file.  Zero means scan all files.|
|**--report-delta** |The number of files to process before reporting progress.|
|**--verbose**      |Route log file messages also to stdout.|
|**--debug**        |Route 'debug' messages to stdout and the 'trace' log.|
|**--version**      |Report the app and python versions.|


## Log Files
The script generates two log files:

1. **Find-PAN-trace.log:** Logs limited details of the runtime execution.
2. **Find-PAN.log:** Logs detailed information of identified PANs.

Log files are generated in the specified log directory or the current working directory if no log directory is provided.

## PAN and TRACK Patterns
The script uses predefined regular expressions to identify PAN and TRACK 1 & 2 data. Supported PAN types include:

- American Express
- MasterCard
- Visa
- Discover
- Diners Club International
- JCB


## Anti-PAN (Suspect) Patterns
The script also checks for patterns indicative of non-PAN data, such as sequential or repeated numbers.

## Binary File Handling
The script can be instructed to detect binary files and skip them during the scanning process.

## Secure Deletion
For files processed during tarfile scanning (files extracted from tar files), the script securely deletes them using platform-specific methods (`shred` on Linux, and `sdelete` on Windows).

## Examples
Scan a directory:
<pre>
$ find-pan.py --path /path/to/directory
</pre>

Scan a tar archive:
<pre>
$ find-pan.py --tar /path/to/archive.tar --temp /path/to/temporary/directory
</pre>

Specify a log directory:
<pre>
$ find-pan.py --path /path/to/directory --log-dir /path/to/logs
</pre>

# Example Usage for a File System Scan
<pre>
$ bin/find-pan.py --path test --report-delta 100 --skip-binary 
find-pan.py v1.5.0
Python 3.12.6 (main, Sep  6 2024, 19:03:47) [Clang 15.0.0 (clang-1500.3.9.4)]
Command-line arguments: ['--path', 'test', '--report-delta', '100', '--skip-binary']
2024-09-15 20:04:44,333 [INFO]: 
Parameters and Defaults
 --path=test
 --tar=None
 --tar_tmp=/Users/anyone/Find-PAN-Logs/tar-temp
 --log_dir=/Users/anyone/Find-PAN-Logs
 --skip_binary=True
 --patterns=/usr/local/Find-PAN/patterns/find-pan-patterns.json
 --line_limit=0
 --rgx_prefix=False
 --report_delta=100
 --verbose=False
 --debug=False
 --version=False

2024-09-15 20:04:44,333 [INFO]: Scanning test ...
2024-09-15 20:04:44,333 [INFO]: Scanned 100 files; matched 37708 PANs, 6411 TRACKs
2024-09-15 20:04:44,333 [INFO]: Scanned 200 files; matched 64061 PANs, 15521 TRACKs
2024-09-15 20:04:44,333 [INFO]: 
2024-09-15 20:04:44,333 [INFO]: -- Processing Summary --
2024-09-15 20:04:44,333 [INFO]: Scanned 200 files.
2024-09-15 20:04:44,333 [INFO]: Matched 64704 PANs.
2024-09-15 20:04:44,333 [INFO]: Matched 15521 TRACKs.
2024-09-15 20:04:44,333 [INFO]: Skipped 69 Anti-PANs.
2024-09-15 20:04:44,333 [INFO]: Skipped 1 Files
2024-09-15 20:04:44,333 [INFO]: Total matches: 80225
</pre>

# Example Usage for a TAR File Scan
<pre>
$ bin/find-pan.py --tar test-archive.tar.gz 
find-pan.py v1.5.0
Python 3.12.6 (main, Sep  6 2024, 19:03:47) [Clang 15.0.0 (clang-1500.3.9.4)]
Command-line arguments: ['--tar', 'test-archive.tar.gz']
2024-09-16 20:04:44,333 [INFO]: 
Parameters and Defaults
 --path=None
 --tar=test-archive.tar.gz
 --tar_tmp=/Users/anyone/Find-PAN-Logs/tar-temp
 --log_dir=/Users/anyone/Find-PAN-Logs
 --skip_binary=False
 --patterns=/usr/local/Find-PAN/patterns/find-pan-patterns.json
 --line_limit=0
 --rgx_prefix=False
 --report_delta=100
 --verbose=False
 --debug=False
 --version=False

2024-09-15 20:04:44,333 [INFO]: Scanning test-archive.tar.gz ...
2024-09-15 20:04:44,333 [INFO]: Scanned 100 files; matched 37060 PANs, 6260 TRACKs
2024-09-15 20:04:44,333 [INFO]: Scanned 200 files; matched 62728 PANs, 15521 TRACKs
2024-09-15 20:04:44,333 [INFO]: 
2024-09-15 20:04:44,333 [INFO]: -- Processing Summary --
2024-09-15 20:04:44,333 [INFO]: Scanned 202 files.
2024-09-15 20:04:44,333 [INFO]: Matched 64704 PANs.
2024-09-15 20:04:44,333 [INFO]: Matched 15521 TRACKs.
2024-09-15 20:04:44,333 [INFO]: Skipped 69 Anti-PANs.
2024-09-15 20:04:44,333 [INFO]: Skipped 0 Files
2024-09-15 20:04:44,333 [INFO]: Total matches: 80225
</pre>

# Notes
- Ensure the necessary platform-specific tools (shred, sdelete/sdelete64) are available for secure file deletion.

# Potential Future Enhancements
## Regular Expression Support
- Enable the tool to select a set of regular expressions: support more than one set in the JSON configuration file.
- Investigate pre-compilation of regular expressions for performance improvement.
- Add support for Non-PCI Primary Account Numbers.
## Processing Metrics
- Investigate adding process timing support on a per-file basis.
## Logging
- Add support for logging extra details for items skipped.
<br><br><br>
---

# PCI DSS 4.0 Compliance Notes
*Control 3.2.1* - Account data storage is kept to a minimum through the implementation of data retention and disposal policies, procedures, and processes that include at least the following:

- Coverage for all locations of stored account data.
- Coverage for any sensitive authentication data (SAD) stored prior to completion of authorization. This bullet is a best practice until its effective date; refer to Applicability Notes below for details.
- Limiting data storage amount and retention time to that which is required for legal or regulatory, and/or business requirements.
- Specific retention requirements for stored account data that defines length of retention period and includes a documented business justification.
- Processes for secure deletion or rendering account data unrecoverable when no longer needed per the retention policy.
- A process for verifying, at least once every three months, that stored account data exceeding the defined retention period has been securely deleted or rendered unrecoverable.

*Control 3.5* - Primary account number (PAN) is secured wherever it is stored.<br>

*Control 3.5.1* - PAN is rendered unreadable anywhere it is stored by using any of the following approaches:<br>

- One-way hashes based on strong cryptography of the entire PAN.
- Truncation (hashing cannot be used to replace the truncated segment of PAN).
- If hashed and truncated versions of the same PAN, or different truncation formats of the same PAN, are present in an environment, additional controls are in place such that the different versions cannot be correlated to reconstruct the original PAN.
- Index tokens.
- Strong cryptography with associated key-management processes and procedures.

# Author
- **Author:** David Means
- **Contact:** W1T3H4T@GMAIL.COM
- **LinkedIn:** [LinkedIn](https://www.linkedin.com/in/davidcmeans/)
