# find-pan.py

## Description

**find-pan.py** is a Python script designed to search for Primary Account Numbers (PANs) and TRACK data in a file system or a tar file.

The script was originally designed for Payments Information System projects.  It leverages regular expressions to identify patterns associated with credit card numbers and track data.

## Features

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
Download and extract the ZIP file, or clone the project:<br>
`$ git clone https://github.com/W1T3H4T/Find-PAN.git`
<pre>
$ cd ./Find-PAN/Install
$ cat make-install.sh 
#!/bin/bash
set -x
aclocal
autoconf
automake --add-missing
./configure
make
sudo make install
set +x
echo
echo "Use 'sudo make uninstall' to remove."
echo

$ ./make-install.sh 
...

$ tree /usr/local/Find-PAN/
/usr/local/Find-PAN/
├── bin
│   ├── create-logs-for-purge-test.py
│   ├── create-pan-data.py
│   ├── create-test-data.sh
│   ├── create-track-data.py
│   ├── find-pan.py
│   ├── get-strings.sh
│   ├── grep-find-pan.sh
│   ├── grep-find-track.sh
│   ├── logger.sh
│   ├── obfuscate-pan.py
│   ├── purge-log-files.py
│   ├── regex-test.py
│   └── test_luhn_check.py
├── patterns
│   ├── find-pan-patterns.json
│   └── find-pan-patterns.schema.json
└── share
    └── doc
        └── find-pan
            ├── LICENSE
            ├── README.md
            └── requirements.txt

6 directories, 18 files

$ cat ~/.bashrc
export PATH=$PATH:/usr/local/Find-PAN/bin:
</pre>

## Virtual Python Environment
Python works best when using virtual environments.  Doing so allows the system administrator and other users to maintain 
their enthronements necessary for unencumbered operation.

For complete instructions, see here: [Python Virtual Environment](https://docs.python.org/3/library/venv.html)

Briefly:
<pre>
$ python -m venv /path/to/new/virtual/environment
</pre>

Next, activate the environment.  I use the following in my bash profile script: 
<pre>
### Configure python environment
export VIRTUAL_ENV_DISABLE_PROMPT=True
source $HOME/.pyenv/bin/activate
</pre>

## Install Required Packages
Install the required packages for the tools.
<pre>
$ sudo apt install libmagic
$ sudo apt install pip
$ pip install -r requirements.txt
</pre>

# Usage
<pre>
find-pan.py [--path PATH] [--tar TAR] [--temp TEMP] [--log-dir LOG_DIR]
            [--skip-binary]  [--verbose] [--debug]
</pre>

# Command-line Arguments:
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
The script can be instructed to detects binary files and skip them during the scanning process.

## Secure Deletion

For files processed during scanning, the script securely deletes them using platform-specific methods (``shred`` on Linux, and ``sdelete`` on Windows).

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

## Notes
- The script supports scanning of filesystems and tarfiles.  Tarfile scanning requires a temporary directory for extracting files from the tar archive, which has a default value pre-applied.
- Ensure the necessary platform-specific tools (shred, sdelete) are available for secure file deletion.
- Use `$ pip install -r requirements.txt` to install required modules.
- Ensure 'libmagic' is installed for your platform, e.g., `brew install libmagic`.

## Author
- **Author:** David Means
- **Contact:** w1t3h4t@gmail.com
