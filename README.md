# find-pan.py

## Description

**find-pan.py** is a Python script designed to search for Primary Account Numbers (PANs) and TRACK data in a file system or a tar file.

The script was originally designed for Payments Information System projects.  It leverages regular expressions to identify patterns associated with credit card numbers and track data.

## Author
- **Author:** David Means
- **Contact:** w1t3h4t@gmail.com

## License

This script is released under the MIT License. See the [LICENSE](LICENSE) file for details.

## Installation
Python works best when using virtual environments.  Doing so allows the system administrator and other users to maintain 
their environemnts necessary for unencumbered operation.

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

### Install Required Packages
Install the required packages for the tools.
<pre>
$ sudo apt install libmagic
$ sudo apt install pip
$ pip install -r requirements.txt
</pre>

## Usage
<pre>
find-pan.py [--path PATH] [--tar TAR] [--temp TEMP] [--log-dir LOG_DIR]
            [--skip-binary]  [--verbose] [--debug]
</pre>

### Command-line Arguments:

|Switch|Description|
|-------------------|:-------------------------------------------------------|
|**--path**         |Specify the file system path to scan for PANs (required when no --tar). |
|**--tar**          |Specify the tar file path to scan for PANs (required when no --path).|
|**--temp**         |Specify the temporary directory for extracting files from the tar archive (required w/ --tar).|
|**--patterns**     |Regular expression JSON file.  Default is 'patterns/find-pan-patterns.json'.|
|**--skip-binary**  |Avoid scanning binary files (optional). |
|**--log-dir**      |Specify the directory for log files (optional).|
|**--line-limit**   |Specify the number of lines to scan per file.  Default is all data/lines (optional). |
|**--verbose**      |Display 'trace' logfile information to stdout (optional).|
|**--debug**        |Sends 'debug' messages 'trace' log file (optional). |


## Features

- Scans files in a specified directory or a tar archive for credit card and track data patterns.
- Identifies suspect data based on regular expression patterns.
- Performs Luhn algorithm checks on identified potential PANs for validation.
- Logs matched PANs with details such as file name, line number, and match type.
- Supports optional logging directory for storing log files.
- Tools provided to purge logs files, generate test data, etc.

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
find-pan.py --path /path/to/directory
</pre>

Scan a tar archive:

<pre>
find-pan.py --tar /path/to/archive.tar --temp /path/to/temporary/directory
</pre>

Specify a log directory:

<pre>
find-pan.py --path /path/to/directory --log-dir /path/to/logs
</pre>

## Notes

- The script supports scanning of filesystems and tarfiles.  Tarfile scanning requires a temporary directory for extracting files from the tar archive.
- Ensure the necessary platform-specific tools (shred, sdelete) are available for secure file deletion.
- Use `$ pip install -r requirements.txt` to install required modules.
- Ensure 'libmagic' is installed for your platform, e.g., `brew install libmagic`.

