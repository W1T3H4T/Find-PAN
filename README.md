# find-pan.py

## Description

**find-pan.py** is a Python script designed to search for Primary Account Numbers (PANs) and TRACK data in a file system or a tar file.

The script was originally designed to find PAN within Payments Information System projects.<br>
 
The script leverages regular expressions to identify patterns associated with credit card numbers and track data.

## Author

- **Author:** David Means
- **Contact:** w1t3h4t@gmail.com

## License

This script is released under the MIT License. See the [LICENSE](LICENSE) file for details.

## Usage

```bash
python find-pan.py [--path PATH] [--tar TAR] [--temp TEMP] [--log-dir LOG_DIR] [--skip-binary]  [--verbose] [--debug]
```

### Command-line Arguments:

- **--path** Specify the file system path to scan for PANs.
- **--tar** Specify the tar file path to scan for PANs.
- **--temp** Specify the temporary directory for extracting files from the tar archive.
- **--skip-binary** Avoid scanning binary files (optional).
- **--log-dir** Specify the directory for log files (optional).
- **--line-limit** Specify the number of lines to scan per file.  Default is all data/lines (optional). 
- **--verbose** Display 'trace' logfile information to stdout (optional).
- **--debug** Sends 'debug' messages 'trace' log file (optiona). 

## Features

- Scans files in a specified directory or a tar archive for credit card and track data patterns.
- Identifies suspect data based on regular expression patterns.
- Performs Luhn algorithm checks on identified potential PANs for validation.
- Logs matched PANs with details such as file name, line number, and match type.
- Supports optional logging directory for storing log files.
- Tools provided to purge logs files, generate test data, etc.

## Log Files

The script generates two log files:

1. **Find-PAN.log:** Logs limited details of the runtime execution.
2. **Find-PAN-trace.log:** Logs detailed information of identified PANs.

Log files are generated in the specified log directory or the current working directory if no log directory is provided.

## PAN Patterns

The script uses predefined regular expressions to identify PANs. Supported PAN types include:

- American Express
- Mastercard
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

```bash
python find-pan.py --path /path/to/directory
```

Scan a tar archive:

```bash
python find-pan.py --tar /path/to/archive.tar --temp /path/to/temporary/directory
```

Specify a log directory:

```bash
python find-pan.py --path /path/to/directory --log-dir /path/to/logs
```

## Notes

- The script supports both file system paths and tar file scanning but requires a temporary directory for extracting files from the tar archive.
- Ensure the necessary platform-specific tools (shred, sdelete) are available for secure file deletion.

Feel free to reach out to the author at `w1t3h4t@gmail.com` for any inquiries or issues related to the script.