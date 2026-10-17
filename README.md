# find-pan.py
* [Description](#description)
  * [Features](#features)
  * [License](#license)
- [Installation](#installation)
  * [Find-PAN Application](#find-pan-application)
  * [Find-PAN Configuration](#find-pan-configuration)
  * [Modules and Libraries](#modules-and-libraries)
    + [Virtual Python Environment](#virtual-python-environment)
      - [Configuration](#configuration)
- [Usage](#usage)
  * [Command-line Arguments:](#command-line-arguments)
  * [Log Files](#log-files)
  * [PAN and TRACK Patterns](#pan-and-track-patterns)
  * [Anti-PAN (Suspect) Patterns](#anti-pan-suspect-patterns)
  * [Binary File Handling](#binary-file-handling)
  * [Secure Deletion](#secure-deletion)
  * [Examples](#examples)
- [Example Usage for a File System Scan](#example-usage-for-a-file-system-scan)
- [Example Usage for a TAR File Scan](#example-usage-for-a-tar-file-scan)
- [Notes](#notes)
- [Potential Future Enhancements](#potential-future-enhancements)
  * [Regular Expression Support](#regular-expression-support)
  * [Processing Metrics](#processing-metrics)
  * [Logging](#logging)
- [PCI DSS 4.0 Compliance Notes](#pci-dss-40-compliance-notes)
- [Author](#author)


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
## Find-PAN Application
Download and extract the ZIP file, or clone the project.
Example:
<pre>
$ git clone https://github.com/W1T3H4T/Find-PAN.git
$ echo "export PATH=$PATH:$HOME/Find-PAN/bin" >> ~/.bashrc
</pre>

## Find-PAN Configuration
Find-PAN uses `find-pan-regex.json` as its configuration file. This file is found in the `config` directory.  Copy it to one of the pre-defined directories.  Find-PAN will attempt to load this file from the following locations:
  <pre>
  $XDG_CONFIG_HOME/find-pan
  $HOME/.config/find-pan
  $HOME/.local/find-pan
  $HOME/.local/share/find-pan
  /usr/local/find-pan </pre>

## Modules and Libraries
Install the operating-system `libmagic` dependency, install [uv](https://docs.astral.sh/uv/), then run the one-time setup script for your platform. The setup configures `uv` so plain `uv` commands (`uv sync`, `uv run`, `uv add`) automatically use a per-platform project environment (`.venv-windows` or `.venv-linux`). This lets a checkout be shared between Windows and WSL/Linux without either side corrupting the other's environment.

Windows (PowerShell):
<pre>
PS> .\bin\setup-env.ps1
</pre>

WSL / Linux / macOS (Debian/Ubuntu shown for the `libmagic` prerequisite):
<pre>
$ sudo apt update
$ sudo apt install -y libmagic python3-full
$ ./bin/setup-env.sh
</pre>

Both scripts persist `UV_PROJECT_ENVIRONMENT` for your user (`.venv-windows` on Windows, `.venv-linux` on POSIX systems). uv resolves the relative value against each project's root, so every `uv` project keeps its own platform-named environment. Open a new shell after setup, then run commands with plain `uv`:
<pre>
$ uv run python bin/find-pan.py --version
$ uv run python bin/run-pytest-regression.py
</pre>

To install only runtime dependencies, omit the development group:
<pre>
$ uv sync --no-dev
</pre>

### pip Alternative
For environments that do not use uv, install the dependencies listed in `requirements.txt` into a virtual environment.

For complete instructions, see here: [Python Virtual Environment](https://docs.python.org/3/library/venv.html)

Briefly:
<pre>
$ python -m venv /path/to/new/virtual/environment
</pre>

### Configuration
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
- UnionPay

### Regular-expression construction

The PAN expressions are maintained in [`config/find-pan-regex.json`](config/find-pan-regex.json). They are intentionally specific: a match is a candidate PAN, not proof that a card account is active or that a particular issuer owns the account.

- **Issuer ranges and total lengths:** Each expression encodes its card brand's published IIN/BIN range and accepted total PAN length. The patterns use explicit alternatives when a brand supports disjoint lengths, such as VISA's 13-, 16-, and 19-digit PANs, rather than accepting every length in a broad range.
- **Numeric boundaries:** `(?<![0-9])` and `(?![0-9])` prevent a valid-length PAN from being reported when it is only a substring of a longer numeric value.
- **Range precision:** Nested alternatives represent non-contiguous ranges. For example, Discover's `622126`�`622925` range is encoded without accepting adjacent `622` values outside that range. Mastercard includes both its `51`�`55` and `2221`�`2720` series.
- **Overlapping ranges:** More-specific patterns must win over broad patterns. The generic VISA expression excludes the configured VISA Electron prefixes so those matches are identified as VISA Electron instead.
- **Validation after matching:** The scanner removes non-digits from a candidate PAN and requires it to pass the Luhn check before logging an event. The expressions reduce false positives; the Luhn check is an additional checksum validation, not an issuer lookup.
- **Anti-PAN values:** The timestamp anti-pattern constrains `YYYYMMDDHHMMSS` components to valid numeric ranges. The scanner then validates the complete calendar date and time before treating it as an anti-PAN, preventing impossible dates such as February 30 from being ignored.

#### Range and length sources

The current ranges and length rules were reviewed against the following published references:

- [ISO/IEC 7812-1](https://www.iso.org/standard/70484.html), which defines the identification-card numbering system and IIN framework.
- [Mastercard 2-Series BIN Implementation for Merchants](https://www.mastercard.us/content/dam/mccom/en-us/documents/merchant-2-series-BIN-impact-checklist-aug-2016.pdf), for the `222100`�`272099` Mastercard series.
- [Discover Network IPP/VAR Compliance Update](https://www.discovernetwork.com/downloads/IPP_VAR_Compliance.pdf), for Discover, Diners Club, JCB, and UnionPay co-brand ranges and 19-digit PAN support.
- The [Payment card number issuer table](https://en.wikipedia.org/wiki/Payment_card_number), used as a public cross-reference for the configured issuer ranges and PAN lengths.

Issuer ranges can change, and the ISO specification does not publish every allocated range. Before changing a pattern, confirm the current range and length with the relevant payment brand's official account-range or network-rules documentation, add representative boundary tests, and preserve the numeric-boundary and Luhn-validation behavior.


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

## Generate Synthetic PAN Test Data

`bin/generate-pan.py` creates synthetic PANs from the configured `PAN Pattern` entries. It generates at least one Luhn-valid PAN for every regular expression defined for the selected pattern. The output is suitable for scanner testing only; it is not an account-status or issuer-ownership check.

List the available patterns:
<pre>
$ python bin/generate-pan.py --list-pan-patterns
</pre>

Generate values for a selected pattern:
<pre>
$ python bin/generate-pan.py --pan-pattern "VISA Electron"
</pre>

Omit `--pan-pattern` in an interactive terminal to choose from a numbered menu. Use `--seed NUMBER` when reproducible synthetic values are required, or `--patterns PATH` to use an alternate pattern configuration.

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
