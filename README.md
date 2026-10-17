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
Install the operating-system dependency for MIME detection, install [uv](https://docs.astral.sh/uv/), then run the one-time setup script for your platform. The setup configures `uv` so plain `uv` commands (`uv sync`, `uv run`, `uv add`) automatically use a per-platform project environment (`.venv-windows` or `.venv-linux`). This lets a checkout be shared between Windows and WSL/Linux without either side corrupting the other's environment.

**Windows (PowerShell)** — `python-magic` needs the `libmagic-1.dll` native library. The easiest way to satisfy this is to install the [file-windows](https://pypi.org/project/file-windows/) package, which bundles the DLL, then run the project setup:
<pre>
PS> .\bin\setup-env.ps1 -FileWindows
</pre>

If you prefer to manage the DLL yourself, place `libmagic-1.dll` (and its
`magic1.mgc` database) on `PATH` or in the same directory as `find-pan.py`.

**WSL / Linux / macOS** — install the system `libmagic` package. Debian/Ubuntu example shown:
<pre>
$ sudo apt update
$ sudo apt install -y libmagic1 python3-full
$ ./bin/setup-env.sh
</pre>

On macOS with Homebrew: `brew install libmagic`.

Both setup scripts persist `UV_PROJECT_ENVIRONMENT` for your user (`.venv-windows` on Windows, `.venv-linux` on POSIX systems). uv resolves the relative value against each project's root, so every `uv` project keeps its own platform-named environment. Open a new shell after setup, then run commands with plain `uv`:
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


# Project Layout

`bin/find-pan.py` is a thin launcher; the implementation is the `find_pan` package in `src/find_pan/`:

|Module|Responsibility|
|---|---|
|`cli.py`|Argument parsing, wiring, error reporting, exit codes.|
|`settings.py`, `version.py`, `errors.py`|Immutable run settings, the version, and the error types.|
|`config.py`|Regex and archive-extractor configuration.|
|`detectors.py`|Luhn check and per-line detection (pure functions).|
|`scanner.py`, `filetypes.py`, `archives.py`|Directory and archive walking, binary/executable detection, external extractors.|
|`models.py`, `redact.py`, `reporting.py`|Match records and counters, redaction (`--mask`), and the sinks (PAN log, CSV, trace log, anti-PAN log).|
|`logging_setup.py`|Builds the loggers from the settings.|

Every match is redacted once by `redact.py` before any sink sees it, so output rules such as `--mask` apply to all outputs. Run the tests with `uv run pytest`.

# Usage

<pre>
find-pan.py [--path PATH] [--file FILE [FILE ...]] [--log-dir LOG_DIR]
            [--skip-binary]  [--verbose] [--debug] [--mask] [--log-anti-pan]
</pre>

## Command-line Arguments:
|Switch|Description|
|-------------------|:-------------------------------------------------------|
|**-h,--help**      |Show this information and exit.|
|**--path**         |A directory to scan for PAN and TRACK data. Archives found in it are detected and expanded (required when no --file).|
|**--file**         |One or more files to scan, e.g. `--file a.txt b.zip c.tar.gz` (the flag may also be repeated; required when no --path). Only the listed files are processed. A missing path or a directory is reported on stderr and skipped, and the run continues. Archives are detected by content and expanded.|
|**--log-dir**      |The directory for log files.|
|**--skip-binary**  |Do not scan (skip) binary files.|
|**--patterns**     |The JSON file containing PAN and TRACK regular expressions.|
|**--line-limit**   |The number of lines to scan per file.  Zero means scan all files.|
|**--report-delta** |The number of files to process before reporting progress.|
|**--verbose**      |Route log file messages also to stdout.|
|**--debug**        |Route 'debug' messages to stdout and the 'trace' log, including a message for each candidate that fails the Luhn check.|
|**--mask**         |Mask PAN digits (keep the first 6 and last 4) in the log, CSV and Luhn-failure debug output. Track data is fully masked. Default off: full numbers are written.|
|**--log-anti-pan** |Write anti-PAN hits to a separate log, `Find-PAN-anti-pan-<date>.log`, and show its path and entry count in the summary. Default off. Output is masked when `--mask` is set; anti-PAN hits never appear in the PAN log or the CSV.|
|**--version**      |Report the app and python versions.|


## Log Files
The script generates two log files (three with `--log-anti-pan`):

1. **Find-PAN-trace.log:** Logs limited details of the runtime execution.
2. **Find-PAN.log:** Logs detailed information of identified PANs.
3. **Find-PAN-anti-pan-<date>.log:** Written only with `--log-anti-pan`; lists the anti-PAN (suspect) hits.

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

Scan specific files (archives are expanded automatically):
<pre>
$ find-pan.py --file report.txt backup.tar.gz export.zip
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

### Random Text with Embedded PAN and Track Data

`--random-text LINES` writes lorem-ipsum text (from the `lorem-text` package) with Luhn-valid PANs and Track 1 / Track 2 records embedded in it, several per line. It is intended for exercising the scanner against realistic, noisy input, including multiple hits on one line.

<pre>
$ python bin/generate-pan.py --random-text 100 --max-hits 4 --seed 42 --output sample.txt
</pre>

|Argument|Description|
|---|---|
|**--random-text LINES**|Number of lines of random text to generate. Must be at least 1.|
|**--max-hits N**|Maximum PAN/track hits per line; each line gets 1 to N (default 3).|
|**--pan-pattern NAME**|Restrict embedded PANs to one pattern. Without it, every configured PAN pattern is used.|
|**--seed NUMBER**|Reproducible output.|
|**--output PATH**|Output file. Defaults to `Random-Text.txt` in the current directory.|

Embedded PANs are generated to avoid the configured anti-PAN patterns, and the lorem text contains no digits, so `find-pan.py` reports each embedded hit and nothing else.

# Example Usage for a File System Scan
<pre>
$ bin/find-pan.py --path test --report-delta 100 --skip-binary 
find-pan.py v1.5.0
Python 3.12.6 (main, Sep  6 2024, 19:03:47) [Clang 15.0.0 (clang-1500.3.9.4)]
Command-line arguments: ['--path', 'test', '--report-delta', '100', '--skip-binary']
2024-09-15 20:04:44,333 [INFO]: 
Parameters and Defaults
 --path=test
 --file=[]
 --log_dir=/Users/anyone/Find-PAN-Logs
 --skip_binary=True
 --patterns=/usr/local/Find-PAN/patterns/find-pan-patterns.json
 --line_limit=0
 --rgx_prefix=False
 --report_delta=100
 --verbose=False
 --debug=False
 --mask=False
 --log-anti-pan=False
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

# Archives and File Types
`--path` and `--file` use the same file processor. Each file is classified by its
**content** (magic bytes), and the extension is only a hint:

- **Archive** (tar, tar.gz/bz2/xz, zip including `.jar`/`.war`/`.ear`/Office files, 7z, gzip): expanded
  into a temporary directory with a locally installed tool, and every member goes back through the
  processor, so nested archives expand too. The directory is removed afterwards.
- **Executable or binary** (with `--skip-binary`): skipped.
- **Anything else**: scanned as text. A text file named `notes.zip` is scanned as text and a note is logged.

The extraction tools (`tar`, `unzip`, `7z`, `gzip`) come from `find-pan-conf.yaml`, which is built the
first time an archive is met by discovering the tools on `PATH`. Edit it if tools are installed
elsewhere.

Every skipped file is logged and listed under `-- Skipped Files --` in the end-of-run summary with its
reason (`NOT-FOUND`, `NOT-A-FILE`, `ARCHIVE-NO-TOOL`, `ARCHIVE-FAILED`, `BINARY`, `EXEC`, `UNREADABLE`).
A missing extraction tool is a warning; a tool that fails, or a `--file` entry that does not exist,
makes the exit status 1 after the rest of the run has completed.
<pre>
$ uv run python bin/find-pan.py --file test-archive.tar.gz notes.txt
find-pan.py v3.0.0
2024-09-15 20:04:44,333 [INFO]: -- Processing Summary --
2024-09-15 20:04:44,333 [INFO]: PANs Matched  :    64704
2024-09-15 20:04:44,333 [INFO]: TRACKs Matched:    15521
2024-09-15 20:04:44,333 [INFO]: Archives expanded: 1
2024-09-15 20:04:44,333 [INFO]: -- Skipped Files --
2024-09-15 20:04:44,333 [INFO]: [ARCHIVE-NO-TOOL] inner.7z - Extractor command not found: 7z
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
