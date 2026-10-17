# Find-PAN Bug-Fix Tracker

This file indexes known bugs and design flaws in `bin/find-pan.py`, sorted
from highest to lowest priority. Each item is tagged with a status and can
be referenced independently by its `BUG-NNN` identifier.

**Status meanings**

- `todo` — not yet started
- `in progress` — actively being worked on
- `done` — resolved and covered by tests

---

## BUG-001: TAR archive member processed even when the safety filter rejects it

**Status:** `done`

**Severity:** Critical

**Location:** `bin/find-pan.py:341-358`, `bin/find-pan.py:364-374` (old code removed)

**Description:**
`process_tar_file()` built `temp_path` from the raw member name, called
`tar.extract(..., filter=custom_tar_filter)`, and then unconditionally called
`process_file(temp_path, ...)` and `secure_delete(..., temp_path)`. When
`custom_tar_filter()` returned `None` for a traversal/absolute member,
extraction was skipped, but the code still operated on the resolved path.

**Failure scenario:**
A tar member named `../../important.db` was not extracted, yet the scanner
read the file at that resolved path and then deleted it. If no file existed,
`os.remove` raised an unhandled `FileNotFoundError` and aborted the scan.

**Fix applied:**
- Removed the built-in `tarfile` extraction path entirely.
- Added external-program extraction (`tar`, `unzip`, `7z`, `gzip`) configured
  via `config/find-pan-conf.yaml`.
- `process_archive_file()` creates a unique temporary directory per archive
  via `tempfile.mkdtemp()`, runs the configured external extractor into it,
  scans the contents with `scan_directory()`, and then removes the entire
  temporary directory with `shutil.rmtree()` in a `finally` block.
- Added archive-type detection for `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`,
  `.tbz2`, `.tar.xz`, `.txz`, `.zip`, `.jar`, `.war`, `.ear`, `.7z`, and `.gz`.

**Tests:** `tests/test_archive.py` (replaced the old `tests/test_tar.py`)

---

## BUG-002: `print_exception_info()` crashes when called with `None`

**Status:** `done`

**Severity:** Critical

**Location:** `bin/find-pan.py:80-114`, `bin/find-pan.py:180`

**Description:**
The function signature types the argument as `Exception`, but
`setup_custom_loggers()` calls `print_exception_info(None)` at line 180. The
`str(e).lower()` call raised `AttributeError` when `e` was `None`.

**Failure scenario:**
When the trace-log parent directory cannot be created, the exception handler
crashes with a confusing `AttributeError` instead of reporting the real
failure.

**Fix applied:**
- Widened the signature to `object` so callers may pass `Exception`, `str`,
  or `None`.
- Guarded the `str(e)` call and only prints an `Info` line when `e` is truthy
  and differs from the exception message.

**Tests:** `tests/test_exceptions.py`

---

## BUG-003: `print_exception_info()` depends on `ProgramName` before it is defined

**Status:** `done`

**Severity:** Critical

**Location:** `bin/find-pan.py:80-114`, `bin/find-pan.py:789`

**Description:**
`ProgramName` was only assigned in `__main__` at line 789. If an exception
occurred earlier (for example, missing config file during argument setup), the
exception handler itself raised `NameError`.

**Failure scenario:**
Running `--version` or any scan without a config file produced a traceback
instead of a clean error message.

**Fix applied:**
- Removed the traceback walk that referenced `ProgramName`.
- The innermost traceback frame is now reported directly, with a safe
  `"<unknown>"` fallback when no traceback is available.

**Tests:** `tests/test_exceptions.py`

---

## BUG-004: `tarfile.extract(..., filter=...)` is Python 3.12+ only

**Status:** `done`

**Severity:** Critical

**Location:** `bin/find-pan.py:352` (old code removed)

**Description:**
`pyproject.toml` declares `requires-python = ">=3.10"`, but the `filter=`
keyword on `tarfile.TarFile.extract()` was added in Python 3.12. On 3.10/3.11
the old call raised `TypeError: extract() got an unexpected keyword argument 'filter'`.

**Failure scenario:**
Any tar scan on Python 3.10 or 3.11 crashed immediately.

**Fix applied:**
The tar-specific extraction code was removed entirely. Archives are now
extracted by external programs (`tar`, `unzip`, `7z`, `gzip`) configured in
`find-pan-conf.yaml`, so the `filter=` API is no longer used.

---

## BUG-005: `find_json_regex_config()` crashes when `XDG_CONFIG_HOME` is unset

**Status:** `done`

**Severity:** High

**Location:** `bin/pan_config.py:205-239`, `bin/pan_config.py:88-127`

**Description:**
`find_json_regex_config()` listed `os.environ.get("XDG_CONFIG_HOME")` as a
candidate, which is `None` on Windows and many Linux shells. Earlier versions
raised `TypeError` from `os.path.join(None, ...)` before any fallback path
was tried. Even after filtering `None`, there was no bundled configuration
fallback.

**Failure scenario:**
Scanner refused to start on Windows or on POSIX without `XDG_CONFIG_HOME`
set, even though a valid config ships with the application.

**Fix applied:**
- Added `_application_root()` that derives the application root from the
  location of `bin/pan_config.py` (the directory containing the `bin` folder).
- `find_json_regex_config()` now searches `XDG_CONFIG_HOME`, `~/.config`,
  `~/.local`, `~/.local/share`, `/usr/local`, and finally `<appRoot>/config`
  for `find-pan-regex.json`.
- `find_extractor_config_path()` applies the same appRoot search for the
  bundled `find-pan-conf.yaml`, while still creating new user configs in the
  established XDG location when no config exists anywhere.
- `None` entries are filtered before `os.path.join()` is called.

**Tests:** `tests/test_configuration.py`, `tests/test_archive.py`

---

## BUG-006: `--version` and `--help` fail if the JSON config is missing

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py:679-718`, `bin/find-pan.py:795-806`

**Description:**
`process_cmdline_arguments()` called `find_json_regex_config()` before handling
`--version` or `--help`. If the config was missing, the program crashed before
it could print version or help text.

**Failure scenario:**
A fresh clone or install without config setup could not even run `--version`.

**Fix applied:**
- Removed the eager `find_json_regex_config()` call from
  `process_cmdline_arguments()`.
- Changed the `--rgx-patterns` default to `None`.
- Moved `--version` handling to the `__main__` block immediately after
  `parse_args()`, before any JSON config lookup.
- `--help` is handled by `argparse` during `parse_args()`, so it exits before
  config discovery as well.
- The JSON regex config is now resolved lazily only when `rgx_patterns` is
  still `None` after argument parsing.

**Tests:** `tests/test_cmdline.py`

---

## BUG-007: `set_log_directory_and_filenames()` returns unbound variables on failure

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py:135-153`

**Description:**
If an exception occurred before `pan_logfile` and `trace_logfile` were assigned,
the function still reached `return pan_logfile, trace_logfile`, raising
`UnboundLocalError` on top of the original error.

**Failure scenario:**
Log-directory creation failure produced a confusing secondary traceback.

**Fix applied:**
Initialized `pan_logfile` and `trace_logfile` to empty strings before the
`try` block so the `return` statement is always well-defined.

**Tests:** `tests/test_exceptions.py`

---

## BUG-008: PAN log handler added twice

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py:196-211`

**Description:**
`pan_logger.addHandler(log_file_handler)` was called once unconditionally and
then again for every run, duplicating every PAN match in the log file. In
addition, the `StreamHandler` for verbose console output was constructed
unconditionally and only added when verbose mode was enabled, leaving an
orphaned handler object.

**Failure scenario:**
Audit logs contained two identical entries for every detection.

**Fix applied:**
- Removed the duplicate `pan_logger.addHandler(log_file_handler)` call.
- Moved the verbose `StreamHandler` construction inside the `if _Args.verbose:`
  block so it is only created when it will actually be used.

**Tests:** `tests/test_cmdline.py`

---

## BUG-009: Prior log files are silently deleted

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py:156-159`

**Description:**
`setup_custom_loggers()` removes existing log files with the same date string
before writing. Multiple runs on the same day destroy earlier audit history.

**Failure scenario:**
Rerunning the scanner overwrites evidence from an earlier scan.

**Fix direction:**
Append to logs or include a timestamp in the filename instead of deleting.

**Fix applied:** log files are opened in append mode and never deleted; each run writes a `---- Find-PAN run started ----` marker to the PAN and trace logs (the anti-PAN log holds findings only). Covered by `tests/test_bugsweep.py`.

---

## BUG-010: `secure_delete()` does not guard the `os.remove` fallback

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py:405-418` (old code removed)

**Description:**
The old `secure_delete()` caught `subprocess.CalledProcessError` but left the
`os.remove()` fallback unprotected against `FileNotFoundError` and other
`OSError`s.

**Failure scenario:**
A tar traversal member pointing to a non-existent path, or a file deleted by
another process between scan and cleanup, aborted the run.

**Fix applied:**
The old per-file `secure_delete()` and `find_secure_delete_program()` code
was removed. Extracted files now live in a unique temporary directory that
is deleted as a unit with `shutil.rmtree()` inside a `finally` block. Any
remaining cleanup error is logged as a warning instead of aborting the scan.

---

## BUG-011: `DataReporter` silently drops Luhn-failing matches

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py:527-544`

**Description:**
`DataReporter.__init__()` runs Luhn validation and returns early if it fails,
incrementing only `BAD-LUHN`. No log line is produced for the suspicious
match.

**Failure scenario:**
A candidate PAN that fails Luhn is invisible in the logs except for a counter,
losing forensic information.

**Fix direction:**
Log Luhn-failing matches at `WARNING` and separate construction from the
reporting side effects.

**Progress:** Luhn failures are now logged at `DEBUG` (visible with `--debug`)
with file, line, offset, pattern and digits; `--mask` masks the digits. The
WARNING-level logging and the constructor/reporting split remain open.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): Luhn failures are first-class `BAD_LUHN` matches routed to `TraceSink` (DEBUG), masked under `--mask`. Covered by `tests/test_reporting.py` and `tests/test_output_redaction.py`.

---

## BUG-012: Heavy module-level global coupling

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:40-66`, throughout

**Description:**
Nearly every function reads or writes module globals (`_Args`, `_MatchCount`,
`_TraceLogObj`, `_DefaultLogObj`, `_StartTime`). This prevents reuse and
makes unit testing difficult.

**Failure scenario:**
Running two scans in the same process corrupts counters and logging state.

**Fix direction:**
Introduce an explicit scanner context object and pass it through the call
graph.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): `Settings` and a `Reporter` are passed explicitly; no mutable module globals remain.

---

## BUG-013: `process_file()` opens the same file twice

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:463-472`

**Description:**
The file is opened in binary mode for `is_binary()` and then reopened in text
mode for scanning. This is inefficient and creates a TOCTOU window.

**Failure scenario:**
A file could change between the binary check and the text read; permissions
or content may differ unexpectedly.

**Fix direction:**
Read the file once and decode the buffer, or wrap the same handle with
`io.TextIOWrapper`.

**Fix applied:** `Scanner.process_file` opens a file once, reads a 1024-byte head for classification (libmagic uses `from_buffer`), then wraps the same handle for the text scan. Covered by `test_a_text_file_is_opened_exactly_once`.

---

## BUG-014: Binary detection requires both `0x00` and `0xFF`

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:275-291`

**Description:**
`is_binary()` only classifies a file as binary when it sees both a null byte
and a `0xFF` in the first 1022 bytes. Many binary formats contain `0x00` but
not `0xFF`. The code also drops the last two bytes of the sample.

**Failure scenario:**
Binary files are scanned as text, hurting performance and producing false
PAN matches in non-text data.

**Fix direction:**
Use `python-magic` consistently or implement a real heuristic (null-byte
presence / non-printable ratio) over the full 1024-byte sample.

**Fix applied:** `filetypes.looks_binary` treats a NUL byte (unless a UTF-16/32 BOM is present) or more than 30% non-text control bytes in the full 1024-byte sample as binary; Latin-1 text is not binary.

---

## BUG-015: `magic.Magic()` instantiated per file

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:233`

**Description:**
`is_executable()` creates a new `magic.Magic(mime=True)` object for every
file when `--skip-binary` is enabled. This is expensive on large scans.

**Failure scenario:**
Scanning large directories is unnecessarily slow.

**Fix direction:**
Create and reuse a single `Magic` instance, or inject it as a dependency.

**Fix applied:** the libmagic instance is built once per module (`_detector`, cached).

---

## BUG-016: `process_cmdline_arguments()` parses args multiple times

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:749`, `bin/find-pan.py:814`, `bin/find-pan.py:648`

**Description:**
`parser.parse_args()` is invoked at least twice (for `--version`, in `__main__`,
and inside `print_version_info()`). This is wasteful and can have side effects.

**Failure scenario:**
Inconsistent Namespace objects; confusing behavior with custom actions.

**Fix direction:**
Parse once and reuse the resulting Namespace.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): `cli.parse_args()` parses once and returns a `Settings` object.

---

## BUG-017: Progress-delta accounting is off by one

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:454`, `bin/find-pan.py:470`

**Description:**
`calculate_delta()` reads `_MatchCount["FILES"]` before the increment in
`process_file()`. The first progress report is therefore delayed by one file.
`_LastReportDelta` is also never reset between scans.

**Failure scenario:**
Progress reports are inaccurate; multiple scans in one process mis-report.

**Fix direction:**
Move the increment before `calculate_delta()` and reset `_LastReportDelta` at
scan start.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): `Reporter.file_started()` counts the file and then checks the progress interval; `--report-delta` must be >= 1. Covered by `test_progress_logged_every_report_delta_files`.

---

## BUG-018: `print_scan_summary()` prints `FILES - 1`

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:663`

**Description:**
The summary logs `_MatchCount["FILES"] - 1`. If no files were scanned, the
output is `-1`.

**Failure scenario:**
Misleading summary; unexplained magic constant.

**Fix direction:**
Remove the `- 1` adjustment and report the actual count.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): `ScanStats` owns the counts and the summary reports the true file count. Covered by `test_summary_reports_true_file_count_and_totals`.

---

## BUG-019: `valid_timestamp()` accepts timestamps one year in the future

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:313-322`

**Description:**
The upper bound is `datetime.now().year + 1`, so future timestamps pass the
anti-PAN filter. `datetime.now()` is also recomputed for every timestamp
match.

**Failure scenario:**
Future timestamps are treated as legitimate anti-PAN matches and excluded
from reporting.

**Fix direction:**
Document the future-year tolerance or tighten the bound; cache `now()`.

**Fix applied:** `valid_timestamp` accepts years up to the current year only.

---

## BUG-020: Only first matching category per line is reported

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:508`

**Description:**
`break` after the first match means a line containing both a PAN and Track
string only increments one counter.

**Failure scenario:**
Under-counting when multiple card data formats appear on the same line.

**Fix direction:**
Remove the premature `break` and report all distinct matches (taking care not
to double-report overlapping matches).

**Fix applied:** `process_file()` now delegates to `scan_line()`, which uses
`finditer` for every pattern and reports all distinct anti-PAN, PAN and TRACK
matches on a line. Overlapping matches are skipped so nothing is double
reported. Covered by `tests/test_debug_luhn.py`.

---

## BUG-021: Signal handling incomplete and unsafe before loggers exist

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:107-116`, `bin/find-pan.py:810`

**Description:**
Only `SIGINT` is handled. `handle_interrupt()` uses `_TraceLogObj` before it
is assigned, which would raise `AttributeError`. SIGTERM/SIGHUP are ignored.

**Failure scenario:**
An early Ctrl-C produces a traceback; `kill` on Unix exits without summary or
log flush.

**Fix direction:**
Handle SIGTERM on Unix; guard `handle_interrupt()` against `None` loggers.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): no custom signal handler; Python raises `KeyboardInterrupt`, which `cli.main` handles at every stage (configuration, scan and summary): sinks are closed, the summary is printed when a scan started, and the exit status is 1.

---

## BUG-022: Dead `raise ValueError` for new config categories

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:510-515`

**Description:**
If the JSON config ever adds a new top-level category (anything other than
`Anti-PAN Pattern`, `PAN Pattern`, or `TRACK Pattern`), the scanner raises
`ValueError` and dies.

**Failure scenario:**
Config extensibility breaks the scanner.

**Fix direction:**
Replace the hard-coded category list with a mapping or default behavior.

**Fix applied:** `scan_line()` raises `ValueError` for any unknown
category instead of a dead branch after the match loop.

---

## BUG-023: Visual Studio debug branch shadows `_Args`

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py:744-747`

**Description:**
If `_EnableVSArgParams` is set to `True`, the function assigns to a local
`_Args` shadowing the global and parses a hard-coded `--path test` argument.

**Failure scenario:**
Accidentally enabling the flag silently overrides real CLI arguments.

**Fix direction:**
Remove the branch or guard it behind a `FIND_PAN_DEBUG` environment variable.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): the Visual Studio argument branch and the global `_Args` were removed.

---

## BUG-024: `enumerate_command_line_arguments()` return type is wrong

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:624-634`

**Description:**
Annotated as `List[str | None]` but returns either `None` or a single `str`.
It also injects newlines into the joined output.

**Fix direction:**
Change the annotation to `str | None` and remove the embedded newlines.

**Resolved by the restructure:** `enumerate_command_line_arguments()` no longer exists; `cli._describe()` builds the parameter listing.

---

## BUG-025: `print_version_info()` re-parses arguments

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:648-649`

**Description:**
The function receives the parser and calls `arg_parse.parse_args()` again just
to check `version`.

**Fix direction:**
Use the already-parsed `_Args` Namespace.

**Fix applied:** resolved by the `find_pan` package restructure (see
`docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`): `--version` prints from `version.format_version()` without re-parsing arguments.

---

## BUG-026: `_FindPANVersion` format is unusual

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:50`, `bin/find-pan.py:643`

**Description:**
The version is stored as a space-separated string `"2 3 1"` and split on use.

**Fix direction:**
Store as a tuple or a conventional `__version__` constant.

**Resolved by the restructure:** the version lives in `src/find_pan/version.py` (`__version__ = "X.Y.Z"`) and is kept in sync with `pyproject.toml` by `bin/update_version.py`.

---

## BUG-027: `custom_tar_filter()` rejects benign filenames containing `..`

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:366`

**Description:**
The substring check `".." in tarinfo.name` blocks legitimate names like
`notes..txt`.

**Fix direction:**
Normalize the path and check for actual traversal rather than the substring.

**Resolved earlier:** the Python tar extraction and `custom_tar_filter()` were removed (BUG-004); external tools extract archives and `../` members are neutralized by them (checked in BUG-041).

---

## BUG-028: `luhn_check()` accepts empty and all-zero strings

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:301-307`

**Description:**
`luhn_check("")`, `luhn_check("0")`, and all-zero digit strings return `True`
because the checksum is zero.

**Failure scenario:**
Latent because regexes enforce length, but any future caller will be
surprised.

**Fix direction:**
Reject empty input and consider rejecting all-zero PANs.

**Fix applied:** `luhn_check()` returns `False` for empty and all-zero
strings. Covered by `tests/test_luhn.py`.

---

## BUG-029: `secure_delete()` paths starting with `-` may be parsed as flags

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:411-415`

**Description:**
A tar member named `--no-wipe.txt` is appended directly to the tool command;
some secure-delete tools may interpret it as an option.

**Fix direction:**
Insert `--` before the path if the tool supports it, or reject member names
starting with `-`.

**Fix applied:** in `bin/purge-log-files.py` (the only remaining secure-delete code) paths are made absolute, `--` precedes the path for `shred`/`gshred`, and the command is a flat list. The same function also crashed when no tool was found (`len(None)`) or when one was (a list nested in a list); both are fixed. Covered by `tests/test_purge_log_files.py`.

---

## BUG-030: `--exception-test` is a production debugging backdoor

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:798-802`

**Description:**
The `--exception-test` CLI flag intentionally divides by zero to exercise the
exception handler. It is exposed to end users.

**Fix direction:**
Remove the flag or hide it behind a build/debug environment variable.

**Fix applied:** the `--exception-test` option is removed from the CLI and `Settings`; the handler can still be exercised with the environment variable `FIND_PAN_EXCEPTION_TEST=1`.

---

## BUG-031: macOS/BSD secure-delete falls back to plain `os.remove`

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py:380-399`

**Description:**
`find_secure_delete_program()` only looks for `shred`/`gshred`, which are not
installed by default on macOS. The fallback is plain `os.remove`, so users may
believe data is securely wiped when it is not.

**Fix direction:**
Document the fallback behavior or add support for `rm -P` on BSD/macOS.

**Fix applied:** no new tool is added (`rm -P` is ineffective on APFS/SSD). Instead the fallback is explicit: a one-time warning says files are removed with a plain delete and are NOT securely wiped, and the README documents it.

---

## BUG-032: `import magic` at module scope segfaults on Windows

**Status:** `done`

**Severity:** Critical

**Location:** `bin/find-pan.py:29`, `bin/find-pan.py:236-268`

**Description:**
`find-pan.py` imported `magic` at module scope.  On Windows with a broken
`libmagic` installation, importing `python-magic` causes a native segfault before
`main()` runs, so even `--version` and `--help` crashed.

**Failure scenario:**
Running `find-pan.py --version` on the Windows dev machine produced
`exit status 139 (Segmentation fault)`.

**Fix applied:**
- Removed the module-scope `import magic`.
- `is_executable()` now imports `magic` lazily and only when `--skip-binary`
  is enabled.
- If `python-magic` cannot be imported, a warning is logged and the MIME-based
  executable check is skipped instead of crashing.
- Errors from `magic.Magic()` or `from_file()` are now logged as warnings rather
  than routed through `print_exception_info()`, which would abort the scan.

**Tests:** `tests/conftest.py` (deterministic stub), manual `--version` and
`--help` verification.

---

## BUG-033: `--line-limit N` scans only N-1 lines

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py` (`process_file()` line loop)

**Description:**
The loop incremented `line_count` and then broke on `line_count >= line_limit`,
so the Nth line was never scanned.

**Failure scenario:**
`--line-limit 3` on a file with a PAN on every line reported 2 PANs.

**Fix applied:**
The limit check is now `line_count > line_limit`. Covered by
`test_line_limit_scans_exactly_limit_lines`.

---

## BUG-034: A Luhn failure or anti-PAN hid other matches on the same line

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py` (`process_file()` / `DataReporter`)

**Description:**
After the first match on a line the scanner stopped, even when that match
failed the Luhn check. A valid PAN later on the line, or matched by a later
pattern, was missed. Anti-PAN matches were also run through the Luhn check:
failures were counted as `BAD-LUHN`, and passing ones were written to the log
and CSV as findings, so the `ANTI-PAN` summary was wrong.

**Fix applied:**
`scan_line()` examines every match of every pattern. Anti-PANs are counted
without a Luhn check, are never reported as findings and exclude only their own
span. A bad number matched by two patterns is counted once in `BAD-LUHN`.
Covered by `tests/test_debug_luhn.py`.

---

## BUG-035: `--mask` did not cover log and CSV output

**Status:** `done`

**Severity:** Medium

**Location:** `bin/find-pan.py` (`DataReporter.print_info()`, `write_csv_row()`)

**Description:**
`--mask` only masked the Luhn-failure debug message. Accepted matches still
wrote full PANs to the CSV `matched_data` column and to the INFO log line
(which includes the whole source line).

**Fix applied:**
With `--mask`, the CSV `matched_data`, the INFO log line (matched text and any
other 12-19 digit run on the line) and the Luhn-failure debug message keep only
the first 6 and last 4 digits. Track data is masked completely. Covered by
`test_mask_applies_to_csv_and_log`.

---

## BUG-036: `--debug` raised `NameError` (`json` not imported)

**Status:** `done`

**Severity:** High

**Location:** `bin/find-pan.py` `main()` (old code)

**Description:**
`main()` called `json.dumps()` to dump the patterns under `--debug`, but the
script never imported `json`.

**Failure scenario:**
`find-pan.py --debug --path ...` crashed with `NameError` as soon as the
patterns loaded.

**Fix applied:**
The dump moved to `find_pan.config.dump_patterns()`, which imports `json`.
Covered by `test_dump_patterns_round_trips_json` and
`test_debug_dumps_patterns_without_name_error`.

---

## BUG-037: Version duplicated in the script and `pyproject.toml`

**Status:** `done`

**Severity:** Low

**Location:** `bin/find-pan.py` (`_FindPANVersion`), `pyproject.toml`

**Description:**
The version existed in two places and `bin/update_version.py` updated only
`pyproject.toml`, so they could drift apart.

**Fix applied:**
`src/find_pan/version.py` holds `__version__`; `update_version.py` updates it
together with `pyproject.toml`. Covered by
`test_bump_updates_pyproject_and_version_module_together` and
`test_version_module_and_pyproject_agree`.

---

## BUG-038: `--log-anti-pan` (new feature, tracked for completeness)

**Status:** `done`

**Description:**
Anti-PAN hits are counted but shown nowhere by default. `--log-anti-pan` writes
them (masked under `--mask`) to `Find-PAN-anti-pan-<date>.log` and adds the log
path and entry count to the summary.

---

## BUG-039: Deferred findings from the modularization review

**Status:** `done`

**Severity:** Minor

**Fix applied (each covered by a test):**
- The `Command-line arguments:` line is printed again (`sys.argv` is used when `main()` gets no argv).
- `--mask` also masks cards written with spaces or dashes (4-4-4-4, 4-4-4-4-3 and Amex 4-6-5) in logged source lines.
- Ctrl-C at any stage of `cli.main` exits with status 1 and no traceback.
- Unreadable files have their own `Unreadable N Files.` summary line and no longer inflate `Skipped N Files.`
- An invalid regex, malformed extractor YAML and a failed archive copy are one-line `Error:` messages (`ConfigError` / `ExtractorError`); a failed extraction is printed to stderr and the exit status is 1.
- A failing sink `close()` no longer replaces the error being reported; `Reporter.close()` is idempotent.
- The console streams use `errors="replace"`, so U+FFFD never produces a logging error on a Windows console.

---

## BUG-040: `--tar` / `--tar-tmp` replaced by `--file`; archives detected by content

**Status:** `done`

**Severity:** Medium

**Description:**
Archives could only be scanned through a dedicated `--tar` flag that trusted file
extensions, `--path` never expanded archives, and a failed or unavailable
extraction was only visible in the log file.

**Fix applied:**
`--file FILE [FILE ...]` (repeatable) and `--path` share one file processor
(`Scanner.process_file`). `filetypes.classify` decides by content (magic bytes);
the extension is only a hint. Archives are expanded with the configured external
tools into a system temporary directory that is always removed, and their members
go back through the processor (nested archives expand naturally). `--tar` and
`--tar-tmp` are removed with no compatibility layer. Every skipped file is logged
and listed in the summary; a missing tool is a warning, a failing tool or a bad
`--file` entry makes the exit status 1 after the run completes.

---

## BUG-041: Hardening of automatic archive extraction

**Status:** `done`

**Severity:** Important

**Description:**
`--path` now runs external extractors on archives found in untrusted trees. A review of that
path found: a tool that extracted members and then exited non-zero (for example on a `../`
member) caused the whole archive to be skipped, hiding its valid members; an archive containing
itself recursed until `RecursionError`; symbolic links inside an extracted tree were followed
and could read files outside it; a relative archive name such as `-evil.zip` reached the tool
looking like an option; and file names, member names and tool stderr could carry control
characters (log injection) or PANs (leaking under `--mask`).

**Fix applied:**
Partial extractions are scanned and then reported as failed; recursion is detected by content
digest; symlinks in extracted trees are skipped (`SYMLINK`); archive paths are made absolute;
stderr is truncated; `Reporter.clean()` neutralizes control characters and masks PANs in
everything derived from untrusted input. Path traversal itself was checked against crafted zip
and tar archives and is neutralized by the tools. Covered by `tests/test_hardening.py`.

---

## BUG-042: Decompression bombs and brace handling in extractor arguments

**Status:** `done`

**Severity:** Important

**Description:**
Nothing bounded what an external extractor could write, how long it could run, or how much disk it
could fill, and `--path` extracts any archive it meets. Separately, extractor arguments were passed
through `str.format`, so a literal `{` or `}` in a configured argument raised `KeyError`.

**Fix applied:**
`archives.run_limited` runs the tool under a watchdog that polls the output directory and kills the
tool and its children when extracted bytes, entry count, elapsed time or free disk space cross the
limits in `ExtractionLimits` (defaults: 10 GiB, 100,000 files, 600 s, 1 GiB free). Limits live in the
`limits:` section of `find-pan-conf.yaml` and can be overridden per extractor. A breach is an
`ARCHIVE-FAILED` skip (partial members are still scanned). Arguments now substitute only `{archive}`
and `{tempdir}`. Covered by `tests/test_limits.py` and `tests/test_hardening.py`.

---
