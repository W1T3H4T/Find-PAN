# Find-PAN Modularization Design

Date: 2026-10-17
Status: Approved 2026-10-17 (not committed)

## 1. Purpose

`bin/find-pan.py` is a 985-line script that mixes logging setup, signal
handling, file-type detection, archive extraction, detection, reporting, CSV
output, argument parsing and the scan summary. Its parts communicate through
module globals (`_Args`, `_MatchCount`, `_TraceLogObj`, `_DefaultLogObj`,
`_CsvWriter`, `_CsvFileObj`, timing variables).

The immediate problem: output rules are not applied in one place. Adding
`--mask` required four separate edits (Luhn debug line, INFO log line, CSV
column, track data), because every sink reads raw match fields itself. Each
future rule would repeat that work and risk leaking an unredacted value.

**Goal:** restructure into a small, clean package in which every output rule is
applied once, before any sink sees the data, with no module-level mutable state.

**Success criteria**

1. A redaction rule is added or changed in one module (`redact.py`) and applies
   to every sink automatically.
2. A test proves that with `--mask` the raw PAN appears in no output file
   (PAN log, trace log, CSV, stdout), including for sinks added later.
3. No module outside `cli.py` reads `sys.argv`, calls `sys.exit()` or
   `print()`, or touches mutable module globals.
4. Behavior visible to users is unchanged (see section 9).
5. Every existing behavior test maps to a test in the new layout; none are dropped.

**Non-goals:** new detection features, new output formats, changes to the
regex configuration schema, installing the project as a distributable package.

## 2. Layout

```
bin/find-pan.py            thin launcher (shebang kept); calls find_pan.cli.main()
src/find_pan/
    __init__.py
    version.py             __version__ and formatting
    errors.py              FindPanError and subclasses
    settings.py            frozen Settings dataclass
    cli.py                 argparse -> Settings; signals; exit codes; wiring
    config.py              regex + extractor configuration (from bin/pan_config.py)
    logging_setup.py       builds the PAN and trace loggers
    models.py              Match, MatchKind, ScanStats
    detectors.py           luhn_check, timestamp check, PAN extraction, scan_line()
    filetypes.py           is_binary, is_executable (python-magic imported lazily)
    archives.py            external-program archive extraction
    scanner.py             directory walk and per-file loop
    redact.py              Redactor, RedactedMatch
    reporting.py           Reporter and sinks (Log, Csv, Trace)
tests/                     reorganized per module (section 8)
```

`bin/pan_config.py` moves to `src/find_pan/config.py`. It is imported only by
`find-pan.py`, so nothing else needs a shim. Its application-root lookup
(`parents[1]` from `bin/`) becomes `parents[2]` from `src/find_pan/`.

### Dependency rules

Dependencies point downward only; there are no cycles.

```
cli  ->  scanner, reporting, redact, logging_setup, config, settings, version, errors
scanner  ->  detectors, filetypes, archives, reporting, models, settings
reporting  ->  redact, models, errors
detectors, redact, models, settings, version, errors   (leaf modules; no I/O)
```

`detectors`, `redact`, `models` and `settings` are pure (no I/O) and are the
easiest to test.

## 3. Components

### settings.py

`Settings` is a frozen dataclass holding every option the program reads
(`archive` is the value of the unchanged `--tar` flag):
`path`, `archive`, `tar_tmp`, `log_dir`, `rgx_patterns`, `rgx_prefix`,
`skip_binary`, `line_limit`, `report_delta`, `csv`, `verbose`, `debug`, `mask`,
`log_anti_pan`, `exception_test`. It contains no argparse code. `cli.py` builds it from parsed
arguments, so tests construct a `Settings` directly.

### models.py

All frozen dataclasses or enums:

- `MatchKind`: `PAN`, `TRACK`, `ANTI_PAN`, `BAD_LUHN`.
- `Match`: `file_path`, `line_number`, `offset`, `kind`, `pattern_name`,
  `pattern`, `matched_data` (raw), `source_line` (raw), `pan` (extracted digits,
  empty for anti-PANs).
- `ScanStats`: counters for files scanned, files skipped, binary, executable,
  and one count per `MatchKind`; `record(kind)`, plus timing fields. It replaces
  `_MatchCount` and the timing globals.

### detectors.py

Pure functions, no logging, no counting:

- `luhn_check(number)`: false for empty and all-zero input.
- `valid_timestamp(value)`.
- `extract_pan(matched_data)`: strips track framing and non-digits.
- `scan_line(file_path, line_number, line, patterns, ...) -> list[Match]`:
  returns every anti-PAN, PAN, TRACK and BAD_LUHN match on the line, using the
  current overlap rules (anti-PAN spans exclude only themselves; a candidate
  overlapping an accepted or anti-PAN span is skipped; a bad number matched by
  two patterns yields one `BAD_LUHN`).

### filetypes.py

`is_executable(path)` and `is_binary(path, skip_binary)`. They return a result
(`SkipReason | None`) and do not mutate counters; the scanner reports the skip.
`python-magic` stays a lazy import with the existing fallback behavior, so a
missing or broken libmagic never prevents start-up.

### archives.py

`extract_archive(archive_path, extractor_config, tar_tmp, runner=subprocess.run)`
is a context manager yielding the temporary directory and always removing it.
The subprocess runner is injectable so tests need no real extractor.
Extractor failures raise `ExtractorError`.

### scanner.py

`Scanner(settings, patterns, reporter, loggers, extractor_config)` with `scan_path()`, `scan_directory()`,
`scan_file()` and `scan_archive()`. It walks files, applies the line limit
(`line_count > line_limit` semantics), calls `detectors.scan_line`, and passes
every `Match` to `reporter.report`. It reports skips through
`reporter.skip(path, reason)` and contains `OSError` per file.

### redact.py

`Redactor(enabled)` with `apply(match) -> RedactedMatch`.
`RedactedMatch` carries the same fields as `Match` but with `matched_data`,
`source_line` and `pan` already redacted when enabled (keep first 6 and last 4
digits of PANs; track data fully masked; any other 12-19 digit run in the
source line masked). With redaction disabled the values pass through unchanged.
`mask_pan`, `mask_matched_data` and `mask_text` live here as the only
implementation.

### reporting.py

```python
class Reporter:
    def report(self, match: Match) -> None:
        self.stats.record(match.kind)
        view = self.redactor.apply(match)
        for sink in self.sinks:
            if sink.accepts(match.kind):
                sink.emit(view)
```

Sinks implement `accepts(kind)`, `emit(view: RedactedMatch)` and `close()`, and
receive only a `RedactedMatch`, never a raw `Match`.

| Sink | Accepts | Output |
|---|---|---|
| `LogSink` | `PAN`, `TRACK` | INFO line on the PAN logger |
| `CsvSink` | `PAN`, `TRACK` | CSV row, flushed per row |
| `TraceSink` | `BAD_LUHN` | `DEBUG` line on the trace logger |
| `AntiPanSink` | `ANTI_PAN` (only created when `--log-anti-pan` is set) | INFO line in its own log file, `Find-PAN-anti-pan-<DDMonYYYY>.log` in the log directory |

`ANTI_PAN` matches are always counted. By default no sink shows them. With
`--log-anti-pan`, the CLI adds an `AntiPanSink` that writes them, after
redaction (so `--mask` applies), to a dedicated log file whose name contains
`anti-pan`. They never appear in the PAN log, the trace log or the CSV. When the
flag is off the sink and its file are not created, so no empty file is left
behind.
`sanitize_for_ascii` is applied inside the sinks that need it. `Reporter` also
provides `skip(path, reason)`, `progress()` (report-delta messages) and
`summary()` (the existing "Processing Summary" / "Skipped Summary" text, built
from real counts, so the old `FILES - 1` adjustment disappears).
When `--log-anti-pan` is set, the "Skipped Summary" gains two lines:
`Anti-PAN log   : <full path of the anti-PAN log file>` and
`Anti-PANs logged: <N>`, where N is the number of entries written to that file.
The existing `Detected N Anti-PANs.` line is unchanged and always shown.
Without the flag the summary is identical to today's.

### logging_setup.py

`build_loggers(settings) -> Loggers` creates the log directory, removes prior
log files as today, and builds the PAN and trace loggers without module
globals. When `settings.log_anti_pan` is set it also builds a third logger
writing to `Find-PAN-anti-pan-<DDMonYYYY>.log` (same date format and directory
as the other logs; a prior file of that name is removed like the others). Failure raises `LoggingSetupError`. A trace file handler failure
reports the original error.

### config.py

Moved from `pan_config.py`: archive-type detection, extractor configuration
discovery and loading, regex configuration discovery and loading, pattern
compilation (with and without prefix). It adds the `--debug` pattern dump
(currently in `main()`), with its own `json` import and a test.

### cli.py

`parse_args(argv) -> Settings` (adds the `--log-anti-pan` flag, default off; single parse; `--version` and `--help` work
without any configuration file), `main(argv=None) -> int`. `main` is the only
place that wires components, handles `KeyboardInterrupt`, prints errors and
chooses exit codes. `print_exception_info()` and `--exception-test` stay here
for unexpected exceptions.

### version.py

Holds `__version__` and `format_version(prog)`. The version is currently
duplicated (`_FindPANVersion` in the script, `version` in `pyproject.toml`).
`bin/update_version.py` is extended to update both, with a test, so they cannot
drift.

## 4. Data flow

```
cli.main(argv)
  settings  <- parse_args(argv)
  config    <- config.load(settings)               # patterns, extractor config
  loggers   <- logging_setup.build_loggers(settings)
  reporter  <- Reporter(Redactor(settings.mask), sinks, ScanStats())
  Scanner(settings, patterns, reporter, loggers).scan_path(...) / scan_archive(...)
  reporter.close()                                 # always, in finally
  print reporter.summary(); return exit code
```

Per file and line: `filetypes` decides scan or skip; `detectors.scan_line`
returns `Match` records; the scanner passes each to `reporter.report`, which
counts, redacts once, and fans out to the sinks that accept that kind.

## 5. Error handling

- `errors.py`: `FindPanError`; subclasses `ConfigError`, `LoggingSetupError`,
  `ExtractorError`.
- Library modules raise these; they never call `sys.exit()` or `print()`.
  `cli.main` converts a `FindPanError` into a stderr message and exit status 1.
- Per-file `OSError` is contained in the scanner (warning plus skip reason, scan
  continues). An extractor failure logs an error and the run continues. The
  temporary extraction directory is always removed.
- Start-up order: arguments, then configuration and patterns, then loggers, then
  sinks (CSV last). A bad pattern file does not leave a half-written CSV.
- SIGINT: no custom handler is installed; Python raises `KeyboardInterrupt` and `main` catches it at every stage,
  closes the sinks, prints the summary and exits with status 1 (unchanged).
- Sinks are closed in a `finally`, so the CSV is always flushed and closed.

## 6. Bugs absorbed by this design

| Item | How it is resolved |
|---|---|
| `--debug` raises `NameError` (`json` not imported in `main()`) | Pattern dump moves to `config`, imports `json`, covered by a test |
| BUG-012 global coupling | No mutable module globals; `Settings` and a `Reporter` are passed explicitly |
| BUG-016, BUG-025 repeated argument parsing | `parse_args` runs once |
| BUG-017, BUG-018 progress and summary counts | `ScanStats` owns counts; summary reports real numbers |
| BUG-021 signal handling before loggers exist | Handler only raises `KeyboardInterrupt`; `main` handles it |
| BUG-023 Visual Studio branch shadows `_Args` | Removed with the globals |
| BUG-011 Luhn failures invisible | `BAD_LUHN` is a first-class `Match` with a sink |
| Version duplicated in script and `pyproject.toml` | Single `version.py`, updated by `update_version.py` |

Out of scope and left in `bug-fix.md` as `todo`: BUG-009, 013, 014, 015, 019,
024, 026, 027, 029, 030, 031. The restructure makes several easier (013, 014,
015 are local to `filetypes`/`scanner`) but does not fix them.

## 7. Packaging and launch

- `bin/find-pan.py` inserts `<repo>/src` at the front of `sys.path` (resolved
  from its own location) and calls `find_pan.cli.main()`. The shebang, the
  README commands and `uv run python bin/find-pan.py` keep working.
- `pyproject.toml` keeps `package = false` and adds
  `[tool.pytest.ini_options] pythonpath = ["src"]`.
- `bin/generate-pan.py`, `check-json-regex.py` and `run-pytest-regression.py`
  do not import `pan_config`; they need no code changes (confirmed by search).
  Documentation paths in the README are updated.
- Files use LF endings (repository `.gitattributes` enforces it).

## 8. Testing

**Unit (per module).**

- `detectors`: table-driven Luhn, anti-PAN, overlap, multi-hit lines, tracks.
- `redact`: every masking rule, enabled and disabled.
- Summary: with `--log-anti-pan` the summary names the anti-PAN log path and the
  logged count (equal to the number of lines written); without it neither line
  appears.
- `--log-anti-pan`: the anti-PAN log file exists and contains the hits only
  when the flag is set; it is absent otherwise; hits never appear in the PAN
  log, trace log or CSV; and they are masked under `--mask`.
- `reporting`: `Reporter` with in-memory fake sinks; each real sink alone.
- `settings` / `cli`: `parse_args(argv)` returns `Settings`; no globals.
- `filetypes`, `archives`, `scanner`: `tmp_path` based; the subprocess runner is
  injected.
- `config`: pattern loading and compilation, including the `--debug` dump.
- `version` / `update_version`: both locations stay in sync.

**Guarantee test.** A parametrized end-to-end test runs `cli.main([...])` with
`--mask`, `--csv` and `--debug` and asserts that the raw PAN and the raw track
data appear in no PAN log, trace log, CSV or captured stdout. The same test
without `--mask` asserts the full values are present. Because it inspects the
real output files, a future sink that bypasses `Redactor` fails it.

**Integration and launcher.** A few `cli.main(argv)` runs check exit codes and
file contents. One test runs `bin/find-pan.py --version` as a subprocess.

**Migration.** Each current test file maps to the new layout:

| Existing | Moves to |
|---|---|
| `test_luhn.py` | detectors tests |
| `test_csv_output.py` | `CsvSink` and CLI integration tests |
| `test_debug_luhn.py` | detectors, redact, reporting and trace-sink tests |
| `test_cmdline.py` | `cli` / `settings` tests |
| `test_configuration.py` | `config` tests |
| `test_archive.py` | `archives` / `scanner` tests |
| `test_exceptions.py` | `cli` error-handling tests |
| `test_generate_pan.py`, `test_update_version.py` | unchanged (separate scripts) |

`conftest.py` no longer reloads a hyphenated script; tests import `find_pan`
and the python-magic stub stays.

**Parity check (one-time, not committed).** Before removing the old code, scan
`RegressionTests/` and `tests` fixtures with the old script (from git) and the
new package and diff the CSV output and counts. Intended differences are listed
in section 9.

## 9. Behavior compatibility

New: `--log-anti-pan` (default off; with it off, output is identical to today).

Unchanged: all existing CLI flags and defaults, log and CSV formats, log file names,
summary wording, exit codes, `--version` / `--help` without configuration.

Note: "today" means the current working tree, where anti-PAN hits are
counted and not shown (`scan_line`, BUG-034). `--log-anti-pan` opts in to a
separate `Find-PAN-anti-pan-<date>.log` for them; it does not change the counts
or the other outputs.

Intended differences, all bug fixes: `--debug` no longer raises `NameError`; the
summary reports the true file count (no `- 1`); progress reports fire on the
correct file; a bad pattern file no longer leaves an empty CSV behind.

## 10. Implementation order (for the plan)

1. Add `src/find_pan` skeleton, `settings`, `errors`, `models`, `version`; wire
   `pytest` `pythonpath`.
2. Move pure logic: `detectors`, `redact`, with their tests.
3. Add `reporting` and `logging_setup`, with tests including the guarantee test
   against the new pipeline.
4. Move `config`, `filetypes`, `archives`, `scanner`.
5. Add `cli` and the launcher; run the parity check against the old script.
6. Migrate remaining tests; update README, `update_version.py`, and
   `bug-fix.md`; delete the old script body and `bin/pan_config.py`.

Each step leaves the suite green; the old script keeps working until step 5.
