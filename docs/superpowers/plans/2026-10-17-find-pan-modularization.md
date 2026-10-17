# Find-PAN Modularization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `bin/find-pan.py` into a `src/find_pan/` package in which every output rule (including `--mask`) is applied once, before any sink sees a match, with no mutable module globals.

**Architecture:** The scanner turns lines into immutable `Match` records. A `Reporter` counts each one, redacts it once with `Redactor`, and hands the `RedactedMatch` to the sinks that accept its kind (PAN log, CSV, trace log, optional anti-PAN log). `Settings` (frozen) and explicit objects replace `_Args`, `_MatchCount`, and the logger/CSV globals. `bin/find-pan.py` becomes a launcher.

**Tech Stack:** Python >= 3.10, argparse, logging, csv, pytest, uv (`uv run pytest`), PyYAML, python-magic (lazy import).

**Spec:** `docs/superpowers/specs/2026-10-17-find-pan-modularization-design.md`

## Global Constraints

- Python `>=3.10` (`pyproject.toml`); type hints use `X | None`, `list[...]`.
- Files use LF line endings (`.gitattributes` has `* text=auto eol=lf`).
- The user has said **do not commit**: no task commits or stages anything. Leave all changes in the working tree.
- `package = false` stays in `pyproject.toml`; add only `pythonpath = ["src"]` to `[tool.pytest.ini_options]`.
- Library modules never call `sys.exit()`, `print()`, or read `sys.argv`; only `cli.py` does.
- Dependencies point downward only: leaf modules (`settings`, `errors`, `models`, `version`, `detectors`, `redact`) import nothing from the package except `models`/`errors`; `reporting` imports `redact`, `models`, `errors`; `scanner` imports `detectors`, `filetypes`, `archives`, `reporting`, `models`, `settings`; `cli` may import everything.
- CLI flags, defaults, log/CSV formats, log file names (`Find-PAN-<DDMonYYYY>.log`, `Find-PAN-trace-<DDMonYYYY>.log`, new `Find-PAN-anti-pan-<DDMonYYYY>.log`), summary wording and exit codes are unchanged. `ANTI_PAN` hits are counted but shown by no sink unless `--log-anti-pan`.
- Masking keeps the first 6 and last 4 digits of a PAN; track data is masked completely; any other 12-19 digit run in a source line is masked.
- The old script and its tests keep working until Task 10; do not delete `bin/pan_config.py` or old tests before then.

## Review Focus

Inputs the spec implies but no task would otherwise exercise, most likely first. Each has a test in the task named in brackets.

1. `--report-delta 0` (or negative): the old code does `files % 0`. Expect an argparse error (exit status 2), not a traceback. [Task 9]
2. A CSV path that cannot be opened: expect a one-line error on stderr and exit status 1, with no traceback and no partial output. [Task 9]
3. Files with no trailing newline, empty files, and non-UTF-8 bytes: scanned without crashing; invalid bytes become replacement characters. [Task 8]
4. A line with several PANs plus other long digit runs, scanned with `--mask`: no raw PAN survives in any sink or in the source line. [Task 3, Task 9]
5. `--log-anti-pan` on input with zero anti-PANs: the file exists, is empty, and the summary shows `Anti-PANs logged: 0`. [Task 4, Task 9]

---

### Task 1: Package skeleton, settings, errors, models, version

**Files:**
- Create: `src/find_pan/__init__.py`, `src/find_pan/settings.py`, `src/find_pan/errors.py`, `src/find_pan/models.py`, `src/find_pan/version.py`
- Modify: `pyproject.toml` (add `pythonpath = ["src"]` under `[tool.pytest.ini_options]`)
- Test: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `errors.py`: `class FindPanError(Exception)`; subclasses `ConfigError`, `LoggingSetupError`, `ExtractorError`.
  - `settings.py`: `@dataclass(frozen=True) class Settings` with fields and defaults `path: str | None = None`, `archive: str | None = None`, `tar_tmp: str = ""`, `log_dir: str = ""`, `rgx_patterns: str | None = None`, `rgx_prefix: bool = False`, `skip_binary: bool = False`, `line_limit: int = 0`, `report_delta: int = 500`, `csv: str | None = None`, `verbose: bool = False`, `debug: bool = False`, `mask: bool = False`, `log_anti_pan: bool = False`, `exception_test: bool = False`.
  - `models.py`: `class MatchKind(str, Enum)` with `PAN="PAN"`, `TRACK="TRACK"`, `ANTI_PAN="ANTI-PAN"`, `BAD_LUHN="BAD-LUHN"`; `@dataclass(frozen=True) class Match` with `file_path: str`, `line_number: int`, `offset: int`, `kind: MatchKind`, `pattern_name: str`, `pattern: str`, `matched_data: str`, `source_line: str`, `pan: str`; `class SkipReason(str, Enum)` with `BINARY="BINARY"`, `EXECUTABLE="EXEC"`, `UNREADABLE="UNREADABLE"`; `class ScanStats` with `count(kind) -> int`, `record(kind: MatchKind) -> None`, `file_scanned() -> None`, `skipped(reason: SkipReason) -> None`, attributes `files`, `skipped_files`, `binary`, `executable` (ints), `start() -> None`, `stop() -> None`, properties `total_time`, `average_time` (total / files, 0 when no files).
  - `version.py`: `__version__ = "2.3.1"`, `format_version(prog: str) -> str` returning `f"{prog} v2.3.1"`.

- [ ] **Step 1: Write failing tests in `tests/test_models.py`**: `test_settings_defaults_and_frozen` (defaults above; assigning `Settings().mask = True` raises `dataclasses.FrozenInstanceError`); `test_stats_record_counts_per_kind`; `test_stats_skip_updates_skipped_and_reason_counters` (BINARY increments `skipped_files` and `binary`; EXECUTABLE increments `skipped_files` and `executable`); `test_stats_average_time_zero_without_files`; `test_format_version` equals `"find-pan v2.3.1"` for prog `"find-pan"`; `test_errors_share_base` (all three subclass `FindPanError`).
- [ ] **Step 2: Run** `uv run pytest tests/test_models.py -q`. Expected: FAIL (`ModuleNotFoundError: find_pan`).
- [ ] **Step 3: Implement** the modules above; add `pythonpath = ["src"]` to `pyproject.toml`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: all pass (old suite unaffected).

---

### Task 2: Detectors

**Files:**
- Create: `src/find_pan/detectors.py`
- Test: `tests/test_detectors.py`

**Interfaces:**
- Consumes: `Match`, `MatchKind` (Task 1).
- Produces:
  - `luhn_check(number: str) -> bool` (false for empty / all-zero; raises `ValueError` for non-digits, as today).
  - `valid_timestamp(value: str) -> bool` (14 digits, `%Y%m%d%H%M%S`, year 1900 to current year + 1).
  - `extract_pan(matched_data: str) -> str` (Track 1 `%B`/`%M` strips framing up to `^`; Track 2 `;` up to `=`; otherwise all digits).
  - `scan_line(file_path: str, line_number: int, line: str, patterns: list[tuple[str, str, re.Pattern]]) -> list[Match]` where each tuple is `(category, pattern_name, compiled)` with category in `"Anti-PAN Pattern" | "PAN Pattern" | "TRACK Pattern"`; raises `ValueError` for any other category.

- [ ] **Step 1: Write failing tests** by porting `tests/test_luhn.py` (valid/invalid PANs, zero strings now rejected, non-numeric raises) and adding table-driven `scan_line` tests using patterns compiled from `config/find-pan-regex.json` via `compile_regex_patterns` (from `pan_config` until Task 6): `test_three_valid_pans_on_one_line` returns 3 `PAN` matches with correct `offset`s; `test_bad_luhn_does_not_hide_valid_pan` (`"<4556737586899856> <4556737586899855>"` yields one `BAD_LUHN` then one `PAN`); `test_anti_pan_excludes_only_its_span` (`"123456789012345678 card 4556737586899855"` yields one `ANTI_PAN` and one `PAN`); `test_same_bad_number_two_patterns_yields_one_bad_luhn`; `test_two_tracks_one_line` yields 2 `TRACK` and no `PAN`; `test_unknown_category_raises_value_error`; `test_invalid_timestamp_not_anti_pan`. Each `Match` has `pan` digits (empty for `ANTI_PAN`) and the raw `matched_data`/`source_line`.
- [ ] **Step 2: Run** `uv run pytest tests/test_detectors.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** by moving the logic from `find-pan.py` (`luhn_check`, `valid_timestamp`, `DataReporter.extract_pan_from_match`, `scan_line`/`_overlaps`) with no logging or counting; `scan_line` keeps the current overlap rules and emits `BAD_LUHN` matches instead of calling `DataReporter`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 3: Redactor

**Files:**
- Create: `src/find_pan/redact.py`
- Test: `tests/test_redact.py`

**Interfaces:**
- Consumes: `Match` (Task 1).
- Produces: `mask_pan(pan: str) -> str`; `mask_matched_data(matched: str, pan: str) -> str`; `mask_text(text: str) -> str`; `@dataclass(frozen=True) class RedactedMatch` with the same fields as `Match`; `class Redactor` with `__init__(self, enabled: bool)` and `apply(self, match: Match) -> RedactedMatch`.

- [ ] **Step 1: Write failing tests** porting `test_mask_pan_helpers` (`"4556737586899856" -> "455673******9856"`; 9-digit input fully masked; `"4556 7375 8689 9856"` -> `"4556 73** **** 9856"`; `";4556737586899856=2512"` -> `";****************=****"`) and adding: `test_apply_disabled_returns_identical_values`; `test_apply_masks_matched_data_pan_and_source_line` (raw PAN absent from every field); `test_apply_masks_other_long_digit_runs_in_source_line` (a second 16-digit number in `source_line` is masked); `test_apply_masks_track_fully`; `test_apply_does_not_mutate_input_match`.
- [ ] **Step 2: Run** `uv run pytest tests/test_redact.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** by moving `mask_pan`, `mask_matched_data`, `mask_text` out of `find-pan.py`; `apply` masks `matched_data` with `mask_matched_data(match.matched_data, match.pan)`, `pan` with `mask_pan`, and `source_line` by replacing the matched text then `mask_text` over the rest.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 4: Reporter and sinks

**Files:**
- Create: `src/find_pan/reporting.py`
- Test: `tests/test_reporting.py`

**Interfaces:**
- Consumes: `Match`, `MatchKind`, `ScanStats`, `SkipReason` (Task 1); `Redactor`, `RedactedMatch` (Task 3); `ConfigError` (Task 1).
- Produces:
  - Sink protocol: `accepts(kind: MatchKind) -> bool`, `emit(view: RedactedMatch) -> None`, `close() -> None`.
  - `LogSink(logger: logging.Logger)` accepts `PAN`, `TRACK`; emits `"%s:%s:%s->%s (%s), %s: %s"` (path, line, offset, pattern name, kind, pattern, source line) at INFO.
  - `CsvSink(path: str)` accepts `PAN`, `TRACK`; opens the file (`ConfigError` on `OSError`), writes the header `filename,line_number,offset,pattern_name,data_type,matched_data`, one row per emit with `sanitize_for_ascii` and `os.path.basename`, flushes per row.
  - `TraceSink(logger)` accepts `BAD_LUHN`; emits `"Luhn failure: file=%s line=%s offset=%s pattern=%s extracted=%s matched=%s"` at DEBUG.
  - `AntiPanSink(logger, path: str)` accepts `ANTI_PAN`; same line format as `LogSink`; attribute `entries: int`, `path: str`.
  - `sanitize_for_ascii(value: str) -> str`.
  - `Reporter(redactor: Redactor, sinks: list, stats: ScanStats, trace_logger: logging.Logger, report_delta: int)` with `report(match: Match) -> None` (records the kind in `stats`, redacts once, emits to every sink whose `accepts(match.kind)` is true), `file_started() -> None` (calls `stats.file_scanned()`; every `report_delta` files logs `"Scanned %s files; matched %s PANs, %s TRACKs, %s Files Skipped"` at INFO on `trace_logger`), `skip(path: str, reason: SkipReason) -> None`, `summary_lines(log_dir: str) -> list[str]`, `close() -> None` (closes every sink even if one raises).
  - `summary_lines` reproduces the current "Processing Summary" / "Skipped Summary" text using real counts (no `FILES - 1`); when an `AntiPanSink` is present it adds `Anti-PAN log   : <path>` and `Anti-PANs logged: <entries>` after the `Detected N Anti-PANs.` line.

- [ ] **Step 1: Write failing tests** with a `FakeSink` recording emitted views: `test_report_redacts_once_and_fans_out`; `test_sinks_only_receive_redacted_views` (with `Redactor(True)` the raw PAN appears in no emitted field); `test_sink_not_called_for_unaccepted_kind`; `test_counts_all_kinds_even_when_no_sink_accepts`; `test_log_sink_and_csv_sink_ignore_bad_luhn_and_anti_pan`; `test_csv_sink_writes_header_and_row_and_flushes` (read the file before `close()`); `test_csv_sink_unwritable_path_raises_config_error`; `test_csv_sanitizes_non_ascii`; `test_trace_sink_logs_bad_luhn_at_debug` (caplog); `test_anti_pan_sink_counts_entries_and_writes_only_anti_pans`; `test_summary_without_anti_pan_sink_has_no_anti_pan_log_lines`; `test_summary_with_anti_pan_sink_shows_path_and_count` including count `0` for an empty log (Review Focus 5); `test_progress_logged_every_report_delta_files`; `test_close_closes_all_sinks_even_if_one_fails`.
- [ ] **Step 2: Run** `uv run pytest tests/test_reporting.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `reporting.py`; summary wording copied from `print_scan_summary()` in `bin/find-pan.py`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 5: Logging setup

**Files:**
- Create: `src/find_pan/logging_setup.py`
- Test: `tests/test_logging_setup.py`

**Interfaces:**
- Consumes: `Settings`, `LoggingSetupError` (Task 1).
- Produces: `generate_logfile_name(basename: str) -> str` (`f"{basename}-{DDMonYYYY}.log"`, e.g. `Find-PAN-17Oct2026.log`); `@dataclass class Loggers` with `pan: logging.Logger`, `trace: logging.Logger`, `anti_pan: logging.Logger | None`, `anti_pan_path: str | None`; `build_loggers(settings: Settings) -> Loggers`.

- [ ] **Step 1: Write failing tests** (each uses `tmp_path` and a `Settings(log_dir=..., tar_tmp=...)`): `test_creates_log_and_tar_tmp_directories`; `test_creates_pan_and_trace_files_and_removes_prior_ones`; `test_debug_sets_trace_level_debug_else_info`; `test_verbose_adds_console_handler_to_pan_logger`; `test_repeated_build_does_not_duplicate_handlers`; `test_anti_pan_logger_absent_by_default_and_no_file`; `test_anti_pan_logger_and_file_named_with_anti_pan_when_flag_set` (name contains `anti-pan`); `test_unwritable_log_dir_raises_logging_setup_error` (log_dir is an existing file).
- [ ] **Step 2: Run** `uv run pytest tests/test_logging_setup.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** by moving `generate_logfile_name`, `set_log_directory_and_filenames`, `setup_custom_loggers` (use named loggers, clear their handlers first, raise `LoggingSetupError` with the original message instead of `sys.exit`).
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 6: Config

**Files:**
- Create: `src/find_pan/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: `ConfigError` (Task 1).
- Produces (names unchanged from `bin/pan_config.py`): `EXTRACTOR_CONFIG_FILENAME`, `detect_archive_type(path) -> str | None`, `find_extractor_config_path() -> str`, `load_extractor_config(path) -> dict[str, dict]`, `build_extractor_config(path) -> None`, `find_json_regex_config() -> str`, `load_json_data(filename) -> dict | None`, `compile_regex_patterns(json_data) -> list`, `compile_regex_patterns_with_prefix(json_data) -> list`; new `dump_patterns(json_data: dict) -> str` (`json.dumps(json_data, indent=4)`). `_application_root()` returns `Path(__file__).resolve().parents[2]`.

- [ ] **Step 1: Write failing tests** by porting `tests/test_configuration.py` and `tests/test_archive.py` config/detection cases to import `find_pan.config`, plus `test_dump_patterns_round_trips_json` (covers the missing-`json`-import bug) and `test_application_root_is_repository_root` (contains `config/find-pan-regex.json`).
- [ ] **Step 2: Run** `uv run pytest tests/test_config.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** by copying `bin/pan_config.py` to `src/find_pan/config.py`, fixing the root depth, adding `dump_patterns`, and raising `ConfigError` where it now raises bare `FileNotFoundError`/`ValueError` for missing or invalid files (keep both caught in `cli`). Leave `bin/pan_config.py` in place for now.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 7: File-type detection and archives

**Files:**
- Create: `src/find_pan/filetypes.py`, `src/find_pan/archives.py`
- Test: `tests/test_filetypes.py`, `tests/test_archives.py`

**Interfaces:**
- Consumes: `SkipReason`, `ExtractorError` (Task 1); `detect_archive_type`, `EXTRACTOR_CONFIG_FILENAME` (Task 6).
- Produces:
  - `filetypes.is_executable(path: str, logger: logging.Logger, verbose: bool = False) -> bool` (lazy `import magic`; returns False and warns when unavailable or failing, as today).
  - `filetypes.has_binary_content(path: str) -> bool` (first 1024 bytes excluding the last two contain both `0x00` and `0xFF`; `OSError` propagates).
  - `filetypes.skip_reason(path: str, skip_binary: bool, logger: logging.Logger, verbose: bool = False) -> SkipReason | None` (None when `skip_binary` is false).
  - `archives.extract_archive(archive_path: str, extractor_config: dict[str, dict], tar_tmp: str, logger: logging.Logger, runner=subprocess.run, verbose: bool = False)` — a context manager yielding the temp directory path, always removing it; raises `ExtractorError` for unsupported type, missing/incomplete extractor config, missing command, or non-zero exit.

- [ ] **Step 1: Write failing tests**: `test_skip_reason_none_when_skip_binary_false`; `test_binary_content_needs_both_nul_and_ff`; `test_executable_detected_via_stubbed_magic` (install a stub `magic` module in `sys.modules`); `test_magic_import_error_returns_false_and_warns`; `test_extract_archive_yields_dir_and_removes_it` (fake `runner` records the command, formatted from `{archive}`/`{tempdir}`); `test_extract_archive_copies_archive_when_configured`; `test_extract_archive_removes_dir_when_runner_fails` (runner raises `subprocess.CalledProcessError`; expect `ExtractorError`, directory gone); `test_unsupported_type_and_missing_extractor_raise_extractor_error`.
- [ ] **Step 2: Run** `uv run pytest tests/test_filetypes.py tests/test_archives.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** by moving `is_executable`, `is_binary`, `process_archive_file` out of `find-pan.py`, replacing counters and `_Args` use with parameters and returned values.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 8: Scanner

**Files:**
- Create: `src/find_pan/scanner.py`
- Test: `tests/test_scanner.py`

**Interfaces:**
- Consumes: `Settings`, `ExtractorError`, `SkipReason` (Task 1); `scan_line` (Task 2); `Reporter` (Task 4); `Loggers` (Task 5); `skip_reason`, `extract_archive` (Task 7).
- Produces: `class Scanner` with `__init__(self, settings: Settings, patterns: list, reporter: Reporter, loggers: Loggers, extractor_config: dict | None = None)`, `scan_path(path: str) -> None`, `scan_directory(directory: str) -> None`, `scan_file(file_path: str) -> None`, `scan_archive(archive_path: str) -> None`.

- [ ] **Step 1: Write failing tests** (fixtures build a real `Reporter` with `FakeSink`, patterns from `compile_regex_patterns`): `test_scan_file_reports_each_hit_once`; `test_line_limit_scans_exactly_limit_lines` (limit 3, 6 PAN lines -> 3); `test_empty_file_and_no_trailing_newline_and_invalid_utf8` (Review Focus 3); `test_binary_file_skipped_when_skip_binary_and_counted`; `test_unreadable_file_is_skipped_and_scan_continues` (patch `open` to raise `PermissionError` for one file); `test_scan_directory_walks_nested_directories`; `test_scan_archive_scans_extracted_files_and_cleans_up` (inject extractor via monkeypatched `extract_archive` yielding a prepared tmp directory); `test_scan_archive_extractor_error_is_logged_not_raised`.
- [ ] **Step 2: Run** `uv run pytest tests/test_scanner.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `process_filesystem`/`scan_directory`/`process_file` behavior: call `reporter.file_started()` before reading, `reporter.skip(path, reason)` on skip or `OSError`, `scan_line` per line with `line_count > line_limit` break semantics, and `reporter.report(match)` for each result; log the same "Scanning ..." messages to the PAN/trace loggers as today.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.

---

### Task 9: CLI, launcher, end-to-end tests, parity check

**Files:**
- Create: `src/find_pan/cli.py`, `tests/test_cli.py`, `tests/test_output_redaction.py`
- Modify: `bin/find-pan.py` (becomes the launcher, below)

**Interfaces:**
- Consumes: everything from Tasks 1-8.
- Produces: `build_parser() -> argparse.ArgumentParser`; `parse_args(argv: Sequence[str] | None = None) -> Settings` (flags unchanged, `--tar` fills `Settings.archive`, new `--log-anti-pan` store_true, `--report-delta` must be >= 1 else `parser.error`); `main(argv: Sequence[str] | None = None) -> int`. `main` order: parse; `--version` prints version info and returns 0 before any config; resolve regex config; `--exception-test`; load/compile patterns (`ConfigError`/`FileNotFoundError`/`ValueError` -> stderr, return 1); build loggers; build sinks (`CsvSink` last; `AntiPanSink` only with `--log-anti-pan`); install SIGINT handler that raises `KeyboardInterrupt`; run `Scanner`; in `finally` `reporter.close()`; print/log `summary_lines`; return 0, or 1 after `KeyboardInterrupt`, `FindPanError`, or "required arguments not found" (print help). Keep `print_exception_info(e)` here for unexpected exceptions.
- Launcher `bin/find-pan.py`: keep the shebang; insert `<repo>/src` at the front of `sys.path` using `Path(__file__).resolve().parents[1] / "src"`; `raise SystemExit(main())` from `find_pan.cli`.

- [ ] **Step 1: Write failing tests**: in `tests/test_cli.py`: `test_parse_args_defaults_and_flags` (all flags incl. `--mask`, `--log-anti-pan`, `--tar` -> `archive`); `test_report_delta_zero_is_argparse_error` (`SystemExit` code 2); `test_version_works_without_config`; `test_missing_arguments_prints_help_returns_1`; `test_bad_pattern_file_returns_1_and_creates_no_csv`; `test_unwritable_csv_returns_1_without_traceback` (capsys has no `Traceback`); `test_keyboard_interrupt_closes_csv_and_returns_1` (monkeypatch `Scanner.run`); `test_debug_dumps_patterns_without_name_error`; `test_launcher_version_subprocess` (`subprocess.run([sys.executable, "bin/find-pan.py", "--version"])` returns 0 and prints `v2.3.1`). In `tests/test_output_redaction.py`: a parametrized `test_mask_hides_raw_values_in_every_output` that scans a file containing two PANs on one line, a Track 1 and Track 2 record, and an anti-PAN, with `["--path", dir, "--mask", "--csv", csv, "--debug", "--log-anti-pan", "--log-dir", logs, "--tar-tmp", tmp]`, then asserts no raw PAN or raw track string appears in any file under `logs/`, in the CSV, or in captured stdout; `test_without_mask_full_values_are_present`; `test_log_anti_pan_file_absent_without_flag`; `test_log_anti_pan_summary_lines_and_count`; `test_zero_anti_pans_creates_empty_file_and_count_zero`.
- [ ] **Step 2: Run** `uv run pytest tests/test_cli.py tests/test_output_redaction.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `cli.py` and the launcher as described; arguments help text copied from `process_cmdline_arguments()`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: pass.
- [ ] **Step 5: Parity check (not committed):** put the old script at `$TEMP/old-find-pan.py` via `git show HEAD:bin/find-pan.py` (its `pan_config` import needs `bin/` on `PYTHONPATH`), scan `RegressionTests/` with it and with the new launcher using the same flags and `--csv`, and compare the CSV files and the `Detected`/`Matched` counts. Expected: identical CSV; differences only the intended ones in spec section 9. Record the result in the task notes.

---

### Task 10: Migrate remaining tests, tooling and docs; remove old code

**Files:**
- Modify: `bin/update_version.py`, `README.md`, `bug-fix.md`, `tests/conftest.py`
- Delete: `bin/pan_config.py`; old tests superseded by Tasks 2-9 (`tests/test_luhn.py`, `tests/test_csv_output.py`, `tests/test_debug_luhn.py`, `tests/test_cmdline.py`, `tests/test_configuration.py`, `tests/test_archive.py`, `tests/test_exceptions.py`) after confirming each of their cases has a counterpart (list the mapping in the task notes)
- Test: `tests/test_update_version.py`

**Interfaces:**
- Consumes: `find_pan.version.__version__` (Task 1).
- Produces: `update_version.py` writes the new version to both `pyproject.toml` and `src/find_pan/version.py` (`__version__ = "X.Y.Z"`), with `--version-file` defaulting to that path.

- [ ] **Step 1: Write failing tests** in `tests/test_update_version.py`: `test_bump_updates_pyproject_and_version_module_together`; `test_version_module_and_pyproject_agree` (current repo files; fails on drift); `test_exception_test_flag_prints_exception_info` (ported from `test_exceptions.py` against `cli.main(["--exception-test"])`, exit status 1).
- [ ] **Step 2: Run** `uv run pytest tests/test_update_version.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the `update_version.py` change; slim `tests/conftest.py` to the fixtures still used (magic stub, `tmp_path` helpers) and remove the hyphenated-script loader; delete `bin/pan_config.py` and the superseded tests; move any remaining old-script code out of `bin/find-pan.py` (it must contain only the launcher).
- [ ] **Step 4: Update docs:** `README.md` (new `--log-anti-pan` argument row and usage line; layout section describing `src/find_pan/`; note `uv run python bin/find-pan.py` is unchanged); `bug-fix.md` (mark BUG-011 `done`, BUG-012, 016, 017, 018, 021, 023, 025 `done`; add a new entry for the `--debug` `NameError` as `done`; add a note for the version-sync fix).
- [ ] **Step 5: Run** `uv run pytest tests -q` and `uv run python bin/find-pan.py --version`. Expected: all pass; version line `find-pan.py v2.3.1`. Run `grep -rn "pan_config" --include=*.py --include=*.md .` and expect no references outside `bug-fix.md` history text.
