# baseline.py Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `bin/baseline.py`, which archives find-pan's findings as a baseline (`--create`) and re-runs find-pan to verify nothing changed (`--validate NAME` / `--validate --all`).

**Architecture:** Two small find-pan additions (`--summary-json`, stable `archive!/member` display paths) make runs machine-comparable. `baseline.py` is a single script of pure functions (name/path handling, deterministic input enumeration and hashing, canonical CSV, diffs) plus a thin subprocess runner and CLI. A baseline is `RegressionTests/baseline/<name>/baseline.csv` + `baseline.yaml`.

**Tech Stack:** Python >= 3.10, argparse, csv, hashlib, subprocess, PyYAML (already a dependency), pytest, uv.

**Spec:** `docs/superpowers/specs/2026-10-17-baseline-tool-design.md`

## Global Constraints

- Python `>=3.10`; type hints use `X | None`, `list[...]`. Files use LF line endings.
- Work on branch `baseline-tool`. Commit at the end of each task with the trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Do not push or open a PR (the user decides).
- `baseline.py` runs find-pan as a **subprocess** of `bin/find-pan.py` with `sys.executable`, working directory = repository root, and never imports `find_pan` internals except `find_pan.filetypes.sniff_archive_format` and `find_pan.config` for tool names.
- Baseline names match `^[A-Za-z0-9][A-Za-z0-9._-]*$`; no path separators, no `..`.
- All paths stored in `baseline.yaml` are repository-relative with `/` separators, and every input must be inside the repository.
- Input lists are sorted by the UTF-8 bytes of the path. Text files (no NUL in the first 8192 bytes) are hashed after `\r\n` -> `\n`; binary files are hashed raw.
- The CSV is stored sorted by `(filename, int line_number, int offset, pattern_name, data_type, matched_data)`, written with `csv` (header `filename,line_number,offset,pattern_name,data_type,matched_data`), `\n` line endings, UTF-8.
- Exit status: 0 pass/created, 1 difference, 2 usage/environment error. `baseline.py` owns find-pan's `--csv`, `--log-dir`, `--summary-json`, `--version`, `--verbose`, `--debug`; passing them to `--create` is an error.
- `--validate` never modifies a baseline. Temporary files are removed on every path.
- Shipped baselines must not use `--skip-binary` (it depends on libmagic).

## Review Focus

Conditions the spec implies but the task tests would not otherwise exercise, most likely first. Each has a test in the task named.

1. A baseline name or YAML `name` containing `..`, `/`, `\` or an absolute path must be rejected before any file is read or written. [Task 2, Task 3]
2. A find-pan run with zero findings (header-only CSV, empty skipped list) creates and validates cleanly. [Task 3]
3. File names and matched data containing commas, quotes, non-ASCII and spaces round-trip through the CSV and sort identically on every platform. [Task 2]
4. A failed or interrupted `--create` leaves no partial baseline directory; `--force` replacement is atomic (old baseline intact on failure). [Task 3]
5. `--validate --all` with no baselines is an error (exit 2), and one broken baseline does not stop the others from running. [Task 3]

---

### Task 1: find-pan `--summary-json` and stable display paths for archive members

**Files:**
- Modify: `src/find_pan/settings.py`, `src/find_pan/cli.py`, `src/find_pan/reporting.py`, `src/find_pan/scanner.py`
- Test: `tests/test_summary_json.py`

**Interfaces:**
- Produces:
  - `Settings.summary_json: str | None = None`; CLI option `--summary-json PATH` (help text: write the run summary as JSON).
  - `Reporter.summary_data() -> dict` with keys `pans`, `tracks`, `bad_luhn`, `anti_pans`, `files_scanned`, `archives_expanded`, `archives_skipped` (ints), `skipped` (list of `[reason_value, path]`, in the order skipped), `total_time`, `average_time` (floats).
  - `cli.main` writes `summary_data()` plus `"exit_status": <int>` to the `--summary-json` path (UTF-8, `\n`, `indent=2`, `sort_keys=True`) after the scan, also when the exit status is 1.
  - `Scanner.display_path(path: str) -> str`: a path under an extraction directory becomes `<display of the archive>!/<member path with / separators>`, nested archives chain (`outer.zip!/inner.tar!/f.txt`); any other path has `os.sep` replaced by `/`. `Scanner._skip` passes the display path (and a display-path detail) to `Reporter.skip`.

- [ ] **Step 1: Write failing tests in `tests/test_summary_json.py`**: `test_summary_json_written_with_counts_and_exit_status` (run `cli.main` over a temp dir with one PAN file, parse the JSON: `pans == 1`, `files_scanned == 1`, `exit_status == 0`, `skipped == []`); `test_summary_json_written_when_a_file_entry_is_missing` (`--file` missing path: `exit_status == 1`, `skipped == [["NOT-FOUND", "<path with / separators>"]]`); `test_summary_json_is_valid_when_nothing_found` (zero counts); `test_summary_json_option_is_documented_in_help`; `test_display_path_of_a_top_level_file_uses_forward_slashes` (monkeypatch `os.sep` helper by passing a path built with `os.path.join`); `test_display_path_of_an_extracted_member_is_archive_bang_member` (fake `extract_archive` yields a temp dir containing a symlink-stand-in or a binary skip; the `skipped` entry path equals `bundle.zip!/inner/blob.bin`); `test_display_path_of_a_nested_archive_chains` (two fake extractions -> `outer.zip!/inner.zip!/blob.bin`); `test_csv_filename_column_is_unchanged_for_members` (still the basename).
- [ ] **Step 2: Run** `uv run pytest tests/test_summary_json.py -q`. Expected: FAIL (unknown option / missing attribute).
- [ ] **Step 3: Implement** the interfaces above: a stack `self._extractions: list[tuple[str, str]]` of `(extraction dir, archive display path)` pushed/popped around the `_walk` in `Scanner._expand_unchecked`; `display_path` checks the stack from the innermost outward. Add the option to `build_parser`/`_settings_from`; write the JSON in `_run` after `summary_lines`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: all pass (existing tests unchanged).
- [ ] **Step 5: Commit** `git add -A src tests && git commit` with message "Add --summary-json and stable archive member display paths".

---

### Task 2: baseline.py pure functions

**Files:**
- Create: `bin/baseline.py` (functions only; `main` added in Task 3)
- Test: `tests/test_baseline.py` (load the script with `importlib.util.spec_from_file_location("baseline", ROOT / "bin" / "baseline.py")`, as `tests/test_purge_log_files.py` does)

**Interfaces:**
- Produces (all in `bin/baseline.py`):
  - `class BaselineError(Exception)`; constants `REPO_ROOT: Path`, `BASELINE_ROOT: Path` (`REPO_ROOT / "RegressionTests" / "baseline"`), `OWNED_SWITCHES: tuple[str, ...]`, `CSV_FIELDS: list[str]`.
  - `validate_name(name: str) -> str` (returns the name; raises `BaselineError`).
  - `to_repo_relative(path: str, root: Path = REPO_ROOT) -> str` (POSIX, must exist and be inside `root`, else `BaselineError`).
  - `rewrite_find_pan_args(args: list[str], root: Path = REPO_ROOT) -> list[str]` (rewrites the values of `--path`, `--file` (every following value up to the next `--` option) and `--rgx-patterns`; raises `BaselineError` for any `OWNED_SWITCHES` entry).
  - `enumerate_inputs(args: list[str], root: Path = REPO_ROOT) -> list[str]` (sorted by UTF-8 bytes; `--path DIR` lists regular files recursively, skipping symlinks and special files; `--file` entries are listed as given; duplicates removed).
  - `hash_input(rel_path: str, root: Path = REPO_ROOT) -> dict` -> `{"path", "size", "sha256", "eol_normalized"}`; `inputs_manifest(args, root) -> list[dict]`.
  - `canonical_rows(rows: Iterable[Sequence[str]]) -> list[tuple[str, ...]]`; `read_rows(path: Path) -> list[tuple[str, ...]]` (skips the header); `write_canonical_csv(rows, path: Path) -> None`.
  - `diff_rows(baseline: list, current: list) -> tuple[list, list]` -> `(missing, extra)` as multiset differences, each sorted canonically.
  - `diff_inputs(baseline: list[dict], current: list[dict]) -> list[str]` (messages for added/removed/changed files).
  - `diff_summary(baseline: dict, current: dict) -> list[str]` (compares `pans, tracks, bad_luhn, anti_pans, files_scanned, archives_expanded, archives_skipped` and the sorted `skipped` pairs; ignores times and `exit_status`; message format `field: baseline X, now Y`).
  - `format_row(row) -> str` -> `file:line:offset  type  pattern  data`.

- [ ] **Step 1: Write failing tests in `tests/test_baseline.py`**: `test_validate_name_accepts_and_rejects` (accepts `plain-text`, `a.b_c`; rejects `""`, `..`, `a/b`, `a\\b`, `/abs`, `-x`, `a b`); `test_to_repo_relative_uses_forward_slashes_and_rejects_outside_and_missing`; `test_rewrite_args_rewrites_path_file_and_rgx_patterns_and_keeps_other_switches`; `test_rewrite_args_rejects_every_owned_switch` (parametrized); `test_enumerate_is_sorted_by_utf8_bytes_not_walk_order` (create `B.txt`, `a.txt`, `é.txt`, `Z/z.txt` in a temp repo root and assert the exact list `B.txt, Z/z.txt, a.txt, é.txt`); `test_enumerate_skips_symlinks_and_lists_archives_once` (skip the symlink part if symlinks cannot be created); `test_enumerate_path_and_file_union_is_deduplicated`; `test_hash_text_ignores_crlf_but_not_content` (CRLF and LF copies equal, one-byte change differs, `eol_normalized` true); `test_hash_binary_is_raw` (bytes containing NUL: CRLF vs LF differ, `eol_normalized` false); `test_canonical_rows_sort_numeric_fields_numerically` (line 2 before line 10); `test_csv_round_trip_with_commas_quotes_unicode_and_spaces` (Review Focus 3; rows written then read are equal and sort order is stable); `test_write_canonical_csv_uses_lf_and_header`; `test_diff_rows_multiset` (duplicates count; missing/extra); `test_diff_inputs_reports_added_removed_changed`; `test_diff_summary_ignores_times_and_reports_changes`; `test_format_row`.
- [ ] **Step 2: Run** `uv run pytest tests/test_baseline.py -q`. Expected: FAIL (module/attributes missing).
- [ ] **Step 3: Implement** the interfaces in `bin/baseline.py` (shebang `#!/usr/bin/env -S uv run python`, module docstring, the same banner style as the other scripts). Sorting key for paths: `path.encode("utf-8")`. Row sort key: `(filename, int(line), int(offset), pattern, type, data)`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: all pass.
- [ ] **Step 5: Commit** "Add baseline.py core: inputs, hashing, canonical CSV and diffs".

---

### Task 3: baseline.py `--create`, `--validate` and the command line

**Files:**
- Modify: `bin/baseline.py`
- Test: `tests/test_baseline.py` (end-to-end tests on a temporary copy of the repository's `RegressionTests` fixtures and a temporary baseline root)

**Interfaces:**
- Consumes: Task 1 (`--summary-json`, display paths) and Task 2 functions.
- Produces:
  - `run_find_pan(args: list[str], root: Path = REPO_ROOT) -> RunResult` where `RunResult` is a dataclass `(rows: list[tuple], summary: dict, status: int, stderr: str)`; it runs `[sys.executable, str(root / "bin" / "find-pan.py"), *args, "--csv", tmp_csv, "--log-dir", tmp_dir, "--summary-json", tmp_json]` with `cwd=root`, deletes its temporary files, and raises `BaselineError` (with stderr) when the status is not 0 or 1 or the CSV/JSON is missing.
  - `required_tools(inputs: list[str], root: Path) -> list[str]`: extractor command names (from `find_pan.config.load_extractor_config(find_extractor_config_path())`) needed by inputs whose content `find_pan.filetypes.sniff_archive_format` identifies as an archive; sorted, unique.
  - `create(name: str, description: str, find_pan_args: list[str], force: bool = False, root: Path = REPO_ROOT, baseline_root: Path = BASELINE_ROOT) -> Path`: builds the baseline in a temporary directory inside `baseline_root` and moves it into place only on success (atomic replace for `--force`); writes `baseline.csv` and `baseline.yaml` (fields exactly as in the spec: `name, description, created, find_pan{version, command}, python, platform, requires_tools, inputs, summary`).
  - `validate(name: str, strict: bool = False, max_diff: int = 50, root=REPO_ROOT, baseline_root=BASELINE_ROOT) -> Outcome`, a dataclass `(name, verdict, lines: list[str], status: int)` with verdict one of `PASS`, `FAIL (inputs changed)`, `FAIL (output differs)`, `FAIL (inputs changed, output differs)`, `SKIPPED (environment)`, `ERROR`; `status` 0, 1 or 2 (SKIPPED is 0, or 1 with `strict`).
  - `main(argv: list[str] | None = None) -> int` with the command line of spec section 3 (`parse_known_args`; `--validate [NAME]`, `--all`, `--create NAME`, `--description`, `--force`, `--strict`, `--max-diff`).

- [ ] **Step 1: Write failing end-to-end tests** (each uses the `tmp_path` fixture: copy `RegressionTests/*.txt` into `tmp_path/RegressionTests`, copy `bin/` and `src/` and `config/` so the subprocess runs a real find-pan, and pass `root`/`baseline_root`): `test_create_then_validate_passes` (both files exist; yaml has `name`, `find_pan.version`, `inputs` sorted, `summary.pans > 0`); `test_create_refuses_an_existing_name_without_force_and_replaces_with_force`; `test_failed_create_leaves_no_partial_directory` (Review Focus 4; bad switch makes find-pan exit 2; assert the baseline directory does not exist and, with `--force`, the old baseline is intact); `test_create_rejects_owned_switches_and_outside_paths`; `test_create_with_zero_findings` (Review Focus 2: an input file without PANs creates, then validates `PASS`); `test_validate_detects_an_edited_input_and_names_the_lost_row` (remove one PAN line: verdict `FAIL (inputs changed, output differs)`, a `missing:` line containing `file:line:offset`); `test_validate_detects_a_corrupted_baseline_row` (edit one CSV row: `FAIL (output differs)` naming it as missing and extra); `test_validate_detects_a_changed_summary_count`; `test_crlf_only_change_to_an_input_passes`; `test_validate_reports_added_and_removed_input_files`; `test_validate_all_mixes_pass_and_fail_and_returns_1`; `test_validate_all_continues_after_a_broken_baseline` (Review Focus 5: malformed YAML in one, the others still validated, overall status 2 only when none failed with 1... assert exact: broken + pass -> 2; broken + fail -> 1); `test_validate_all_with_no_baselines_is_an_error_status_2`; `test_unknown_baseline_status_2`; `test_yaml_name_must_match_directory_and_names_with_separators_are_rejected` (Review Focus 1, for `--create` and `--validate`); `test_missing_tool_is_skipped_and_fails_with_strict` (write a baseline whose `requires_tools` lists a nonexistent tool name); `test_max_diff_limits_printed_rows_but_prints_the_count`; `test_validate_does_not_modify_the_baseline` (file hashes before/after); `test_main_exit_codes`.
- [ ] **Step 2: Run** `uv run pytest tests/test_baseline.py -q`. Expected: the new tests FAIL (functions missing).
- [ ] **Step 3: Implement** the interfaces. `validate` order: load YAML and check the name -> required tools (SKIPPED) -> re-enumerate and hash inputs -> `run_find_pan(recorded command)` -> compare rows and summary. The recorded `find_pan.command` is run as-is (it is already repository-relative). `main` prints each outcome as `NAME: VERDICT` followed by its detail lines and a final tally line `N passed, N failed, N skipped, N errors`.
- [ ] **Step 4: Run** `uv run pytest tests -q`. Expected: all pass.
- [ ] **Step 5: Commit** "Add baseline.py --create and --validate".

---

### Task 4: Shipped baselines, cross-platform check, documentation

**Files:**
- Create: `RegressionTests/baseline/plain-text/{baseline.csv,baseline.yaml}`, `RegressionTests/baseline/archives/{...}`, `RegressionTests/baseline/masked/{...}`
- Modify: `README.md`, `bug-fix.md` (no new bug entries; add a short "Regression baselines" note only if the file has a suitable section, otherwise skip), `tests/test_baseline.py`
- Test: `tests/test_shipped_baselines.py`

**Interfaces:**
- Consumes: `baseline.create`, `baseline.validate` (Task 3).

- [ ] **Step 1: Write failing test `tests/test_shipped_baselines.py`**: `test_every_shipped_baseline_passes` (parametrized over `baseline.py --validate --all` listing; calls `validate` per directory against the real repository; skipped when an archive baseline reports `SKIPPED (environment)`); `test_shipped_baseline_names_match_their_directories`; `test_shipped_baselines_have_lf_line_endings`.
- [ ] **Step 2: Run** the test. Expected: FAIL (no baselines yet).
- [ ] **Step 3: Create the baselines** with the tool: `uv run python bin/baseline.py --create plain-text --description "13 plain card-brand fixtures" --file RegressionTests/American-Express.txt ... ` (all 13 `.txt` files, no `--path`), `--create archives --description "zip, tar and 7z copies of the plain fixtures" --file RegressionTests/ZIP_Test.zip RegressionTests/TAR_Test.tar RegressionTests/7z_Test.7z`, `--create masked --description "plain fixtures with --mask" --mask --file <the 13 files>`.
- [ ] **Step 4: Cross-platform validation:** run `uv run python bin/baseline.py --validate --all` on Windows, then in WSL (`wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/dmean/GitHub/Find-PAN && UV_PROJECT_ENVIRONMENT=.venv-linux uv run --frozen python bin/baseline.py --validate --all'`). Expected: `plain-text` and `masked` PASS on both; `archives` PASS on Windows and `SKIPPED (environment)` on Linux when `7z` is absent. If any baseline differs between platforms, stop and diagnose before continuing (do not edit the baseline to match).
- [ ] **Step 5: Document:** README section "Regression baselines" (purpose, `--create`/`--validate`/`--all` examples, what the directory holds, exit codes, the Windows/Linux note, `--strict`). Update the test count claims only if the README states one.
- [ ] **Step 6: Run** `uv run pytest tests -q`, then commit "Add shipped regression baselines and document baseline.py".
