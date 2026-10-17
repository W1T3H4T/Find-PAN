# baseline.py Design

Date: 2026-10-17
Status: Draft for review (not committed)

## 1. Purpose

`bin/baseline.py` records what `find-pan` finds in a set of files as a **baseline**, and later
re-runs `find-pan` the same way to verify that the results have not changed. It is the
regression harness for detection: a changed regex, Luhn rule, masking rule or extractor shows up as a
precise list of rows that went missing or appeared.

**Success criteria**

1. `baseline.py --create NAME <find-pan switches>` runs find-pan and archives the findings and a
   description of how they were produced under `RegressionTests/baseline/NAME/`.
2. `baseline.py --validate NAME` and `baseline.py --validate --all` re-run find-pan exactly as
   recorded and report **which rows differ** (missing or extra, with file, line and offset), not only
   that something differs.
3. A baseline created on Windows validates on Linux, and the reverse, with no differences.
4. Any change to an input file beyond line endings is a failure, reported separately from a change in
   scanner output.

**Non-goals:** a general test framework, remote storage of baselines, comparing two arbitrary runs,
a GUI. Performance is not a goal beyond "the fixtures run in seconds".

## 2. Layout

```
bin/baseline.py                         the tool
RegressionTests/baseline/<name>/
    baseline.csv                        the findings, in canonical order
    baseline.yaml                       how it was created (contains name: <name>)
tests/test_baseline.py                  unit and end-to-end tests
```

The directory name is the baseline name. `baseline.yaml` also contains `name:`; validation fails if the
two disagree. Names may contain letters, digits, `-`, `_` and `.` only (no path separators).

## 3. Command line

```
baseline.py --create NAME [--description TEXT] [--force] [find-pan switches ...]
baseline.py --validate NAME [--strict] [--max-diff N]
baseline.py --validate --all [--strict] [--max-diff N]
```

- `--create` and `--validate` are mutually exclusive and one is required. `--validate` takes an
  optional `NAME`; exactly one of `NAME` or `--all` must be given.
- In `--create`, every argument that `baseline.py` does not define is passed to find-pan
  (`parse_known_args`), for example
  `baseline.py --create plain-text --description "13 plain fixtures" --path RegressionTests --skip-binary`.
  A literal `--` separates the two when needed.
- `baseline.py` owns find-pan's `--csv`, `--log-dir`, `--summary-json`, `--version`, `--verbose` and
  `--debug`; passing any of them to `--create` is an error, not an override.
- `--create` refuses to replace an existing baseline unless `--force` is given.
- `--max-diff N` limits how many differing rows are printed per baseline (default 50; the count is
  always printed).
- `--strict` turns environment skips (section 7) into failures.

**Exit status:** 0 every baseline matches (or was created); 1 at least one baseline differs; 2 usage or
environment error (unknown baseline, malformed YAML, missing input, find-pan could not run).

## 4. What `--create` does

1. Validate the name and refuse an existing directory without `--force`.
2. Resolve every input named by `--path` and `--file` to a path **inside the repository** (anything
   outside is an error: baselines must be reproducible from a checkout) and rewrite it as a
   repository-relative path with `/` separators. Path-valued switches `--rgx-patterns` are rewritten
   the same way.
3. Enumerate the input files (section 5).
4. Run `python bin/find-pan.py <switches> --csv <tmp>.csv --log-dir <tmp> --summary-json <tmp>.json`
   as a subprocess with the interpreter running `baseline.py`, working directory = repository root.
5. Write `baseline.csv` (header plus rows sorted, section 6, LF line endings) and `baseline.yaml`.

### baseline.yaml

```yaml
name: plain-text
description: 13 plain fixtures
created: 2026-10-17T12:00:00Z
find_pan:
  version: 3.0.1
  command:                       # arguments after bin/find-pan.py, repository-relative
    - --path
    - RegressionTests
    - --skip-binary
python: 3.14.5
platform: win32
requires_tools: [unzip, tar]     # extractors needed by archive inputs
inputs:                          # sorted, see section 5
  - path: RegressionTests/VISA.txt
    size: 464
    sha256: <hex>
    eol_normalized: true         # true for text, false for binary/archives
summary:                         # compared on validate
  pans: 349
  tracks: 0
  bad_luhn: 0
  anti_pans: 1
  files_scanned: 13
  archives_expanded: 0
  skipped:                       # sorted [reason, display path] pairs
    - [BINARY, RegressionTests/foo.bin]
```

`created`, `python` and `platform` are informational and never compared.

## 5. Enumerating input files (Windows and Linux must agree)

- Paths are repository-relative, with `/` separators, and compared as exact strings.
- The list is **sorted by the UTF-8 bytes of the path** (code point order), not by `os.walk` order,
  the locale, or case folding.
- `--path DIR` lists every regular file under `DIR`; symbolic links, devices and sockets are not
  listed. Archives are listed as one file each; their members are not enumerated.
- Hashes: **text files** (no NUL byte in the first 8 KiB) are hashed after `\r\n` is replaced by
  `\n`, so a CRLF checkout equals an LF checkout; **binary files and archives** are hashed as they
  are. `eol_normalized` records which rule applied.
- `.gitattributes` already forces LF for text, which keeps the checked-in hashes stable on both
  platforms; the normalization is a second line of defense for working trees that disagree.

## 6. Canonical CSV and comparison

- Rows come from find-pan's `--csv` (`filename, line_number, offset, pattern_name, data_type,
  matched_data`). find-pan writes them in directory-walk order, which differs between operating
  systems, so `baseline.py` **sorts** them by those six fields (numeric fields numerically) before
  storing and before comparing. Rows are compared exactly; duplicates count.
- The diff is a multiset difference: rows only in the baseline are **missing**, rows only in the run
  are **extra**. Each is printed as `file:line:offset  type  pattern  data`, up to `--max-diff`.
- The summary section is compared field by field and the skipped list as a sorted list; each
  difference is printed as `field: baseline X, now Y`.

## 7. What `--validate` does

For one or all baselines (`--all` lists the directories under `RegressionTests/baseline/` that contain
a `baseline.yaml`, sorted by name):

1. Load the YAML; check `name` against the directory; check required tools: if an archive baseline
   lists `requires_tools` that are not installed, the baseline is reported **SKIPPED (environment)**
   with the missing tools and does not affect the exit status (`--strict` makes it a failure).
2. **Inputs:** re-enumerate and hash the input files and compare with the recorded list. Added,
   removed or changed files are printed as **INPUTS CHANGED**: this is a failure, because the baseline
   no longer describes these files. Line-ending-only changes are not changes (section 5).
3. **Run:** execute find-pan with the recorded command (same switches), producing a temporary CSV and
   summary JSON.
4. **Compare** CSV rows and the summary (section 6).
5. Print a one-line verdict per baseline: `PASS`, `FAIL (inputs changed)`, `FAIL (output differs)`,
   `FAIL (inputs changed, output differs)` or `SKIPPED`, then the details, then a final tally.

Input changes and output changes are reported together, so a changed fixture and a changed scanner can
be told apart in one run. The hash tells you *that* an input changed; the row diff tells you *what*
that did to the findings (which lines were lost or gained).

## 8. Required changes to find-pan

`baseline.py` must not scrape log text and cannot compare random temporary paths, so two small,
generally useful additions are part of this work:

1. **`--summary-json PATH`** (new option): writes the run summary as JSON (`pans`, `tracks`, `bad_luhn`,
   `anti_pans`, `files_scanned`, `archives_expanded`, `archives_skipped`, `skipped`: list of
   `[reason, path]`, plus `exit_status`). Timing fields are included but `baseline.py` ignores them.
2. **Stable display paths for extracted members.** A file found inside an archive is currently
   reported with its temporary path (`.../find-pan-ab12cd/inner.txt`), which differs on every run. In
   skip reports and the summary JSON it is shown as `<archive path>!/<member path>` (nested:
   `outer.zip!/inner.tar!/file.txt`), with the archive path as given (repository-relative for
   baselines). The CSV `filename` column is unchanged.

Both are covered by find-pan tests of their own.

## 9. Errors

- Unknown baseline, missing `baseline.yaml`/`baseline.csv`, malformed YAML, or a recorded input that
  no longer exists: a one-line error naming the baseline, exit status 2 for that baseline; `--all`
  carries on with the others and reports status 2 at the end if no baseline failed with status 1.
- find-pan exiting with a status other than 0 or 1, or not producing the CSV or JSON: exit status 2
  with its stderr shown.
- The tool never modifies a baseline during `--validate`, and temporary files are removed afterwards.

## 10. Shipped baselines and tests

**Shipped baselines** (created with this tool, under `RegressionTests/baseline/`):

- `plain-text`: `--file` with the 13 plain `.txt` fixtures (`--path RegressionTests` would also expand the
  three archives that sit next to them).
- `archives`: `--file RegressionTests/ZIP_Test.zip RegressionTests/TAR_Test.tar RegressionTests/7z_Test.7z`
  (requires unzip, tar, 7z).
- `masked`: the same 13 plain fixtures with `--mask`, which pins redaction.

None of them uses `--skip-binary`, which would depend on the machine's libmagic.

**Tests** (`tests/test_baseline.py`, plus find-pan tests for section 8):

- Unit: input enumeration is sorted by bytes, uses `/`, ignores links, and is independent of `os.walk`
  order; CRLF and LF copies of a text file hash equal while a one-byte content change does not;
  archives hash raw; CSV canonical sort (numeric fields); multiset diff; summary diff; name and path
  validation; switch pass-through, rejection of owned switches, and path rewriting.
- End to end on a temporary copy of the fixtures: create then validate passes; editing one input file
  fails with `inputs changed` plus the exact lost row; corrupting one CSV row fails and names it;
  changing a summary count fails; `--validate --all` mixes pass and fail and reports status 1;
  missing baseline gives status 2; `--create` without `--force` on an existing name fails; line-ending
  changes alone pass; a missing tool gives SKIPPED (and fails with `--strict`).
- Cross-platform: the shipped baselines are created on Windows and validated under WSL Linux as part of
  the work, and the result is recorded in the PR.

## 11. Implementation order

1. find-pan: `--summary-json` and stable member display paths, with tests.
2. `baseline.py` core: argument parsing, input enumeration and hashing, YAML, CSV canonicalization and
   diff, with unit tests.
3. `--create` and `--validate` (single and `--all`) with the end-to-end tests.
4. Create the shipped baselines; validate them on Windows and Linux.
5. README section and `bug-fix.md`-style notes for the new tool.
