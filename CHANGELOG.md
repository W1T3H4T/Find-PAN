# Changelog

Release history is reconstructed from the [GitHub release for v3.5.3](https://github.com/W1T3H4T/Find-PAN/releases/tag/v3.5.3), the repository's published tags, and version-related commits. Versions without published tags are historical version milestones, not necessarily GitHub releases. Dates reflect the relevant commit or published release date; this is a concise reconstruction rather than an exhaustive history.

## 3.6.1 — documentation update

- Add a supporting-scripts guide and a reconstructed changelog.
- Show the current version and documentation links in the main README.

## 3.6.0 — 2026-11-07

- Compare saved and newly generated find-pan CSVs for baseline validation.
- Add baseline discovery, single-line validation progress, timing and an interactive spinner.
- Add case-sensitive directory-name exclusion patterns for recursive scans.
- Move baseline artifacts under `RegressionTests` and improve publication and collision safeguards.
- Update environment setup, packaging, scanner regressions and lint checks.

## 3.5.3 — 2026-10-18

- Limit nested archive expansion and isolate per-file scan failures.
- Improve scanning of lines with many matches and limit reported long-line context.
- Mask PANs written with varied grouping and prevent CSV spreadsheet-formula injection.
- Prevent extraction cleanup from following links outside the extraction directory.

## 3.5.2 — 2026-10-18 (version milestone)

- Add `--min-size` to the synthetic test-data generator.
- Report the regex configuration actually used and clarify its default in help.

## 3.5.1 — 2026-10-18 (version milestone)

- Make synthetic data generators deterministic and exact when seeded.
- Add shell and PowerShell find-pan launchers.
- Add a generator for large test trees with known answers.
- Normalize delimited PANs and use expected PAN and track lists as report filters.

## 3.3.0 — 2026-10-18 (version milestone)

- Add raw scanning and expected PAN and track value lists.
- Probe libmagic in a child process before importing python-magic.

## 3.2.0 — 2026-10-17 (version milestone)

- Improve verbose output, PAN prefix matching and baseline reports.
- Fall back to 7-Zip for zip extraction when appropriate.

## 3.1.2 — 2026-10-17 (version milestone)

- Configure archive extractors per operating system with ordered candidates.
- Fix GNU tar extraction and read-only member cleanup on Windows.

## 3.1.1 — 2026-10-17 (version milestone)

- Add and test per-fixture regression baselines.
- Replace environment-dependent skips with tests and remove stale references.

## 3.1.0 — 2026-10-17 (version milestone)

- Add baseline creation and validation with shipped regression baselines.
- Add JSON scan summaries and stable archive-member display paths.

## 3.0.1 — 2026-10-17 (version milestone)

- Bound extraction-watchdog overshoot on fast filesystems.
- Harden archive extraction with size, file-count, time and disk limits.

## 3.0.0 — 2026-10-17 (version milestone)

- Restructure the scanner into the `find_pan` package.
- Detect and expand supported archives by content and replace the old tar-specific options with `--file`.
- Add CSV reporting, masking support and synthetic PAN generation.

## 2.1.0 release candidate — 2024-09-16

- Record the 2.1.0 release candidate in repository history.

## 1.5.0 — 2024-09-15 (version milestone)

- Update the project to version 1.5.0 and move supporting scripts into `bin`.
