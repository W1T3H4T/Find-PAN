# Copilot Instructions

## Project Guidelines
- The user expects precise regular expressions that encode the required data format rather than broad digit-only matching.
- Use pytest for configuration-processing tests in this repository.
- The baseline system's associated files belong under RegressionTests, and paths should be defined once rather than duplicated.
- Configuration discovery should fall back to the config directory beside the running Find-PAN installation's bin directory, after environment-variable locations.
- For releases, commit and push the intended changes before creating or moving the release tag; ensure the tag points to the intended main commit.
- When cleaning RegressionTests, retain files containing invalid PAN or invalid TRACK data, as well as baseline configuration files.
- Never bypass plyint errors or warnings; always address them.
- Address plyint recommendations, even if they are not explicitly requested by the user; all others should be raised to the user for confirmation before proceeding.
- The baseline tool must not inspect --path or other find-pan source arguments; it should consume only baseline configuration creation/name and validation options and forward source specifiers to find-pan. --create and --validate accept configuration names without requiring a directory.
- The baseline should create a find-pan CSV and, for validation, rerun find-pan to a different CSV location and report an error when the CSV files differ.
- Baseline validation reporting should show one line per baseline, updating the running status to the final result rather than emitting separate running and result lines.

## Application Design
- Parallel design must run multiple independent Find-PAN applications from a dispatcher; do not make workload division or output handling concurrent and do not add concurrency inside Find-PAN components.

## Concurrency Implementation
- Implement Find-PAN concurrency through a dedicated dispatcher that launches independent Find-PAN processes; do not introduce concurrency into scanner functions.
- Partition whole files by size and merge worker output.