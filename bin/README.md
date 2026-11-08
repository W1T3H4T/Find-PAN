# Find-PAN Supporting Scripts

These scripts support Find-PAN 3.7.0. Run the examples from the repository root after following the [installation instructions](../README.md#installation). Python scripts use the project-root `.venv`; `uv run python` is shown below. See each script's `--help` for its complete options. Generated fixtures may contain synthetic PANs and track data; scanner logs and CSVs may contain sensitive data unless masking is enabled.

## Launch and setup

| Script | Purpose |
| --- | --- |
| `find-pan.py` | Launch the scanner; see the [main usage guide](../README.md#usage). |
| `find-pan.sh`, `find-pan.ps1` | Run the scanner using `FIND_PAN_HOME`'s `.venv` and launcher (or this checkout if unset), forwarding arguments and exit status. Relative paths remain relative to the caller's working directory. See [quick start](../README.md#quick-start). |
| `setup-env.sh`, `setup-env.ps1` | Set up the project-root `.venv` and development dependencies. The `--recreate` / `-Recreate` option removes and recreates `.venv`. See [installation](../README.md#installation). |

```console
uv run python bin/find-pan.py --version
uv run python bin/find-pan.py --file RegressionTests/VISA.txt --mask
uv run python bin/find-pan.py --file evidence.zip --raw-file "*.dmp" --mask
```

## Regression baselines and tests

`baseline.py` creates configurations and CSVs under `RegressionTests/baseline`, lists them, and validates scanner output against a saved CSV. Source options after `--create` are passed to find-pan. Use `--exclude-dir baseline` when scanning the containing regression tree. `--force` replaces an existing baseline and its CSV. See [regression baselines](../README.md#regression-baselines) for details.

```console
uv run python bin/baseline.py --list
uv run python bin/baseline.py --create visa --file RegressionTests/VISA.txt
uv run python bin/baseline.py --validate visa
uv run python bin/baseline.py --validate --all
uv run python bin/run-pytest-regression.py --workers 4
```

`run-pytest-regression.py` runs pytest from the repository root. Consult its help for additional options.

## Synthetic data generators

| Script | Purpose | Output and precautions |
| --- | --- | --- |
| `generate-pan.py` | Generate synthetic Luhn-valid PANs or random text with planted findings. | Writes a file in the current directory or the `--output` path and may overwrite it. `--seed` makes output reproducible. |
| `generate-invalid-pan.py` | Generate pattern-conformant PANs that fail the Luhn check. | Writes values to standard output; `--count` sets the number of lines. |
| `generate-test-data.py` | Build a reproducible tree of synthetic text, binary files and archives with known answers. | `--out` must be absent or empty; answers are written alongside it in `<out>.expected` unless `--answers` is specified. |

```console
uv run python bin/generate-pan.py --list-pan-patterns
uv run python bin/generate-pan.py --random-text 100 --max-hits 4 --seed 42 --output sample.txt
uv run python bin/generate-invalid-pan.py --count 5
uv run python bin/generate-test-data.py --out data --files 50 --seed 1
```

See the main README's [synthetic data](../README.md#generate-synthetic-test-data) and [many test files](../README.md#generate-many-test-files) sections for details.

## Configuration and maintenance

| Script | Purpose | Precautions |
| --- | --- | --- |
| `check-json-regex.py` | Inspect PAN regex lengths from the discovered configuration. | Uses the configured regex JSON; invoke without arguments. |
| `obfuscate-pan.py` | Print obfuscated PAN matches from a file or directory using `--json` patterns. | Reports to standard output; it does not rewrite the input. |
| `purge-log-files.py` | Remove old files under `--path`, filtered by `--age` and optional `--prefix`. | Deletes files. Uses an available secure-deletion utility; otherwise warns and deletes normally. Review the path, age and prefix first. |
| `update_version.py` | Show or update the project version. | Update options rewrite `pyproject.toml` and `src/find_pan/version.py`; also synchronize the project entry in `uv.lock` when releasing. |

```console
uv run python bin/check-json-regex.py
uv run python bin/obfuscate-pan.py --file RegressionTests/VISA.txt --json config/find-pan-regex.json
uv run python bin/update_version.py --show
```

## Shell helpers

- `grep-find-pan.sh` and `grep-find-track.sh` perform basic grep-based PAN or track searches. They accept `--path` and optionally `--rgx-prefix`. Each removes its existing log file in the current directory before starting; they are not substitutes for the full scanner.
- `rename-files.sh` copies files in the current directory with `-1` added before their extensions. It can copy earlier outputs on repeated runs and overwrite existing destinations; run only in a suitable working directory.
- `logger.sh` supplies logging functions for shell scripts and is intended to be sourced, not run as a standalone tool.
