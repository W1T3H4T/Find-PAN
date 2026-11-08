# Find-PAN regular expressions

This guide describes the pattern configuration used to recognize PANs and track data, how the scanner applies it, 
and how to add or change patterns. The configured expressions define what Find-PAN can detect: a Luhn-valid number 
is not necessarily a finding, and a finding does not establish that an account exists or is active.

## Location and selection

The shipped configuration is [`config/find-pan-regex.json`](../config/find-pan-regex.json). Select a different JSON 
file with `--rgx-patterns FILE`; the file is used as the complete pattern configuration, not merged with the shipped 
file. Otherwise, Find-PAN selects the first `find-pan-regex.json` found in:

1. `$FIND_PAN_HOME/config` (if `FIND_PAN_HOME` is set)
2. `$XDG_CONFIG_HOME/find-pan/config` (if `XDG_CONFIG_HOME` is set)
3. `<installation>/config`, beside the running launcher's `bin` directory

A file under `FIND_PAN_HOME` takes precedence over the XDG file; if neither exists, the installation's configuration is used. If no file is found, discovery fails. Use `--rgx-patterns config/find-pan-regex.json` 
when testing the shipped file explicitly from the repository root. Files and directories inside archives are scanned with 
the same selected patterns; parallel workers receive the same configuration option.

## JSON structure

The configuration is a JSON object with these exact category names. Each category contains named entries; each entry 
has a `regex` array of Python regular-expression strings. The entry name is included in findings and identifies some 
special behavior.

| Category | Purpose |
| --- | --- |
| `Delimited PAN Pattern` | Locates grouped-digit candidates to normalize; it does not itself produce a PAN finding. |
| `Anti-PAN Pattern` | Identifies spans to exclude from PAN and track matching. |
| `TRACK Pattern` | Matches whole track records, including framing and separators. |
| `PAN Pattern` | Matches contiguous PAN digits after normalization. |

For example, the following fragment describes a hypothetical 16-digit range beginning with `9999`; it is an illustration, not a claim about a real issuer:

```json
{
  "PAN Pattern": {
	"Example range": {
	  "regex": ["(?<![0-9])9999[0-9]{12}(?![0-9])"],
	  "length": "16"
	}
  }
}
```

The `length` value documents the possible PAN lengths. The scanner compiles the `regex` strings and does not use `length` to enforce them; the expressions themselves must enforce the intended format. Keep the metadata accurate, including ranges or multiple lengths when appropriate. `Notes` in the shipped JSON is explanatory and is not a pattern category. Avoid placing regex-bearing entries in other categories: the scanner does not recognize them.

JSON escaping applies before Python sees a regex. For example, write `\\1` in a JSON string to represent the regex back-reference `\1`. Use Python's `re` syntax, not shell globs or PCRE-only constructs. Invalid JSON or an expression that fails compilation causes an error rather than a scan with that expression silently ignored.

## How matching works

For each decoded line or raw-scan text view, Find-PAN performs these steps:

1. **Normalize grouped candidates.** `Delimited PAN Pattern` expressions find digit groups separated by spaces or hyphens. Overlapping candidates are resolved by leftmost start, then longest match. Spaces and hyphens in selected candidates are removed; positions remain mapped to the original input.
2. **Apply anti-PANs.** Anti-PAN expressions run on the normalized text first. Each accepted anti-PAN excludes only its own span. An entry named exactly `Timestamp` additionally requires a real `YYYYMMDDHHMMSS` calendar timestamp with a year from 1900 through the current year.
3. **Find PANs and tracks.** PAN expressions run on normalized text and track expressions on the original text. They are evaluated in configuration order, including the order of regexes within an entry. Candidates overlapping an anti-PAN or a previously accepted finding are skipped. Thus, earlier accepted patterns decide the reported name for overlapping ranges; the shipped configuration places track patterns before PAN patterns.
4. **Validate and report.** Find-PAN extracts PAN digits from the match, including the PAN part of a track record, and applies the Luhn checksum. A Luhn-valid candidate is reported; an invalid candidate is counted as a Luhn failure, not a finding. A failed candidate does not block a later valid overlapping candidate, and overlapping failed candidates are counted once. Findings and offsets refer to the original input, not the compacted text.

Multiple non-overlapping findings on a line are possible. `--pan-list` and `--track-list` filter findings after detection; they do not supply additional patterns. Track-list entries must fully match a configured track expression. Raw scans use the same detection logic on decoded byte views; see [raw scans](../README.md#scanning-memory-dumps-and-other-non-text-files).

### `--rgx-prefix`

With `--rgx-prefix`, Find-PAN prepends the character class `[ '\"{]` to **PAN Pattern** expressions only. It requires and consumes one preceding space, single quote, double quote, or opening brace. Consequently, a PAN at the beginning of a line or preceded by a different character may no longer match, and the consumed character is part of the match span. TRACK, anti-PAN, and delimited patterns are not prefixed. This option is separate from numeric boundaries in the expressions and should be tested explicitly when used.

## Constructing new expressions

1. **Define the format first.** Determine the authoritative issuer or data format, allowed prefixes or ranges, exact digit counts, separators and framing. Encode those constraints in the expression rather than using a broad digit-only pattern. Avoid guessing an issuer's ranges or assuming that a Luhn-valid number identifies an issuer.
2. **Use precise digit boundaries for PANs.** `(?<![0-9])` before and `(?![0-9])` after the digits prevent a substring of a longer digit sequence from matching. Use `[0-9]` when ASCII digits are intended. Boundaries do not consume surrounding characters; they work differently from `--rgx-prefix`.
3. **Specify lengths and alternatives explicitly.** For example, `(?<![0-9])9999[0-9]{12}(?![0-9])` allows exactly 16 digits with the illustrative prefix. If prefixes require different remaining lengths, use separate alternatives or separate expressions; verify the total digit count of each branch. Update `length` to describe the actual supported lengths. Existing entries may legitimately describe multiple lengths; do not assume the metadata constrains the regex.
4. **Consider overlapping categories and ordering.** Review other issuer ranges, TRACK expressions and anti-PANs. Put a more specific pattern before a broader overlapping one when it should determine the finding name; test both order and exclusion effects. An overly broad anti-PAN can hide genuine matches.
5. **For grouped PANs, describe the grouping rather than the issuer.** A pattern such as `(?<![0-9])[0-9]{4}([ -])[0-9]{4}\\1[0-9]{4}\\1[0-9]{4}(?![0-9])` in JSON captures the first separator and requires the same separator in subsequent positions. The normalizer removes spaces and hyphens only; after normalization, PAN and anti-PAN patterns still determine the result. Test mixed separators, overlaps and malformed groupings.
6. **For tracks, match the whole record.** Preserve the delimiters needed to extract the PAN: `%B` or `%M`, followed by PAN digits and `^` for Track 1; `;`, PAN digits and `=` for Track 2. Include required record framing and fields in the regex. Track patterns operate on original text and are also used to validate complete `--track-list` entries.
7. **Check generator compatibility separately.** The shipped JSON notes describe a simple `(prefix)[0-9]{len}` convention, but current shipped patterns also contain boundaries, alternatives and multiple lengths. The scanner supports Python `re` independently of the synthetic generator. [`bin/generate-pan.py`](../bin/generate-pan.py) supports a subset of parsed regex constructs and verifies generated values with `fullmatch`; test generation for any new expression rather than assuming every valid Python regex is supported.

## Test and review

Use synthetic data rather than real account or track data in tests and examples. Include positive and negative examples for every prefix/range endpoint and permitted length; nearby disallowed prefixes and lengths; adjacent digits and punctuation; Luhn-valid and invalid values; overlapping patterns; and anti-PAN false positives. For grouped PANs, exercise both spaces and hyphens, inconsistent separators, offsets and normalization. For tracks, test full records, incomplete records, embedded PANs and track-list validation. Where relevant, include raw encodings and extracted archive members.

From the repository root, with the project environment set up:

```console
uv run python -m pytest tests/test_config.py tests/test_detectors.py tests/test_delimited.py tests/test_rawscan.py tests/test_raw_cli.py
uv run python bin/generate-pan.py --patterns config/find-pan-regex.json --pan-pattern "Example range" --seed 1 --output synthetic.txt
uv run python bin/find-pan.py --rgx-patterns config/find-pan-regex.json --file synthetic.txt --mask
```

The generator example requires that the illustrative entry has first been added to the selected configuration. Check both the generated value and scanner output, and test with and without `--rgx-prefix` if it is relevant. The generator is a sample producer, not an exhaustive coverage proof. Run the existing regression baselines when changes affect shipped detection behavior, review any differences, and update expected results only when the change is intentional. See [regression baselines](../README.md#regression-baselines) and the [main detection guide](../README.md#detection-behavior).
