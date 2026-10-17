#!/usr/bin/env -S uv run python
"""Generate synthetic, Luhn-valid PANs from configured PAN regular expressions."""

import argparse
import json
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from lorem_text import lorem

try:
    from re import _parser as regex_parser
except ImportError:  # pragma: no cover
    import sre_parse as regex_parser


DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parents[1] / "config" / "find-pan-regex.json"
MAX_GENERATION_ATTEMPTS = 1_000


@dataclass(frozen=True)
class GeneratedPan:
    """A synthetic PAN generated for one configured regex."""

    pattern_name: str
    regex_index: int
    regex: str
    pan: str


def luhn_check(number: str) -> bool:
    """Return whether a numeric value passes the Luhn check."""
    checksum = 0
    for index, digit in enumerate(reversed(number)):
        value = int(digit)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    return checksum % 10 == 0


def luhn_check_digit(prefix: str) -> str:
    """Return the digit that makes a numeric prefix Luhn-valid."""
    for digit in "0123456789":
        if luhn_check(prefix + digit):
            return digit
    raise ValueError("Unable to calculate a Luhn check digit.")


def generate_from_tokens(tokens: Iterable, rng: random.Random) -> str:
    """Generate a numeric candidate from a parsed Python regular expression."""
    value = []

    for token, data in tokens:
        if token == regex_parser.LITERAL:
            value.append(chr(data))
        elif token == regex_parser.IN:
            choices = []
            for item_token, item_data in data:
                if item_token == regex_parser.LITERAL:
                    choices.append(chr(item_data))
                elif item_token == regex_parser.RANGE:
                    choices.extend(chr(code) for code in range(item_data[0], item_data[1] + 1))
                elif item_token == regex_parser.CATEGORY:
                    choices.extend("0123456789")
            if not choices:
                raise ValueError(f"Unsupported character class: {data}")
            value.append(rng.choice(choices))
        elif token == regex_parser.BRANCH:
            _, branches = data
            value.append(generate_from_tokens(rng.choice(branches), rng))
        elif token == regex_parser.SUBPATTERN:
            value.append(generate_from_tokens(data[-1], rng))
        elif token in (regex_parser.MAX_REPEAT, regex_parser.MIN_REPEAT):
            minimum, maximum, repeated_tokens = data
            maximum = min(maximum, minimum + 8)
            for _ in range(rng.randint(minimum, maximum)):
                value.append(generate_from_tokens(repeated_tokens, rng))
        elif token in (regex_parser.ASSERT, regex_parser.ASSERT_NOT, regex_parser.AT):
            continue
        else:
            raise ValueError(f"Unsupported regex token: {token}")

    return "".join(value)


def generate_matching_luhn_pan(regex: str, rng: random.Random) -> str:
    """Generate one numeric, Luhn-valid PAN that fully matches *regex*."""
    compiled_regex = re.compile(regex)
    parsed_regex = regex_parser.parse(regex, 0)

    for _ in range(MAX_GENERATION_ATTEMPTS):
        candidate = generate_from_tokens(parsed_regex, rng)
        if not candidate.isdecimal() or len(candidate) < 2:
            continue

        pan = candidate[:-1] + luhn_check_digit(candidate[:-1])
        if compiled_regex.fullmatch(pan) and luhn_check(pan):
            return pan

    raise ValueError(f"Could not generate a Luhn-valid PAN for regex: {regex}")


def load_pan_patterns(patterns_path: Path) -> dict[str, dict]:
    """Load and validate the PAN-pattern configuration."""
    with patterns_path.open(encoding="utf-8") as patterns_file:
        configuration = json.load(patterns_file)

    pan_patterns = configuration.get("PAN Pattern")
    if not isinstance(pan_patterns, dict) or not pan_patterns:
        raise ValueError("The configuration does not contain PAN Pattern entries.")
    return pan_patterns


def resolve_pattern_name(patterns: dict[str, dict], requested_name: str) -> str:
    """Resolve a requested pattern name, accepting case-insensitive input."""
    if requested_name in patterns:
        return requested_name

    matches = [name for name in patterns if name.casefold() == requested_name.casefold()]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(f"Unknown PAN pattern: {requested_name}")


def select_pattern_interactively(patterns: dict[str, dict]) -> str:
    """Prompt the user to choose a configured PAN pattern."""
    pattern_names = list(patterns)
    print("Available PAN patterns:")
    for index, name in enumerate(pattern_names, 1):
        print(f"  {index}. {name}")

    selection = input("Select a PAN pattern by number or name: ").strip()
    if selection.isdigit() and 1 <= int(selection) <= len(pattern_names):
        return pattern_names[int(selection) - 1]
    return resolve_pattern_name(patterns, selection)


def generate_pans(
    pattern_name: str, pattern_data: dict, count: int, rng: random.Random
) -> list[GeneratedPan]:
    """Generate *count* Luhn-valid PANs for every regex in a selected PAN pattern."""
    regexes = pattern_data.get("regex")
    if not isinstance(regexes, list) or not regexes:
        raise ValueError(f"PAN pattern '{pattern_name}' does not define any regexes.")

    generated_pans = []
    for index, regex in enumerate(regexes, 1):
        if not isinstance(regex, str):
            raise ValueError(f"PAN pattern '{pattern_name}' contains a non-string regex.")
        for _ in range(count):
            generated_pans.append(
                GeneratedPan(pattern_name, index, regex, generate_matching_luhn_pan(regex, rng))
            )
    return generated_pans


FILLER_SEPARATORS = (" ", " ", " ", ", ", ": ", " - ", "; ", " | ", "=")
DEFAULT_MAX_HITS = 3
TRACK_NAMES = ("DOE/JANE", "SMITH/JOHN", "PUBLIC/J Q", "TEST/CARDHOLDER", "ROE/RICHARD")


def load_optional_section(patterns_path: Path, section: str) -> dict[str, dict]:
    """Load a pattern section from the configuration; empty when absent."""
    with patterns_path.open(encoding="utf-8") as patterns_file:
        section_data = json.load(patterns_file).get(section)
    return section_data if isinstance(section_data, dict) else {}


def collect_regexes(section: dict[str, dict]) -> list[re.Pattern]:
    """Compile every regex of a configuration section."""
    return [
        re.compile(regex)
        for entry in section.values()
        for regex in entry.get("regex", [])
        if isinstance(regex, str)
    ]


def generate_clean_pan(
    pan_patterns: dict[str, dict], anti_pans: list[re.Pattern], rng: random.Random
) -> str:
    """Generate a Luhn-valid PAN that does not trip any anti-PAN pattern."""
    for _ in range(MAX_GENERATION_ATTEMPTS):
        pattern_data = pan_patterns[rng.choice(list(pan_patterns))]
        pan = generate_matching_luhn_pan(rng.choice(pattern_data["regex"]), rng)
        if not any(anti.search(pan) for anti in anti_pans):
            return pan
    raise ValueError("Could not generate a PAN that avoids the anti-PAN patterns.")


def build_track(pan: str, track_number: int, rng: random.Random) -> str:
    """Build Track 1 (%B...) or Track 2 (;...) data around *pan*."""
    expiry = f"{rng.randint(27, 39):02d}{rng.randint(1, 12):02d}"
    service_code = rng.choice(("101", "201", "220", "601"))
    discretionary = "".join(rng.choice("0123456789") for _ in range(rng.randint(4, 12)))
    if track_number == 1:
        return f"%B{pan}^{rng.choice(TRACK_NAMES)}^{expiry}{service_code}{discretionary}?"
    return f";{pan}={expiry}{service_code}{discretionary}?"


def generate_hit(
    pan_patterns: dict[str, dict],
    track_regexes: list[re.Pattern],
    anti_pans: list[re.Pattern],
    rng: random.Random,
) -> str:
    """Generate one embedded PAN or (when track patterns exist) track record."""
    pan = generate_clean_pan(pan_patterns, anti_pans, rng)
    if not track_regexes or rng.random() < 0.6:
        return pan
    for _ in range(MAX_GENERATION_ATTEMPTS):
        track = build_track(pan, rng.choice((1, 2)), rng)
        if any(regex.fullmatch(track) for regex in track_regexes):
            return track
    return pan


def filler(rng: random.Random) -> str:
    """Return a short run of lorem-ipsum text (digit-free, drawn from the seeded rng)."""
    words = [rng.choice(lorem.WORDS) for _ in range(rng.randint(2, 8))]
    if rng.random() < 0.3:
        words[0] = words[0].capitalize()
    return " ".join(words) + rng.choice(("", "", ".", ",", "?"))


def generate_random_text(
    pan_patterns: dict[str, dict],
    track_regexes: list[re.Pattern],
    anti_pans: list[re.Pattern],
    lines: int,
    max_hits: int,
    rng: random.Random,
) -> list[str]:
    """Generate *lines* lines of random text with 1..*max_hits* PAN/track hits each.

    Filler is lorem-ipsum text (lorem-text package) and contains no digits, so
    it cannot form false PAN or anti-PAN matches next to an embedded hit.
    """
    output = []
    for _ in range(lines):
        parts = [filler(rng)]
        for _ in range(rng.randint(1, max_hits)):
            parts.append(rng.choice(FILLER_SEPARATORS))
            parts.append(generate_hit(pan_patterns, track_regexes, anti_pans, rng))
            parts.append(rng.choice(FILLER_SEPARATORS))
            parts.append(filler(rng))
        output.append("".join(parts))
    return output


def default_output_path(pattern_name: str) -> Path:
    """Return the default output file path for *pattern_name*.

    Spaces in the pattern name are replaced with hyphens so the resulting
    filename is easy to use on the command line.
    """
    safe_name = pattern_name.replace(" ", "-")
    return Path.cwd() / f"{safe_name}.txt"


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate synthetic, Luhn-valid PANs from a selected PAN pattern.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--patterns",
        type=Path,
        default=DEFAULT_PATTERNS_PATH,
        help="Path to the JSON file containing PAN patterns.",
    )
    parser.add_argument(
        "--pan-pattern",
        help="PAN pattern name to generate. Prompts for a selection when omitted in a terminal.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate PANs for every configured PAN pattern.",
    )
    parser.add_argument(
        "--list-pan-patterns",
        action="store_true",
        help="List available PAN pattern names and exit.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Optional random seed for reproducible synthetic values.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of PANs to generate for each regex in the selected pattern.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file path. Defaults to a file named after the pattern.",
    )
    parser.add_argument(
        "--random-text",
        type=int,
        metavar="LINES",
        help="Generate LINES lines of random text with embedded PAN and track data, "
        "several hits per line, instead of one PAN per line. Uses --pan-pattern "
        "when given, otherwise every PAN pattern.",
    )
    parser.add_argument(
        "--max-hits",
        type=int,
        default=DEFAULT_MAX_HITS,
        help="With --random-text, the maximum PAN/track hits per line (each line gets 1 to this many).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include regex patterns in the output alongside each generated PAN.",
    )
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    """Run the PAN generator application."""
    args = parse_arguments(arguments)

    if args.all and args.pan_pattern:
        print("Error: --all cannot be used with --pan-pattern.", file=sys.stderr)
        return 2

    if args.random_text is not None and (args.random_text < 1 or args.max_hits < 1):
        print("Error: --random-text and --max-hits must be at least 1.", file=sys.stderr)
        return 2

    try:
        patterns = load_pan_patterns(args.patterns)
        if args.list_pan_patterns:
            print("\n".join(patterns))
            return 0

        if args.random_text is not None:
            if args.pan_pattern:
                chosen = resolve_pattern_name(patterns, args.pan_pattern)
                selected = {chosen: patterns[chosen]}
            else:
                selected = patterns
            text_lines = generate_random_text(
                selected,
                collect_regexes(load_optional_section(args.patterns, "TRACK Pattern")),
                collect_regexes(load_optional_section(args.patterns, "Anti-PAN Pattern")),
                args.random_text,
                args.max_hits,
                random.Random(args.seed),
            )
            output_path = args.output or Path.cwd() / "Random-Text.txt"
            output_path.write_text("\n".join(text_lines) + "\n", encoding="utf-8")
            print(f"Wrote {len(text_lines)} line(s) of random text to {output_path}", file=sys.stderr)
            return 0

        if args.all:
            pattern_names = list(patterns)
        elif args.pan_pattern:
            pattern_name = resolve_pattern_name(patterns, args.pan_pattern)
            pattern_names = [pattern_name]
        elif sys.stdin.isatty():
            pattern_names = [select_pattern_interactively(patterns)]
        else:
            raise ValueError("Specify --pan-pattern or --all when standard input is not interactive.")

        rng = random.Random(args.seed)
        generated_by_pattern: dict[str, list[GeneratedPan]] = {}
        for pattern_name in pattern_names:
            generated_by_pattern[pattern_name] = generate_pans(
                pattern_name, patterns[pattern_name], args.count, rng
            )
    except (OSError, ValueError, json.JSONDecodeError, re.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    def _format_pan_lines(generated_pan: GeneratedPan) -> list[str]:
        if args.verbose:
            return [
                f"Regex {generated_pan.regex_index}: {generated_pan.regex}",
                f"PAN: {generated_pan.pan}",
            ]
        return [generated_pan.pan]

    if args.all and not args.output:
        total_written = 0
        for pattern_name, generated_pans in generated_by_pattern.items():
            output_path = default_output_path(pattern_name)
            output_lines = [f"Synthetic PANs for {pattern_name}:"]
            for generated_pan in generated_pans:
                output_lines.extend(_format_pan_lines(generated_pan))

            output_text = "\n".join(output_lines) + "\n"
            output_path.write_text(output_text, encoding="utf-8")
            total_written += len(generated_pans)
        print(f"Wrote {total_written} PAN(s) across {len(generated_by_pattern)} pattern file(s).", file=sys.stderr)
        return 0

    # Single output destination: either --output or the default for the one selected pattern.
    output_path = args.output or default_output_path(pattern_names[0])
    output_lines = []
    for pattern_name, generated_pans in generated_by_pattern.items():
        output_lines.append(f"Synthetic PANs for {pattern_name}:")
        for generated_pan in generated_pans:
            output_lines.extend(_format_pan_lines(generated_pan))

    output_text = "\n".join(output_lines) + "\n"
    output_path.write_text(output_text, encoding="utf-8")
    print(output_text, end="")
    print(f"Wrote {sum(len(pans) for pans in generated_by_pattern.values())} PAN(s) to {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
