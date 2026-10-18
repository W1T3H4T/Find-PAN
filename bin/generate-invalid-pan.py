#!/usr/bin/env python3
"""Generate test values that fit a configured PAN pattern but fail the Luhn checksum.

Examples:
    python generate-invalid-pan.py --count 5000 > RegressionTests/Invalid-PAN.txt

Each value is built from a pattern in the "PAN Pattern" section of find-pan-regex.json (rotating through the
patterns), so it has a real issuer range and length, and then has its check digit changed so it fails Luhn.
Values that would trip an anti-PAN pattern are discarded.  Output rotates between ungrouped, space-separated
and hyphen-separated forms; grouped output uses blocks of four digits with a shorter final block.  Every
line fails Luhn after separators are removed, and find-pan reports one Luhn check failure per line.
"""

import argparse
import importlib.util
import random
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from find_pan.config import compile_regex_patterns, load_json_data  # noqa: E402
from find_pan.detectors import scan_line  # noqa: E402
from find_pan.models import MatchKind  # noqa: E402

DEFAULT_PATTERNS = ROOT / "config" / "find-pan-regex.json"
MAX_ATTEMPTS = 1000


def load_generator():
    """Import generate-pan.py (its name is not a valid module name) for its pattern-driven generation."""
    spec = importlib.util.spec_from_file_location("generate_pan", Path(__file__).with_name("generate-pan.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def nonnegative_int(value: str) -> int:
    """Accept a count of zero or more; reject invalid CLI input."""
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from error
    if count < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return count


def corrupt(pan: str, rng: random.Random) -> str:
    """Replace the check digit with a wrong one; each of the nine other digits fails Luhn."""
    return pan[:-1] + str((int(pan[-1]) + rng.randrange(1, 10)) % 10)


def confirmed(text: str, patterns: list) -> bool:
    """Whether find-pan reports *text*, alone on a line or with text around it, as exactly one Luhn failure.

    This asks the scanner itself: a Luhn failure can contain a shorter number that another pattern accepts as
    a PAN, and some anti-PAN patterns depend on how much of the line follows the number.
    """
    lines = [text] + [f"a {text} " + "x" * extra for extra in (0, 8, 16, 24)]
    return all([m.kind for m in scan_line("f", 1, line, patterns)] == [MatchKind.BAD_LUHN] for line in lines)


def generate(count: int, patterns_path: Path = DEFAULT_PATTERNS, rng: random.Random | None = None) -> Iterator[str]:
    """Yield exactly count values, each fitting a PAN pattern and having an intentionally wrong checksum."""
    if count < 0:
        raise ValueError("count must be nonnegative")
    rng = rng or random.SystemRandom()
    generator = load_generator()
    pan_patterns = generator.load_pan_patterns(patterns_path)
    patterns = compile_regex_patterns(load_json_data(str(patterns_path)))
    names = list(pan_patterns)
    separators = ("", " ", "-")
    for index in range(count):
        name = names[index % len(names)]
        separator = separators[index % len(separators)]
        for _ in range(MAX_ATTEMPTS):
            valid = generator.generate_matching_luhn_pan(rng.choice(pan_patterns[name]["regex"]), rng)
            digits = corrupt(valid, rng)
            text = separator.join(digits[start:start + 4] for start in range(0, len(digits), 4))
            if confirmed(text, patterns):
                break
        else:
            raise ValueError(f"Could not generate an invalid PAN for pattern: {name}")
        yield text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count", type=nonnegative_int, default=100, metavar="N",
        help="number of output lines (default: 100); zero produces no output",
    )
    parser.add_argument(
        "--patterns", type=Path, default=DEFAULT_PATTERNS, metavar="FILE",
        help="regex configuration to take PAN patterns from (default: the shipped find-pan-regex.json)",
    )
    args = parser.parse_args()
    try:
        for value in generate(args.count, args.patterns):
            print(value)
    except BrokenPipeError:
        # Allow consumers to stop reading before the requested count is reached.
        pass


if __name__ == "__main__":
    main()

