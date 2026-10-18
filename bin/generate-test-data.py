#!/usr/bin/env -S uv run python
"""Generate a directory tree of many small test files holding known PAN and track data.

Examples:
    python generate-test-data.py --out data --files 100000 --seed 1
    python generate-test-data.py --out data --files 5000 --archives 5 --binary 5 \\
        --mix clean=40,pan=30,delimited=10,track=10,bad-luhn=5,anti-pan=5

Files are spread over nested directories and vary in name, extension (.txt .log .csv .json .xml or none) and
size.  Each is lorem-ipsum text with zero or more planted hits, built from the PAN, TRACK and Anti-PAN patterns
of find-pan-regex.json (through generate-pan.py and generate-invalid-pan.py):

    pan        a Luhn-valid PAN                   find-pan reports a PAN
    delimited  a Luhn-valid PAN as 4556-7375-...  find-pan reports a PAN
    track      Track 1 or Track 2 data            find-pan reports a TRACK
    bad-luhn   a brand-conformant Luhn failure    find-pan counts a Luhn check failure
    anti-pan   a timestamp or sequential number   find-pan counts an anti-PAN

With --binary some files are random binary noise with no hits; with --archives some files are collected into
.zip, .tar and .gz archives (some nested) whose members hold the hits.

The answers are written next to the tree, in DIR.expected (or --answers DIR), so a scan of DIR sees only the
generated files:
    manifest.json   every file with its planted counts
    expected.json   the totals find-pan should report: pans, tracks, bad_luhn, anti_pans
    pans.txt        planted PANs, usable as --pan-list
    tracks.txt      planted tracks, usable as --track-list
"""

import argparse
import gzip
import importlib.util
import io
import json
import math
import random
import re
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(BIN.parent / "src"))

from find_pan.config import compile_regex_patterns, load_json_data  # noqa: E402
from find_pan.detectors import scan_line  # noqa: E402
from find_pan.models import MatchKind  # noqa: E402

DEFAULT_PATTERNS = BIN.parent / "config" / "find-pan-regex.json"
KINDS = ("clean", "pan", "delimited", "track", "bad-luhn", "anti-pan")
DEFAULT_MIX = "clean=40,pan=30,delimited=10,track=10,bad-luhn=5,anti-pan=5"
EXTENSIONS = (".txt", ".txt", ".log", ".log", ".csv", ".json", ".xml", "")
SEPARATORS = (" ", " ", " ", ", ", ": ", " - ", "; ", " | ", "=")
AVERAGE_LINE = 70


def load(name: str):
    """Import a sibling script whose file name is not a valid module name."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), BIN / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class Counts:
    pans: int = 0
    tracks: int = 0
    bad_luhn: int = 0
    anti_pans: int = 0

    def add(self, other: "Counts") -> None:
        self.pans += other.pans
        self.tracks += other.tracks
        self.bad_luhn += other.bad_luhn
        self.anti_pans += other.anti_pans

    def as_dict(self) -> dict:
        return {"pans": self.pans, "tracks": self.tracks, "bad_luhn": self.bad_luhn, "anti_pans": self.anti_pans}


@dataclass
class Made:
    """One generated file: name, content and what it holds."""

    name: str
    data: bytes
    counts: Counts = field(default_factory=Counts)
    kind: str = "text"


def parse_mix(text: str) -> dict[str, float]:
    mix = {}
    for item in text.split(","):
        name, _, weight = item.partition("=")
        name = name.strip()
        if name not in KINDS:
            raise ValueError(f"unknown mix kind {name!r}; expected one of {', '.join(KINDS)}")
        try:
            mix[name] = float(weight)
        except ValueError as error:
            raise ValueError(f"bad weight for {name!r}: {weight!r}") from error
        if mix[name] < 0:
            raise ValueError(f"weight for {name!r} must not be negative")
    if sum(mix.values()) <= 0:
        raise ValueError("the mix needs at least one positive weight")
    return mix


def group(digits: str) -> list[str]:
    """Split *digits* into the group sizes the delimited PAN patterns recognise."""
    if len(digits) == 15 and digits[:2] in ("34", "37"):
        sizes = (4, 6, 5)
    elif len(digits) == 14:
        sizes = (4, 6, 4)
    else:
        sizes = (4,) * (len(digits) // 4) + ((len(digits) % 4,) if len(digits) % 4 else ())
    parts, start = [], 0
    for size in sizes:
        parts.append(digits[start:start + size])
        start += size
    return parts


class Maker:
    """Builds hits and files from the configured patterns."""

    def __init__(self, patterns_path: Path, mix: dict[str, float], rng: random.Random, max_hits: int,
                 max_size: int, crlf: float) -> None:
        self.pan_tool = load("generate-pan")
        self.invalid_tool = load("generate-invalid-pan")
        self.rng = rng
        self.pan_patterns = self.pan_tool.load_pan_patterns(patterns_path)
        self.patterns = compile_regex_patterns(load_json_data(str(patterns_path)))
        self.hit_kinds = [kind for kind in KINDS if kind != "clean" and mix.get(kind, 0) > 0]
        self.hit_weights = [mix[kind] for kind in self.hit_kinds]
        self.clean_share = mix.get("clean", 0) / sum(mix.values())
        self.max_hits, self.max_size, self.crlf = max_hits, max_size, crlf
        self.pans: dict[str, None] = {}
        self.track_values: dict[str, None] = {}

    # --- hits ---------------------------------------------------------------------------------------------------

    def confirmed(self, text: str, kind: MatchKind) -> bool:
        """Whether find-pan reports *text*, however much text follows it on a line, as exactly one *kind*.

        This asks the scanner itself, so interactions between patterns (an unbounded brand pattern matching
        inside a longer PAN, an anti-PAN pattern that looks at the rest of the line) cannot make the expected
        counts wrong.  Some patterns look at the characters left on the line, hence the trailing text lengths.
        """
        return all(
            [m.kind for m in scan_line("f", 1, f"a {text} " + "x" * extra, self.patterns)] == [kind]
            for extra in (0, 8, 16, 24))

    def valid_pan(self) -> str:
        """A Luhn-valid PAN from a random configured pattern that find-pan reports as a PAN."""
        for _ in range(self.pan_tool.MAX_GENERATION_ATTEMPTS):
            data = self.pan_patterns[self.rng.choice(list(self.pan_patterns))]
            pan = self.pan_tool.generate_matching_luhn_pan(self.rng.choice(data["regex"]), self.rng)
            if self.confirmed(pan, MatchKind.PAN):
                return pan
        raise ValueError("could not generate a PAN that find-pan reports as a PAN")

    def hit(self, kind: str, counts: Counts) -> str:
        rng = self.rng
        for _ in range(self.pan_tool.MAX_GENERATION_ATTEMPTS):
            if kind in ("pan", "delimited"):
                pan = self.valid_pan()
                text = pan if kind == "pan" else rng.choice((" ", "-")).join(group(pan))
                if kind == "pan" or self.confirmed(text, MatchKind.PAN):
                    self.pans[pan] = None
                    counts.pans += 1
                    return text
            elif kind == "track":
                text = self.pan_tool.build_track(self.valid_pan(), rng.choice((1, 2)), rng)
                if self.confirmed(text, MatchKind.TRACK):
                    self.track_values[text] = None
                    counts.tracks += 1
                    return text
            elif kind == "bad-luhn":
                name = rng.choice(list(self.pan_patterns))
                digits = self.invalid_tool.corrupt(
                    self.pan_tool.generate_matching_luhn_pan(rng.choice(self.pan_patterns[name]["regex"]), rng), rng)
                text = rng.choice(("", " ", "-")).join(group(digits)) if rng.random() < 0.5 else digits
                if self.confirmed(text, MatchKind.BAD_LUHN):
                    counts.bad_luhn += 1
                    return text
            else:                                                        # anti-pan
                if rng.random() < 0.5:
                    when = datetime(2000, 1, 1) + timedelta(seconds=rng.randrange(0, 20 * 365 * 24 * 3600))
                    text = when.strftime("%Y%m%d%H%M%S")
                else:
                    text = rng.choice(("123456", "654321")) + "".join(
                        str(rng.randrange(10)) for _ in range(rng.randint(12, 13)))
                if self.confirmed(text, MatchKind.ANTI_PAN):
                    counts.anti_pans += 1
                    return text
        raise ValueError(f"could not generate a {kind} value that find-pan reports as intended")

    # --- files --------------------------------------------------------------------------------------------------

    def lines(self, counts: Counts) -> list[str]:
        rng = self.rng
        hits = 0 if (not self.hit_kinds or rng.random() < self.clean_share) else rng.randint(1, self.max_hits)
        wanted = rng.randint(0, max(1, self.max_size // AVERAGE_LINE))
        text = [self.pan_tool.filler(rng) for _ in range(max(wanted, 1 if hits else wanted))]
        for _ in range(hits):
            kind = rng.choices(self.hit_kinds, self.hit_weights)[0]
            index = rng.randrange(len(text))
            text[index] += rng.choice(SEPARATORS) + self.hit(kind, counts) + rng.choice(SEPARATORS) + self.pan_tool.filler(rng)
        return text

    def render(self, text: list[str], extension: str) -> bytes:
        newline = "\r\n" if self.rng.random() < self.crlf else "\n"
        if extension == ".csv":
            body = [f"{number},{row}" for number, row in enumerate(text, 1)]
        elif extension == ".json":
            body = [json.dumps(text, indent=0)] if text else []
        elif extension == ".xml":
            body = ["<records>"] + [f"<r>{row}</r>" for row in text] + ["</records>"] if text else []
        else:
            body = text
        return (newline.join(body) + (newline if body else "")).encode("utf-8")

    def text_file(self, stem: str) -> Made:
        extension = self.rng.choice(EXTENSIONS)
        counts = Counts()
        return Made(stem + extension, self.render(self.lines(counts), extension), counts)

    def binary_file(self, stem: str) -> Made:
        size = self.rng.randint(64, max(65, self.max_size))
        noise = bytes(self.rng.randrange(256) for _ in range(size))
        return Made(stem + self.rng.choice((".bin", ".dat")), b"\x00\x01" + noise.replace(b"\x00\x01", b"\x02"), kind="binary")


# --- archives --------------------------------------------------------------------------------------------------


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            #   A fixed timestamp keeps the bytes (and so the tree) dependent on the seed alone.
            info = zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return buffer.getvalue()


def _tar(members: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def archive(members: list[Made], stem: str, rng: random.Random, nest: float) -> Made:
    """Collect *members* into one archive file; a single member may become a .gz."""
    counts = Counts()
    for member in members:
        counts.add(member.counts)
    pairs = [(m.name, m.data) for m in members]
    if len(pairs) == 1 and rng.random() < 0.3:
        return Made(f"{stem}-{pairs[0][0]}.gz", gzip.compress(pairs[0][1], mtime=0), counts, "archive")
    if rng.random() < nest:
        pairs = [(f"{stem}-inner.zip", _zip(pairs))]
    if rng.random() < 0.5:
        return Made(f"{stem}.zip", _zip(pairs), counts, "archive")
    return Made(f"{stem}.tar", _tar(pairs), counts, "archive")


# --- layout ----------------------------------------------------------------------------------------------------


def directory_for(index: int, per_dir: int, depth: int, total: int) -> Path:
    """Nested directory (depth levels) for file number *index*, about *per_dir* files each."""
    directories = max(1, -(-total // per_dir))
    fanout = max(2, math.ceil(directories ** (1 / depth) - 1e-9)) if depth > 0 else 1
    number = index // per_dir
    return Path(*[f"d{(number // fanout ** level) % fanout:03d}" for level in reversed(range(depth))]) if depth else Path()


def generate(out: Path, files: int, maker: Maker, rng: random.Random, per_dir: int, depth: int,
             binary: float, archives: float, nest: float) -> tuple[Counts, list[dict]]:
    """Write *files* files under *out*; return the planted totals and the manifest entries."""
    totals, entries, pending = Counts(), [], []
    width = len(str(files))

    def write(made: Made, folder: Path) -> None:
        target = out / folder / made.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(made.data)
        totals.add(made.counts)
        entries.append({"path": (folder / made.name).as_posix(), "kind": made.kind, **made.counts.as_dict()})

    def flush(folder: Path, number: int) -> None:
        if pending:
            write(archive(pending[:], f"a{number:0{width}d}", rng, nest), folder)
            pending.clear()

    folder = Path()
    for index in range(files):
        folder = directory_for(index, per_dir, depth, files)
        stem = f"f{index:0{width}d}"
        roll = rng.random()
        if roll < binary:
            write(maker.binary_file(stem), folder)
        elif roll < binary + archives:
            pending.append(maker.text_file(stem))
            if len(pending) >= rng.randint(1, 5):
                flush(folder, index)
        else:
            write(maker.text_file(stem), folder)
    flush(folder, files)
    return totals, entries


def write_answers(answers: Path, totals: Counts, entries: list[dict], maker: Maker, seed: int, args) -> None:
    answers.mkdir(parents=True, exist_ok=True)
    binary_files = sum(entry["kind"] == "binary" for entry in entries)
    expected = {**totals.as_dict()}
    (answers / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    manifest = {"seed": seed, "files": len(entries), "binary_files": binary_files, "totals": expected,
                "options": {"mix": args.mix, "per_dir": args.per_dir, "depth": args.depth,
                            "max_size": args.max_size, "binary": args.binary, "archives": args.archives},
                "entries": entries}
    (answers / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    (answers / "pans.txt").write_text("".join(f"{pan}\n" for pan in maker.pans), encoding="utf-8")
    (answers / "tracks.txt").write_text("".join(f"{track}\n" for track in maker.track_values), encoding="utf-8")


def percentage(value: str) -> float:
    try:
        number = float(value.rstrip("%"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a percentage such as 5 or 5%") from error
    if not 0 <= number <= 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return number / 100


def positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True, metavar="DIR", help="directory to create (must not exist or be empty)")
    parser.add_argument("--files", type=positive, required=True, metavar="N", help="number of files to generate")
    parser.add_argument("--seed", type=int, default=None, help="random seed (default: random, recorded in manifest.json)")
    parser.add_argument("--mix", default=DEFAULT_MIX, metavar="KIND=WEIGHT,...",
                        help=f"relative weights of {', '.join(KINDS)} (default: {DEFAULT_MIX})")
    parser.add_argument("--max-hits", type=positive, default=3, metavar="N", help="most hits in one file (default: 3)")
    parser.add_argument("--max-size", type=positive, default=4096, metavar="BYTES", help="approximate largest text file (default: 4096)")
    parser.add_argument("--per-dir", type=positive, default=100, metavar="N", help="files per directory (default: 100)")
    parser.add_argument("--depth", type=int, default=2, metavar="N", help="directory levels (default: 2; 0 for one flat directory)")
    parser.add_argument("--binary", type=percentage, default=0.0, metavar="PCT", help="percent of files that are binary noise (default: 0)")
    parser.add_argument("--archives", type=percentage, default=0.0, metavar="PCT", help="percent of files placed in archives (default: 0)")
    parser.add_argument("--nest", type=percentage, default=0.2, metavar="PCT", help="percent of archives holding an inner zip (default: 20)")
    parser.add_argument("--crlf", type=percentage, default=0.1, metavar="PCT", help="percent of text files with CRLF line ends (default: 10)")
    parser.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS, metavar="FILE", help="regex configuration (default: the shipped one)")
    parser.add_argument("--answers", type=Path, default=None, metavar="DIR",
                        help="where to write manifest.json, expected.json, pans.txt, tracks.txt (default: <out>.expected)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.depth < 0:
            raise ValueError("--depth must not be negative")
        if args.binary + args.archives > 1:
            raise ValueError("--binary and --archives together must not exceed 100%")
        mix = parse_mix(args.mix)
        if args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())):
            raise ValueError(f"{args.out} exists and is not empty")
        seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2 ** 32)
        rng = random.Random(seed)
        maker = Maker(args.patterns, mix, rng, args.max_hits, args.max_size, args.crlf)
        args.out.mkdir(parents=True, exist_ok=True)
        totals, entries = generate(args.out, args.files, maker, rng, args.per_dir, args.depth,
                                   args.binary, args.archives, args.nest)
        answers = args.answers or args.out.with_name(args.out.name + ".expected")
        write_answers(answers, totals, entries, maker, seed, args)
    except (OSError, ValueError, json.JSONDecodeError, re.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {len(entries)} files under {args.out} (seed {seed}); answers in {answers}", file=sys.stderr)
    print(f"Planted: {totals.pans} PANs, {totals.tracks} tracks, {totals.bad_luhn} Luhn failures, "
          f"{totals.anti_pans} anti-PANs", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
