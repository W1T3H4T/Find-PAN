"""Command-line interface: the only module that reads arguments, prints
errors, or chooses exit codes."""

import argparse
import json
import os
import sys
import traceback
from dataclasses import replace
from typing import Sequence

from find_pan.config import (
    compile_regex_patterns,
    compile_regex_patterns_with_prefix,
    dump_patterns,
    find_extractor_config_path,
    find_json_regex_config,
    load_extraction_limits,
    load_extractor_config,
    load_json_data,
)
from find_pan.errors import FindPanError
from find_pan.logging_setup import build_loggers
from find_pan.models import ScanStats
from find_pan.rawscan import DEFAULT_ENCODINGS as DEFAULT_RAW_ENCODINGS
from find_pan.rawscan import ENCODINGS as RAW_ENCODINGS
from find_pan.redact import Redactor
from find_pan.reporting import AntiPanSink, CsvSink, LogSink, Reporter, TraceSink
from find_pan.scanner import Scanner
from find_pan.settings import Settings
from find_pan.targets import TargetLedger, Targets, load_pan_list, load_track_list
from find_pan.version import format_version

PROGRAM_NAME = "find-pan.py"
REGEX_PATTERN_PREFIX = r"[ '\"{]"


def print_exception_info(e: object) -> None:
    """Print a consolidated report of the active exception, then exit with status 1."""
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_stack = traceback.extract_tb(exc_traceback)

    if tb_stack:
        #   The innermost frame is where the exception was actually raised.
        frame = tb_stack[-1]
        file_name, line_number, func_name = frame.filename, frame.lineno, frame.name
    else:
        file_name, line_number, func_name = "<unknown>", 0, "<unknown>"

    exception_message = str(exc_value) if exc_value is not None else ""
    extra_info = str(e) if e is not None else ""

    print("\nException Information:")
    print("-----------------------------------------------------------------")
    print(f"Function: '{func_name}', on line {line_number}")
    print(f"File    : {file_name}")
    print(f"Type    : {exc_type.__name__ if exc_type else 'Unknown'}")
    print(f"Message : {exception_message}")
    if extra_info and extra_info.lower() != exception_message.lower():
        print(f"Info    : {extra_info}")
    print("-----------------------------------------------------------------")
    sys.exit(1)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _raw_encodings(value: str) -> str:
    names = [name.strip().lower() for name in value.split(",") if name.strip()]
    unknown = [name for name in names if name not in RAW_ENCODINGS]
    if not names or unknown:
        raise argparse.ArgumentTypeError(
            f"unknown encoding {', '.join(unknown) or value!r}; choose from {', '.join(RAW_ENCODINGS)}")
    return ",".join(dict.fromkeys(names))


# autopep8: off
def build_parser() -> argparse.ArgumentParser:
    log_dir = os.path.join(os.path.expanduser("~"), "Find-PAN-Logs")
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description="Scan for PCI PAN and TRACK data patterns.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    #   Mutable processing (change our runtime/detection behavior)
    parser.add_argument( "--path", help="Filesystem pathname to scan.", type=str, default=None)
    parser.add_argument( "--file", help="Files to scan; any number, e.g. --file a.txt b.zip c.tar.gz. "
                        "Archives are detected by content, expanded with the configured tools, and scanned.",
                        nargs="+", action="extend", metavar="FILE", default=[])
    parser.add_argument( "--log-dir", help="Directory for log files.", default=log_dir)
    parser.add_argument( "--rgx-patterns", help="JSON file containing PAN and TRACK regular expressions "
                        "(default: the first find-pan-regex.json found in the configuration directories, "
                        "ending with <appRoot>/config).",
                        type=str, default=None)
    parser.add_argument( "--rgx-prefix", help=f"Apply prefixes ({REGEX_PATTERN_PREFIX}) to regular expressions.",
                        default=False, action="store_true")
    parser.add_argument( "--skip-binary", help="Skip binary files.", action="store_true", default=False)
    parser.add_argument( "--line-limit", help="Line scan limit per file.", type=int, default=0)
    parser.add_argument( "--report-delta", type=_positive_int, default=500,
                        help="Files to process before reporting progress.")
    parser.add_argument( "--csv",
                        help="CSV file path for match output. Emits filename, line number, offset, pattern, and sanitized match data.",
                        type=str, default=None)
    parser.add_argument( "--summary-json", help="Write the run summary (counts and skipped files) to this JSON file.",
                        type=str, default=None, metavar="PATH")
    parser.add_argument( "--raw", default=False, action="store_true",
                        help="Scan every file as raw bytes (memory dumps, disk images): no line splitting, no binary "
                        "skipping, no archive expansion. Matches are reported by byte offset.")
    parser.add_argument( "--raw-encodings", type=_raw_encodings, default=",".join(DEFAULT_RAW_ENCODINGS), metavar="LIST",
                        help=f"With --raw: comma-separated encodings to read text as ({', '.join(RAW_ENCODINGS)}). "
                        "utf-16 covers both byte orders.")
    parser.add_argument( "--pan-list", metavar="FILE", default=None,
                        help="Report only the PANs listed in FILE (one per line; spaces and hyphens allowed). A filter on what the patterns "
                        "found, never a source: the summary lists each value as found (how often, where) or not found.")
    parser.add_argument( "--track-list", metavar="FILE", default=None,
                        help="Report only the track 1 / track 2 data listed in FILE, one per line; works like --pan-list.")
    parser.add_argument( "--log-anti-pan", default=False, action="store_true",
                        help="Write anti-PAN hits to a separate log file (Find-PAN-anti-pan-<date>.log) and report it in the summary.")

    #   Non-functional processing
    parser.add_argument( "--verbose", default=False, action="store_true", help="Verbose output.")
    parser.add_argument( "--debug", default=False, action="store_true", help="Enable debug logging.")
    parser.add_argument( "--mask", default=False, action="store_true",
                        help="Mask PAN digits (keep first 6 and last 4) in the log, CSV and Luhn-failure debug output.")
    parser.add_argument( "--version", default=False, action="store_true", help="Print version information.")
    return parser
# autopep8: on


def _settings_from(namespace: argparse.Namespace) -> Settings:
    return Settings(
        path=namespace.path,
        files=tuple(namespace.file),
        log_dir=namespace.log_dir,
        rgx_patterns=namespace.rgx_patterns,
        rgx_prefix=namespace.rgx_prefix,
        skip_binary=namespace.skip_binary,
        line_limit=namespace.line_limit,
        report_delta=namespace.report_delta,
        csv=namespace.csv,
        verbose=namespace.verbose,
        debug=namespace.debug,
        mask=namespace.mask,
        log_anti_pan=namespace.log_anti_pan,
        summary_json=namespace.summary_json,
        raw=namespace.raw,
        raw_encodings=tuple(namespace.raw_encodings.split(",")),
        pan_list=namespace.pan_list,
        track_list=namespace.track_list,
    )


def parse_args(argv: Sequence[str] | None = None) -> Settings:
    """Parse *argv* into ``Settings`` without touching any configuration file."""
    return _settings_from(build_parser().parse_args(argv))


def _describe(namespace: argparse.Namespace) -> str:
    lines = ["", "Parameters and Defaults"]
    lines += [f" --{name.replace('_', '-')}={value}" for name, value in vars(namespace).items()]
    return "\n".join(lines) + "\n"


def _print_version_header(namespace: argparse.Namespace, argv: Sequence[str]) -> None:
    print(f"{format_version(PROGRAM_NAME)}\nPython {sys.version}")
    if argv and not namespace.version:
        print("Command-line arguments: ", list(argv))


def _load_patterns(settings: Settings, loggers) -> list:
    json_data = load_json_data(settings.rgx_patterns)
    if not json_data:
        raise ValueError(f"No patterns found in {settings.rgx_patterns}")
    if settings.debug:
        loggers.trace.debug(dump_patterns(json_data))
    if settings.rgx_prefix:
        return compile_regex_patterns_with_prefix(json_data)
    return compile_regex_patterns(json_data)


def _load_targets(settings: Settings, patterns: list) -> Targets | None:
    """Read --pan-list and --track-list; None when neither was given."""
    if not (settings.pan_list or settings.track_list):
        return None
    return Targets(
        pans=load_pan_list(settings.pan_list) if settings.pan_list else (),
        tracks=load_track_list(settings.track_list, patterns) if settings.track_list else (),
    )


def _error(message: object) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 1


def _make_streams_tolerant() -> None:
    """Never let an unencodable character (e.g. U+FFFD) break console logging."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: Sequence[str] | None = None) -> int:
    """Run Find-PAN; return the process exit status."""
    parser = build_parser()
    namespace = parser.parse_args(argv)
    argv = list(argv) if argv is not None else sys.argv[1:]
    _make_streams_tolerant()

    if os.environ.get("FIND_PAN_EXCEPTION_TEST"):    # developer hook, not a user option
        try:
            print(10 / 0)
        except ZeroDivisionError:
            print_exception_info("Exception test called")

    #   --version works before any configuration is looked up.
    if namespace.version:
        _print_version_header(namespace, argv)
        return 0

    settings = _settings_from(namespace)
    if not (settings.path or settings.files):
        parser.print_help()
        return 1

    try:
        return _run(namespace, settings, argv)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 1
    except (FindPanError, FileNotFoundError, ValueError) as error:
        return _error(error)
    except Exception as error:  # pylint: disable=broad-exception-caught
        print_exception_info(error)
        return 1


def _write_summary_json(path: str, data: dict, exit_status: int) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump({**data, "exit_status": exit_status}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _run(namespace: argparse.Namespace, settings: Settings, argv: Sequence[str]) -> int:
    """Load configuration, build the reporting pipeline and scan."""
    if settings.rgx_patterns is None:
        settings = replace(settings, rgx_patterns=find_json_regex_config())
        #   Report the file actually used, not the None the parser defaulted to.
        namespace.rgx_patterns = settings.rgx_patterns

    loggers = build_loggers(settings)
    patterns = _load_patterns(settings, loggers)
    targets = _load_targets(settings, patterns)

    _print_version_header(namespace, argv)
    loggers.trace.info("%s", _describe(namespace))
    #   Separates runs in logs that are appended to (the anti-PAN log holds findings only).
    for logger in (loggers.pan, loggers.trace):
        logger.info("---- Find-PAN run started (%s) ----", format_version(PROGRAM_NAME))

    sinks = [LogSink(loggers.pan), TraceSink(loggers.trace)]
    if settings.log_anti_pan:
        sinks.append(AntiPanSink(loggers.anti_pan, loggers.anti_pan_path))
    if settings.csv:
        sinks.append(CsvSink(settings.csv))
    stats = ScanStats()
    reporter = Reporter(Redactor(settings.mask), sinks, stats, loggers.trace, settings.report_delta,
                        expected=TargetLedger(targets) if targets else None)
    scanner = Scanner(
        settings, patterns, reporter, loggers,
        lambda: load_extractor_config(find_extractor_config_path()),
        lambda: load_extraction_limits(find_extractor_config_path()),
    )

    status = 0
    stats.start()
    try:
        scanner.scan_files(settings.files)
        if settings.path:
            scanner.scan_path(settings.path)
    except KeyboardInterrupt:
        loggers.trace.error("KeyboardInterrupt caught. Exiting.")
        status = 1
    finally:
        stats.stop()
        try:
            reporter.close()
        except Exception as error:  # pylint: disable=broad-exception-caught
            #   Report, but never replace an exception already in flight.
            print(f"Error: closing outputs failed: {error}", file=sys.stderr)
            status = 1
    for problem in scanner.problems:
        print(f"{problem.severity.capitalize()}: {problem.message}", file=sys.stderr)
    if stats.failures:
        status = 1       # a requested file or archive was never scanned
    for line in reporter.summary_lines(settings.log_dir):
        loggers.trace.info("%s", line)
    if settings.summary_json:
        try:
            _write_summary_json(settings.summary_json, reporter.summary_data(), status)
        except OSError as error:
            print(f"Error: cannot write summary JSON '{settings.summary_json}': {error}", file=sys.stderr)
            status = 1
    return status
