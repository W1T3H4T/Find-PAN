"""Command-line interface: the only module that reads arguments, prints
errors, or chooses exit codes."""

import argparse
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
    load_extractor_config,
    load_json_data,
)
from find_pan.errors import FindPanError
from find_pan.logging_setup import build_loggers
from find_pan.models import ScanStats
from find_pan.redact import Redactor
from find_pan.reporting import AntiPanSink, CsvSink, LogSink, Reporter, TraceSink
from find_pan.scanner import Scanner
from find_pan.settings import Settings
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


# autopep8: off
def build_parser() -> argparse.ArgumentParser:
    log_dir = os.path.join(os.path.expanduser("~"), "Find-PAN-Logs")
    tar_dir = os.path.join(log_dir, "tar-temp")
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description="Scan for PCI PAN and TRACK data patterns.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    #   Mutable processing (change our runtime/detection behavior)
    parser.add_argument( "--path", help="Filesystem pathname to scan.", type=str, default=None)
    parser.add_argument( "--tar", help="Archive file path (tar, tar.gz, zip, 7z, gz).", type=str, default=None)
    parser.add_argument( "--tar-tmp", help="Parent directory for temporary archive extraction directories.",
                        default=tar_dir)
    parser.add_argument( "--log-dir", help="Directory for log files.", default=log_dir)
    parser.add_argument( "--rgx-patterns", help="JSON file containing PAN and TRACK regular expressions.",
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
    parser.add_argument( "--log-anti-pan", default=False, action="store_true",
                        help="Write anti-PAN hits to a separate log file (Find-PAN-anti-pan-<date>.log) and report it in the summary.")

    #   Non-functional processing
    parser.add_argument( "--verbose", default=False, action="store_true", help="Verbose output.")
    parser.add_argument( "--debug", default=False, action="store_true", help="Enable debug logging.")
    parser.add_argument( "--mask", default=False, action="store_true",
                        help="Mask PAN digits (keep first 6 and last 4) in the log, CSV and Luhn-failure debug output.")
    parser.add_argument( "--version", default=False, action="store_true", help="Print version information.")
    parser.add_argument( "--exception-test", default=False, action="store_true", help="Test exception handler.")
    return parser
# autopep8: on


def _settings_from(namespace: argparse.Namespace) -> Settings:
    return Settings(
        path=namespace.path,
        archive=namespace.tar,
        tar_tmp=namespace.tar_tmp,
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
        exception_test=namespace.exception_test,
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

    #   --version works before any configuration is looked up.
    if namespace.version:
        _print_version_header(namespace, argv)
        return 0
    if namespace.exception_test:
        try:
            print(10 / 0)
        except ZeroDivisionError:
            print_exception_info("Exception test called")

    settings = _settings_from(namespace)
    if not (settings.path or (settings.archive and settings.tar_tmp)):
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


def _run(namespace: argparse.Namespace, settings: Settings, argv: Sequence[str]) -> int:
    """Load configuration, build the reporting pipeline and scan."""
    if settings.rgx_patterns is None:
        settings = replace(settings, rgx_patterns=find_json_regex_config())
    extractor_config = None
    if settings.archive and not settings.path:
        extractor_config = load_extractor_config(find_extractor_config_path())

    loggers = build_loggers(settings)
    patterns = _load_patterns(settings, loggers)

    _print_version_header(namespace, argv)
    loggers.trace.info("%s", _describe(namespace))

    sinks = [LogSink(loggers.pan), TraceSink(loggers.trace)]
    if settings.log_anti_pan:
        sinks.append(AntiPanSink(loggers.anti_pan, loggers.anti_pan_path))
    if settings.csv:
        sinks.append(CsvSink(settings.csv))
    stats = ScanStats()
    reporter = Reporter(Redactor(settings.mask), sinks, stats, loggers.trace, settings.report_delta)
    scanner = Scanner(settings, patterns, reporter, loggers, extractor_config)

    status = 0
    stats.start()
    try:
        if settings.path:
            scanner.scan_path(settings.path)
        else:
            scanner.scan_archive(settings.archive)
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
    for message in scanner.extraction_errors:
        print(f"Error: {message}", file=sys.stderr)
        status = 1
    for line in reporter.summary_lines(settings.log_dir):
        loggers.trace.info("%s", line)
    return status
