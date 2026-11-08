"""Dispatch independent Find-PAN processes and combine their outputs."""

import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from contextlib import ExitStack
from fnmatch import fnmatchcase
from pathlib import Path

from find_pan.models import SkipReason
from find_pan.reporting import CSV_FIELDS, MAX_LISTED_SKIPS

_ROOT = Path(__file__).resolve().parents[2]
_COUNTERS = ("pans", "tracks", "bad_luhn", "anti_pans", "files_scanned", "archives_expanded", "archives_skipped")


def _sources(options):
    paths = list(options.file)
    if options.path:
        for root, directories, files in os.walk(options.path):
            directories[:] = [name for name in directories
                              if not any(fnmatchcase(name, pattern) for pattern in options.exclude_dir)]
            paths.extend(os.path.join(root, name) for name in files)
    return paths


def _partition(paths, workers):
    batches = [[] for _ in range(workers)]
    sizes = [0] * workers
    weighted = []
    for index, path in enumerate(paths):
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        weighted.append((size, index, path))
    for size, index, path in sorted(weighted, key=lambda item: (-item[0], item[1])):
        worker = min(range(workers), key=lambda number: (sizes[number], len(batches[number]), number))
        batches[worker].append((index, path))
        sizes[worker] += size
    return [[path for _, path in sorted(batch)] for batch in batches]


def _worker_arguments(options, manifest, directory):
    args = [sys.executable, str(_ROOT / "bin" / "find-pan.py"), "--worker-manifest", str(manifest),
            "--log-dir", str(directory / "logs"), "--summary-json", str(directory / "summary.json"),
            "--raw-encodings", options.raw_encodings, "--line-limit", str(options.line_limit),
            "--report-delta", str(options.report_delta)]
    if options.csv:
        args.extend(("--csv", str(directory / "findings.csv")))
    for name in ("rgx_patterns", "pan_list", "track_list"):
        value = getattr(options, name)
        if value is not None:
            args.extend(("--" + name.replace("_", "-"), value))
    for pattern in options.raw_file:
        args.extend(("--raw-file", pattern))
    for pattern in options.exclude_dir:
        args.extend(("--exclude-dir", pattern))
    for flag in ("rgx_prefix", "skip_binary", "verbose", "debug", "mask", "log_anti_pan", "raw"):
        if getattr(options, flag):
            args.append("--" + flag.replace("_", "-"))
    return args


def _relay(pipe, output, worker, lock):
    try:
        for line in iter(pipe.readline, ""):
            with lock:
                print(f"[worker {worker}] {line}", end="", file=output, flush=True)
    finally:
        pipe.close()


def _merge_summaries(summaries, elapsed, status):
    result = {key: sum(item[key] for item in summaries) for key in _COUNTERS}
    result["skipped"] = [entry for item in summaries for entry in item["skipped"]]
    result["total_time"] = elapsed
    result["average_time"] = elapsed / result["files_scanned"] if result["files_scanned"] else 0.0
    result["exit_status"] = status
    if summaries and "expected" in summaries[0]:
        result["expected"] = {}
        for kind in ("pans", "tracks"):
            merged = []
            if any(len(item["expected"][kind]) != len(summaries[0]["expected"][kind]) for item in summaries):
                raise ValueError("worker expected-value lists differ")
            for index, entry in enumerate(summaries[0]["expected"][kind]):
                entries = [item["expected"][kind][index] for item in summaries]
                if any(value["value"] != entry["value"] for value in entries):
                    raise ValueError("worker expected-value lists differ")
                locations = [location for value in entries for location in value["locations"]][:3]
                merged.append({"value": entry["value"], "found": sum(value["found"] for value in entries),
                               "locations": locations})
            result["expected"][kind] = merged
    return result


def _read_summaries(directories, csv_requested):
    summaries = []
    csv_directories = []
    failed = False
    for directory in directories:
        path = directory / "summary.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or any(not isinstance(data.get(key), int) or data[key] < 0 for key in _COUNTERS):
                raise ValueError("invalid counters")
            if not isinstance(data.get("skipped"), list):
                raise ValueError("invalid skipped entries")
            summaries.append(data)
        except (OSError, ValueError) as error:
            print(f"Error: worker {directory.name} summary: {error}", file=sys.stderr)
            failed = True
        if (directory / "findings.csv").is_file():
            csv_directories.append(directory)
        elif csv_requested:
            print(f"Error: worker {directory.name} did not produce a CSV", file=sys.stderr)
            failed = True
    return summaries, csv_directories, failed


def _merge_csv(destination, directories):
    with open(destination, "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(CSV_FIELDS)
        for directory in directories:
            with (directory / "findings.csv").open(newline="", encoding="utf-8") as source:
                reader = csv.reader(source)
                if next(reader, None) != CSV_FIELDS:
                    raise ValueError(f"invalid worker CSV in {directory}")
                for row in reader:
                    if len(row) != len(CSV_FIELDS):
                        raise ValueError(f"invalid worker CSV row in {directory}")
                    writer.writerow(row)


def _merge_logs(destination, directories):
    os.makedirs(destination, exist_ok=True)
    names = set()
    for directory in directories:
        logs = directory / "logs"
        if logs.is_dir():
            names.update(path.name for path in logs.iterdir() if path.is_file())
    for name in sorted(names):
        with open(os.path.join(destination, name), "ab") as output:
            for directory in directories:
                path = directory / "logs" / name
                if path.is_file():
                    with path.open("rb") as source:
                        shutil.copyfileobj(source, output)


def _expected_lines(expected):
    lines = ["", "-- Expected Values --"]
    for kind, label in (("pans", "PANs"), ("tracks", "TRACKs")):
        entries = expected[kind]
        if entries:
            found = sum(entry["found"] > 0 for entry in entries)
            lines.append(f"Expected {label} found{' ' * (6 - len(label))}: {found} of {len(entries)}")
    width = max((len(entry["value"]) for kind in ("pans", "tracks") for entry in expected[kind]), default=0)
    for kind, label in (("pans", "PAN"), ("tracks", "TRACK")):
        for entry in expected[kind]:
            value = f"{entry['value']:<{width}}"
            if entry["found"]:
                count = entry["found"]
                lines.append(f"{label:<5} {value}  FOUND  {count} time{'' if count == 1 else 's'}, "
                             f"first at {entry['locations'][0]}")
            else:
                lines.append(f"{label:<5} {value}  NOT FOUND")
    return lines


def _print_summary(summary, log_dir, anti_pan_logs=()):
    skips = Counter(reason for reason, _ in summary["skipped"])
    binary = skips[SkipReason.BINARY.value]
    executable = skips[SkipReason.EXECUTABLE.value]
    width = max(8, *(len(str(value)) for value in (summary["pans"], summary["tracks"],
                                                    summary["pans"] + summary["tracks"],
                                                    summary["files_scanned"])),
                len(f"{summary['average_time']:.3f}"), len(f"{summary['total_time']:.3f}"))
    lines = [
        "", "-- Combined Processing Summary --",
        f"PANs Matched  : {summary['pans']:{width}d}",
        f"TRACKs Matched: {summary['tracks']:{width}d}",
        f"Total matches : {summary['pans'] + summary['tracks']:{width}d}",
        f"Scanned       : {summary['files_scanned']:{width}d} Files.",
        f"Average time  : {summary['average_time']:{width}.3f} seconds per file",
        f"Total time    : {summary['total_time']:{width}.3f} seconds",
        "", "-- Skipped Summary --",
        f"Detected {summary['bad_luhn']} Luhn Check Failures.",
        f"Detected {summary['anti_pans']} Anti-PANs.",
    ]
    for name in anti_pan_logs:
        lines.append(f"Anti-PAN log    : {os.path.join(log_dir, name)}")
    if anti_pan_logs:
        lines.append(f"Anti-PANs logged: {summary['anti_pans']}")
    lines += [f"Skipped {binary + executable} Files.", f"Skipped {executable} Executable Files.",
              f"Skipped {binary} Binary Files."]
    if skips[SkipReason.UNREADABLE.value]:
        lines.append(f"Unreadable {skips[SkipReason.UNREADABLE.value]} Files.")
    if summary["archives_expanded"]:
        lines.append(f"Archives expanded: {summary['archives_expanded']}")
    if summary["archives_skipped"]:
        lines.append(f"Archives skipped (no tool or failed): {summary['archives_skipped']}")
    if "expected" in summary:
        lines += _expected_lines(summary["expected"])
    lines += ["", "Scan complete.", "", f"Log files are located in: {log_dir}"]
    if summary["skipped"]:
        lines += ["", "-- Skipped Files --"]
        lines += [f"[{reason}] {path}" for reason, path in summary["skipped"][:MAX_LISTED_SKIPS]]
        hidden = len(summary["skipped"]) - MAX_LISTED_SKIPS
        if hidden > 0:
            lines.append(f"... and {hidden} more (see the log)")
    print("\n".join(lines))


def _terminate(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        result = subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if result.returncode and process.poll() is None:
            process.kill()
    else:
        try:
            getattr(os, "killpg")(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL"))
        except ProcessLookupError:
            pass


def dispatch(options):
    """Launch and coordinate independent scanner jobs for a parallel CLI invocation."""
    if not (options.path or options.file) or options.worker_manifest:
        print("Error: --workers requires --path or --file", file=sys.stderr)
        return 1
    started = time.perf_counter()
    processes = []
    threads = []
    lock = threading.Lock()
    try:
        batches = _partition(_sources(options), options.workers)
        with tempfile.TemporaryDirectory(prefix="find-pan-workers-") as temporary, ExitStack() as stack:
            directories = []
            try:
                for index, batch in enumerate(batches):
                    directory = Path(temporary) / str(index)
                    directory.mkdir()
                    directories.append(directory)
                    manifest = directory / "files.json"
                    manifest.write_text(json.dumps(batch, ensure_ascii=True), encoding="utf-8")
                    process = stack.enter_context(subprocess.Popen(
                        _worker_arguments(options, manifest, directory), stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                        start_new_session=os.name != "nt",
                        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}))
                    processes.append(process)
                    for pipe, output in ((process.stdout, sys.stdout), (process.stderr, sys.stderr)):
                        thread = threading.Thread(target=_relay, args=(pipe, output, index + 1, lock), daemon=True)
                        thread.start()
                        threads.append(thread)
                statuses = [process.wait() for process in processes]
            finally:
                for process in processes:
                    _terminate(process)
                for process in processes:
                    process.wait()
                for thread in threads:
                    thread.join()
            status = int(any(statuses))
            summaries, csv_directories, incomplete = _read_summaries(directories, bool(options.csv))
            status |= int(incomplete)
            summary = _merge_summaries(summaries, time.perf_counter() - started, status)
            if options.csv:
                _merge_csv(options.csv, csv_directories)
            _merge_logs(options.log_dir, directories)
            if options.summary_json:
                Path(options.summary_json).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            anti_pan_logs = sorted({path.name for directory in directories
                                    for path in (directory / "logs").glob("Find-PAN-anti-pan-*.log")})
            _print_summary(summary, options.log_dir, anti_pan_logs)
            return status
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(f"Error: parallel scan failed: {error}", file=sys.stderr)
        return 1
