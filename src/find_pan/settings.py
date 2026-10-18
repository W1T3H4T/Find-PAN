"""Immutable run settings built by the command line interface."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Every option the scanner reads.

    ``files`` holds the ``--file`` entries; archives are detected and expanded
    automatically for both ``--path`` and ``--file``.
    """

    path: str | None = None
    files: tuple[str, ...] = ()
    log_dir: str = ""
    rgx_patterns: str | None = None
    rgx_prefix: bool = False
    skip_binary: bool = False
    line_limit: int = 0
    report_delta: int = 500
    csv: str | None = None
    verbose: bool = False
    debug: bool = False
    mask: bool = False
    log_anti_pan: bool = False
    summary_json: str | None = None
    raw: bool = False
    raw_encodings: tuple[str, ...] = ("ascii", "utf-16")
    pan_list: str | None = None
    track_list: str | None = None
