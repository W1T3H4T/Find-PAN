"""Immutable run settings built by the command line interface."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Every option the scanner reads.

    ``archive`` is the value of the ``--tar`` command-line flag.
    """

    path: str | None = None
    archive: str | None = None
    tar_tmp: str = ""
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
    exception_test: bool = False
