"""Exceptions raised by the find_pan package.

Library modules raise these; only ``cli.main`` turns them into messages and
exit codes.
"""


class FindPanError(Exception):
    """Base class for all expected Find-PAN failures."""


class ConfigError(FindPanError):
    """Configuration, pattern or output-file problem."""


class LoggingSetupError(FindPanError):
    """The log directory or log files could not be prepared."""


class ExtractorError(FindPanError):
    """An archive could not be extracted."""


class ExtractorUnavailable(ExtractorError):
    """No usable extractor exists for an archive (unknown type, no entry, tool not installed)."""
