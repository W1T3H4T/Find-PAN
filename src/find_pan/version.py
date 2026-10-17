"""Single source of the Find-PAN version (kept in sync with pyproject.toml)."""

__version__ = "2.3.1"


def format_version(prog: str) -> str:
    """Return ``"<prog> v<version>"``."""
    return f"{prog} v{__version__}"
