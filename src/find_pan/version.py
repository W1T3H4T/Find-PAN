"""Single source of the Find-PAN version (kept in sync with pyproject.toml)."""

__version__ = "3.5.2"


def format_version(prog: str) -> str:
    """Return ``"<prog> v<version>"``."""
    return f"{prog} v{__version__}"
