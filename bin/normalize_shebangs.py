#!/usr/bin/env -S uv run python
"""Normalize the shebang lines of all Python scripts in the repository bin/.

Find-PAN is run inside a per-platform uv-managed virtual environment
(.venv-windows or .venv-linux).  The shebang of each script should resolve
python through that environment so that scripts work the same way when
executed directly on Windows (Git Bash / WSL) or on POSIX.

This script rewrites the first line of every *.py file under the repository
bin/ directory to:

    #!/usr/bin/env -S uv run python

`-S` is required because `uv run python` is a multi-word command.
"""

import sys
from pathlib import Path


TARGET_SHEBANG = "#!/usr/bin/env -S uv run python\n"


def normalize(path: Path) -> bool:
    """Return True if the file was changed, False otherwise."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("#!"):
        return False
    lines = text.splitlines(keepends=True)
    if not lines:
        return False
    first = lines[0]
    if first.rstrip() == TARGET_SHEBANG.rstrip():
        return False
    lines[0] = TARGET_SHEBANG
    path.write_text("".join(lines), encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    bin_dir = root / "bin"
    changed = 0
    for path in sorted(bin_dir.glob("*.py")):
        if normalize(path):
            print(f"Updated shebang: {path}")
            changed += 1
    print(f"Normalized {changed} file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
