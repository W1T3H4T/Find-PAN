#!/usr/bin/env bash
# =============================================================================
#  File    :   setup-env.sh
#  What    :   One-time setup for the Find-PAN project environment on
#              WSL / Linux / macOS.
#
#  Synchronizes the project-root .venv without changing user shell settings.
#
#  python-magic requires the system libmagic library.  On Debian/Ubuntu this
#  package is libmagic1; on macOS with Homebrew it is libmagic.  The script
#  checks for the library and warns if it is missing, but it will not abort.
#
#  For direct uv commands, set UV_PROJECT_ENVIRONMENT=.venv.
# =============================================================================

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
venv_path="$project_root/.venv"
recreate=false
if [ "${1:-}" = "--recreate" ]; then
    recreate=true
    shift
fi
if [ "$#" -ne 0 ]; then
    echo "Usage: $0 [--recreate]" >&2
    exit 2
fi

# -- 1. uv must be installed
uv_bin="$(command -v uv || true)"
if [ -z "$uv_bin" ]; then
    #   Not on PATH (common for non-interactive shells); check the
    #   standard installer locations.
    for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /usr/local/bin/uv; do
        if [ -x "$candidate" ]; then
            uv_bin="$candidate"
            break
        fi
    done
fi
if [ -z "$uv_bin" ]; then
    echo "uv was not found on PATH." >&2
    echo "Install it:  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    echo "Then re-run this script." >&2
    exit 1
fi

# -- 1b. Warn if libmagic is not present, but allow the environment to be set up
#         because the scanner still works without --skip-binary.
magic_present=false
case "$(uname -s)" in
    Linux)
        if ldconfig -p 2>/dev/null | grep -q libmagic || [ -f /usr/lib/file/magic.mgc ] || [ -f /usr/share/misc/magic.mgc ]; then
            magic_present=true
        fi
        ;;
    Darwin)
        if command -v brew >/dev/null 2>&1 && [ -f "$(brew --prefix libmagic 2>/dev/null)/lib/libmagic.dylib" ]; then
            magic_present=true
        elif [ -f /usr/local/lib/libmagic.dylib ] || [ -f /opt/homebrew/lib/libmagic.dylib ]; then
            magic_present=true
        fi
        ;;
    *)
        if ldconfig -p 2>/dev/null | grep -q libmagic; then
            magic_present=true
        fi
        ;;
esac

if [ "$magic_present" != true ]; then
    echo "WARNING: libmagic does not appear to be installed." >&2
    echo "         python-magic needs it for the --skip-binary option." >&2
    echo "         Debian/Ubuntu: sudo apt install libmagic1" >&2
    echo "         macOS/Homebrew: brew install libmagic" >&2
fi

# -- 2. Create and verify the project environment
export UV_PROJECT_ENVIRONMENT=.venv
cd -- "$project_root"
if [ "$recreate" = true ] && { [ -e "$venv_path" ] || [ -L "$venv_path" ]; }; then
    if ! rm -rf -- "$venv_path" || [ -e "$venv_path" ] || [ -L "$venv_path" ]; then
        echo "Error: could not remove '$venv_path'." >&2
        echo 'Manually remove the .venv directory and run this script again.' >&2
        exit 1
    fi
fi
if [ ! -e "$venv_path" ] && [ ! -L "$venv_path" ]; then
    "$uv_bin" venv --seed "$venv_path"
fi
"$uv_bin" sync --locked --inexact
python="$venv_path/bin/python"
if [ ! -f "$python" ]; then
    python="$venv_path/Scripts/python.exe"
fi
if ! "$python" -m pip --version >/dev/null 2>&1; then
    "$python" -m ensurepip --upgrade
fi
constraints="$(mktemp)"
trap 'rm -f -- "$constraints"' EXIT
"$uv_bin" export --locked --no-hashes --no-emit-project --output-file "$constraints"
"$python" -m pip install --constraint "$constraints" --requirement "$project_root/requirements.txt"
"$uv_bin" run python -c 'import pytest; print("pytest", pytest.__version__, "is available.")'

echo
echo "Setup complete. In this shell, run:"
echo "  export UV_PROJECT_ENVIRONMENT=.venv"
echo "  uv run python bin/run-pytest-regression.py"