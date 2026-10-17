#!/usr/bin/env bash
# =============================================================================
#  File    :   setup-env.sh
#  What    :   One-time setup for the Find-PAN project environment on
#              WSL / Linux / macOS.
#
#  Configures uv so that plain `uv` commands (`uv sync`, `uv run`, `uv add`)
#  automatically use a POSIX-specific project environment (`.venv-linux`).
#
#  uv has no pyproject.toml setting for the environment path, but it honors
#  the UV_PROJECT_ENVIRONMENT variable, and a *relative* value is resolved
#  against each project's root.  This script exports the variable for the
#  current session and persists it in the shell's rc file, so every uv
#  project keeps its own platform-named environment directory.  Sharing a
#  checkout between Windows and WSL/Linux then works without either side
#  corrupting the other's environment.
#
#  Run once per platform, then open a NEW shell and use plain uv commands:
#      uv run python bin/run-pytest-regression.py
# =============================================================================

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
environment_name=".venv-linux"

#   Which rc file persists the variable for interactive shells
rc_file="$HOME/.bashrc"
case "$(basename -- "${SHELL:-/bin/bash}")" in
    zsh) rc_file="$HOME/.zshrc" ;;
esac

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

# -- 2. Persist the per-platform environment name for this shell
configure_line="export UV_PROJECT_ENVIRONMENT=\"${environment_name}\""
if [ -f "$rc_file" ] && grep -Fq "UV_PROJECT_ENVIRONMENT" "$rc_file"; then
    if grep -Fq "$configure_line" "$rc_file"; then
        echo "$rc_file is already configured."
    else
        echo "WARNING: $rc_file sets UV_PROJECT_ENVIRONMENT to a different value." >&2
        echo "         Review it so it matches: $configure_line" >&2
    fi
else
    {
        echo ""
        echo "# Per-platform uv project environment (added by Find-PAN bin/setup-env.sh)"
        echo "$configure_line"
    } >>"$rc_file"
    echo "Appended UV_PROJECT_ENVIRONMENT to $rc_file."
fi

export UV_PROJECT_ENVIRONMENT="$environment_name"
echo "UV_PROJECT_ENVIRONMENT=$environment_name is active for this session."
echo "Every uv project keeps its own $environment_name directory."
echo "Note: non-interactive shells (scripts, CI) must export the variable themselves."

# -- 3. Create and verify the project environment
cd -- "$project_root"
"$uv_bin" sync
"$uv_bin" run python -c 'import pytest; print("pytest", pytest.__version__, "is available.")'

# -- 4. Clean up a legacy shared .venv, if any (superseded by the
#      per-platform environment; safe to remove with `uv sync` recreating it)
legacy="$project_root/.venv"
if [ -e "$legacy" ]; then
    rm -rf -- "$legacy"
    echo "Removed legacy .venv (replaced by $environment_name)."
fi

echo
echo "Setup complete. Open a NEW shell, then:"
echo "  uv run python bin/run-pytest-regression.py"