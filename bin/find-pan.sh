#!/usr/bin/env bash
# =============================================================================
#  File    :   find-pan.sh
#  What    :   Run Find-PAN (bin/find-pan.py) on WSL / Linux / macOS / Git Bash
#              from any directory, in the project's own environment.
#
#  Every argument is passed to find-pan.py unchanged and its exit status is
#  returned (see "Exit status" in the README).  The working directory is NOT
#  changed, so relative --path / --file / --csv values mean what they say in
#  your shell.
#
#      ./bin/find-pan.sh --path /data --mask --summary-json summary.json
#
#  The environment is the one bin/setup-env.sh configures (.venv-linux, or
#  .venv-windows under Git Bash); an existing UV_PROJECT_ENVIRONMENT wins.
#  uv is used when it is installed (it also brings the environment up to
#  date); otherwise the environment's own Python is used if it exists.
# =============================================================================

set -euo pipefail

#   Resolve this script's real location, following symlinks, so the script
#   can be linked from a directory on PATH.
source_path="${BASH_SOURCE[0]}"
while [ -L "$source_path" ]; do
    link_dir="$(cd -P -- "$(dirname -- "$source_path")" && pwd)"
    source_path="$(readlink -- "$source_path")"
    case "$source_path" in
        /*) ;;
        *) source_path="$link_dir/$source_path" ;;
    esac
done
bin_dir="$(cd -P -- "$(dirname -- "$source_path")" && pwd)"
project_root="$(dirname -- "$bin_dir")"
launcher="$bin_dir/find-pan.py"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) default_environment=".venv-windows"; python_relative="Scripts/python.exe" ;;
    *)                    default_environment=".venv-linux";   python_relative="bin/python" ;;
esac
environment="${UV_PROJECT_ENVIRONMENT:-$default_environment}"

#   uv: on PATH, or in the standard installer locations (non-interactive shells often lack them)
uv_bin="$(command -v uv || true)"
if [ -z "$uv_bin" ]; then
    for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /usr/local/bin/uv /opt/homebrew/bin/uv; do
        if [ -x "$candidate" ]; then
            uv_bin="$candidate"
            break
        fi
    done
fi

if [ -n "$uv_bin" ]; then
    export UV_PROJECT_ENVIRONMENT="$environment"
    exec "$uv_bin" run --project "$project_root" python "$launcher" "$@"
fi

#   No uv: use the environment's Python if it has been created.
case "$environment" in
    /*) environment_dir="$environment" ;;
    *)  environment_dir="$project_root/$environment" ;;
esac
if [ -x "$environment_dir/$python_relative" ]; then
    exec "$environment_dir/$python_relative" "$launcher" "$@"
fi

echo "find-pan.sh: uv was not found and there is no environment at $environment_dir." >&2
echo "Install uv (curl -LsSf https://astral.sh/uv/install.sh | sh) and run bin/setup-env.sh." >&2
exit 1
