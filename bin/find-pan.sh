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
#  FIND_PAN_HOME selects the project root and its .venv. If unset, the
#  parent of this script's bin directory is used.
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
project_root="${FIND_PAN_HOME:-$(dirname -- "$bin_dir")}"
launcher="$project_root/bin/find-pan.py"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) python_relative="Scripts/python.exe" ;;
    *)                    python_relative="bin/python" ;;
esac
environment_dir="$project_root/.venv"

if [ ! -f "$launcher" ]; then
    echo "find-pan.sh: launcher not found at $launcher. Check FIND_PAN_HOME." >&2
    exit 1
fi

if [ -x "$environment_dir/$python_relative" ]; then
    exec "$environment_dir/$python_relative" "$launcher" "$@"
fi

echo "find-pan.sh: Python was not found in $environment_dir." >&2
echo "Run the setup script in $project_root/bin/setup-env.sh." >&2
exit 1
