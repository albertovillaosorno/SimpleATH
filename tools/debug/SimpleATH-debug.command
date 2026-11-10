#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Finder launcher. The Python collector enforces administrator access.
set -eu
SCRIPT_DIRECTORY="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then
    printf '%s\n' 'Python 3.9 or newer is required. Use the Python from your macOS development setup.' >&2
    exit 1
fi
exec "$PYTHON_BIN" "$SCRIPT_DIRECTORY/simpleath_debug.py" "$@"
