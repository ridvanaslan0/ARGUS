#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
EXE="$ROOT/build/argus"

if [ ! -x "$EXE" ]; then
    printf '\n  [X] Binary not found: %s\n' "$EXE"
    printf '      Build it first:  ./build.sh\n\n'
    read -r -p '  press enter to close...' _
    exit 1
fi

export TERM="${TERM:-xterm-256color}"

if [ "$#" -eq 0 ]; then
    "$EXE" run
else
    "$EXE" "$@"
fi

printf '\n'
if [ -t 0 ]; then
    read -r -p '  press enter to close...' _ || true
fi
