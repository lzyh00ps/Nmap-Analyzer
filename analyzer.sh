#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"

# Load API keys from .env if present
if [ -f "$DIR/.env" ]; then
    set -a
    source "$DIR/.env"
    set +a
fi

"$DIR/venv/bin/python3" "$DIR/nmap_analyzer.py" "$@"
