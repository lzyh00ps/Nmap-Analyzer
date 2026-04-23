#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/venv/bin/python3" "$DIR/nmap_analyzer.py" "$@"
