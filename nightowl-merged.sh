#!/bin/bash
# NightOwl v6.0 — Unified Launcher (All tools merged)
# Usage: ./nightowl-merged.sh <command> [args]
#        Or just: ./nightowl-merged.sh  (interactive wizard)

set -e
WORKSPACE="${WORKSPACE:-/home/ali/shamcash}"
cd "$WORKSPACE"

[ -f "$WORKSPACE/venv/bin/activate" ] && source venv/bin/activate

# All commands go through the unified entry point
python3 nightowl "$@"
