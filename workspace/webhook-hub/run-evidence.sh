#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
REPORT=${REPORT:-evidence-report.json}
TTL=${TTL:-2}
python3 -m whub evidence --ttl "$TTL" --report "$REPORT"
