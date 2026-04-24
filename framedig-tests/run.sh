#!/bin/bash
# Build test DBs, run frameProbe.ql on each, dump CSVs. Idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
SEARCH_PATH="$REPO_ROOT/.codeql-extractors"
CODEQL="${CODEQL:-codeql}"

# Pack install once (idempotent).
"$CODEQL" pack install "$ROOT/probes" >/dev/null

for src in "$ROOT"/src/*/; do
  case_name="$(basename "$src")"
  db="$ROOT/dbs/$case_name"
  echo "=== $case_name ==="

  if [ ! -d "$db" ]; then
    "$CODEQL" database create "$db" --overwrite -l teal -s "$src" \
      --search-path "$SEARCH_PATH" 2>&1 | tail -3
  fi

  "$CODEQL" query run --database="$db" \
    --output="$ROOT/dbs/$case_name.bqrs" \
    "$ROOT/probes/frameProbe.ql" 2>&1 | grep -E "Starting|eval|Error" | head -3

  "$CODEQL" bqrs decode --format=csv \
    --output="$ROOT/dbs/$case_name.csv" \
    "$ROOT/dbs/$case_name.bqrs" >/dev/null

  cat "$ROOT/dbs/$case_name.csv"
done
