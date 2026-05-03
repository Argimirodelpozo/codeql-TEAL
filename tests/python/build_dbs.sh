#!/bin/bash
# Build CodeQL DBs for every python-analysis fixture under tests/python/.
# Walks each <dir>/prog.teal and creates <dir>/db if absent. Idempotent.
#
# Override codeql with CODEQL=/path/to/codeql ./build_dbs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
SEARCH_PATH="$REPO_ROOT/.codeql-extractors"
CODEQL="${CODEQL:-codeql}"

force=0
[ "${1:-}" = "--force" ] && force=1

while IFS= read -r -d '' prog; do
  src="$(dirname "$prog")"
  db="$src/db"
  case_name="${src#$ROOT/}"

  if [ -d "$db" ] && [ "$force" -eq 0 ]; then
    echo "skip  $case_name  (db exists; --force to rebuild)"
    continue
  fi

  echo "build $case_name"
  "$CODEQL" database create "$db" --overwrite -l teal -s "$src" \
    --search-path "$SEARCH_PATH" 2>&1 | tail -2
done < <(find "$ROOT" -name prog.teal -print0 | sort -z)
