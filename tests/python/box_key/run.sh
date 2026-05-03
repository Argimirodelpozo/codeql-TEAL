#!/bin/bash
# Build CodeQL DBs for each test case and run the non-unique-box-key
# detector. Idempotent — re-running on existing DBs just re-evaluates.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../../.." && pwd)"
SEARCH_PATH="$REPO_ROOT/.codeql-extractors"
CODEQL="${CODEQL:-codeql}"

for src in "$ROOT"/*/; do
  case_name="$(basename "$src")"
  [ "$case_name" = "probes" ] && continue
  [ ! -f "$src/prog.teal" ] && continue
  db="$src/db"
  echo "=== $case_name ==="

  if [ ! -d "$db" ]; then
    "$CODEQL" database create "$db" --overwrite -l teal -s "$src" \
      --search-path "$SEARCH_PATH" 2>&1 | tail -2
  fi

  python3 - "$db" "$case_name" <<'PYEOF'
import sys, os
os.environ.setdefault("CODEQL", "/home/argi/tools/codeql/codeql")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python-analysis"))
from teal_ssa import SSAProgram
from teal_nonunique_box_key import NonUniqueBoxKeyDetector

db_path, case_name = sys.argv[1], sys.argv[2]
prog = SSAProgram(db_path)
violations = NonUniqueBoxKeyDetector(prog).detect()
print(f"  {len(violations)} violation(s)")
for v in violations:
    print("   ", v.pretty())
PYEOF
  echo
done
