#!/usr/bin/env bash
# Run CodeQL qltests for this pack from detections/; ROOT is the repo root (parent of this dir).
#
# CODEQL_EXTRACTOR_TEAL_ROOT: folder that contains codeql-extractor.yml and tools/<platform>/extractor.
#   Use .codeql-extractors/teal (same layout as build_test_databases.sh). codeql-backend/teal/extractor-pack is identical.
#
# Search path: use ONLY .codeql-extractors here. Adding --search-path=. makes CodeQL see multiple
#   "teal" extractors (codeql-backend/teal/, codeql-backend/teal/extractor-pack/, .codeql-extractors/teal) and extraction fails with
#   "Extractors for 'teal' are found in several same-priority locations".
#
# Requires: codeql on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export CODEQL_EXTRACTOR_TEAL_ROOT="${CODEQL_EXTRACTOR_TEAL_ROOT:-$ROOT/.codeql-extractors/teal}"

cd "$ROOT"

# detections depends on argimirodelpozo/teal-all (codeql-backend/teal/ql/lib).
exec codeql test run detections/ \
  --search-path="$ROOT/.codeql-extractors" \
  --additional-packs="$ROOT/codeql-backend/teal/ql/lib" \
  --learn \
  "$@"
