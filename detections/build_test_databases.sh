#!/bin/bash
# Build all CodeQL databases for sec-guide detection test contracts.
# Run from the repository root.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEARCH_PATH="$REPO_ROOT/.codeql-extractors"
DETECTIONS_DIR="$REPO_ROOT/detections"
DB_DIR="$REPO_ROOT/detections-dbs"

mkdir -p "$DB_DIR"

DETECTIONS=(
  rekey-to close-remainder-to asset-close-to
  fee-validation tx-type-check group-size-check
  is-updatable unprotected-updatable
  is-deletable unprotected-deletable
  delete-funds-check
  inner-txn-fee inner-txn-close-rekey
  asset-id-validation
  hardcoded-min-balance
  unsafe-lsig-args
  timelock-upgrade
)

for dir in "${DETECTIONS[@]}"; do
  # Prefer real-world gabe_* pairs when present; fall back to vuln/fixed.
  for variant in gabe_vuln gabe_fixed vuln fixed; do
    teal_file="$DETECTIONS_DIR/$dir/${variant}.teal"
    if [ ! -f "$teal_file" ]; then
      echo "SKIP $dir/$variant (no ${variant}.teal)"
      continue
    fi

    src_dir="$DB_DIR/$dir/${variant}-src"
    db="$DB_DIR/$dir/${variant}-db"

    mkdir -p "$src_dir"
    cp "$teal_file" "$src_dir/${variant}.teal"

    echo "Building $dir/$variant..."
    codeql database create "$db" --overwrite -l teal -s "$src_dir" \
      --search-path "$SEARCH_PATH" 2>&1 | grep -E "Successfully|Error" | head -1
  done
done

echo "All databases built."
