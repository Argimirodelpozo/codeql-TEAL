#!/usr/bin/env bash
# Build ttreplay inside a go-algorand checkout of d13co/go-algorand@timetravel
# (any recent go-algorand works; the time-travel node is only queried over REST).
#
#   GO_ALGORAND_DIR=~/tools/go-algorand-timetravel tests/replay_harness/ttreplay/build.sh
#
# The checkout needs its libsodium fork built once (`make crypto/libs`, or copy
# crypto/libs from another built checkout). Output: $GO_ALGORAND_DIR/ttreplay.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${GO_ALGORAND_DIR:?set GO_ALGORAND_DIR to a go-algorand checkout}"
mkdir -p "$dir/cmd/ttreplay"
cp "$here"/*.go "$dir/cmd/ttreplay/"
cd "$dir"
GOTOOLCHAIN=auto go build -o ttreplay ./cmd/ttreplay
echo "built $dir/ttreplay"
