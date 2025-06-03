#!/bin/bash
set -eux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  platform="linux64"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  platform="osx64"
else
  echo "Unknown OS"
  exit 1
fi
cd "$(dirname "$0")/.."

(cd extractor && cargo build --release)

# we are in a cargo workspace rooted at the git checkout
BIN_DIR=extractor/target/release
"$BIN_DIR/codeql-extractor-teal" generate --dbscheme ql/lib/teal.dbscheme --library ql/lib/codeql/teal/ast/internal/TreeSitter.qll

/mnt/c/Users/x/Desktop/TealQL/codeql-linux64/codeql/codeql query format -i ql/lib/codeql/teal/ast/internal/TreeSitter.qll
# codeql query format -i ql/lib/codeql/teal/ast/internal/TreeSitter.qll

rm -rf extractor-pack
mkdir -p extractor-pack
# cp -r codeql-extractor.yml downgrades tools ql/lib/teal.dbscheme ql/lib/teal.dbscheme.stats extractor-pack/
cp -r codeql-extractor.yml tools ql/lib/teal.dbscheme ql/lib/teal.dbscheme.stats extractor-pack/
mkdir -p extractor-pack/tools/${platform}
cp "$BIN_DIR/codeql-extractor-teal" extractor-pack/tools/${platform}/extractor
