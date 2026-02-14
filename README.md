# TealQL 

TealQL is an SAST powered by GitHub Advanced Security's CodeQL, bringing the latest in Static Analysis tooling to the Algorand Virtual Machine's native language.

## Quick Start (macOS)

### 1. Clone the Repository

```bash
git clone https://github.com/Argimirodelpozo/codeql-TEAL.git 
cd codeql-TEAL
```

### 2. Build the TEAL Extractor

The script handles dependency linking and permissions automatically:

```bash
cd teal/scripts
./create-extractor-pack.sh
cd ../..
```

### 3. Register Extractor for CodeQL

```bash
rm -rf .codeql-extractors
mkdir -p .codeql-extractors/teal
cp -R teal/extractor-pack/* .codeql-extractors/teal/
```

### 4. Create a CodeQL Database

```bash
rm -rf test-projects/db1 && codeql database create test-projects/db1 --overwrite -l teal -s test-projects/your-teal-project --search-path "$(pwd)/.codeql-extractors" --verbosity=progress
```

### 5. Run a Query

**CLI:**
```bash
codeql query run teal/ql/lib/codeql/missingTxnFeeValidation.ql --database test-projects/db1
```

**Or use the CodeQL VS Code extension** for an interactive UI experience.

---

## Features Coming Soon

## How to Contribute

## Rebuilding Extractors

When encountering parsing errors, a grammar update is probably needed.

1. Fix the appropriate rule in the grammar
2. Commit and push to main
3. Rebuild:

```bash
cd teal/scripts
./create-extractor-pack.sh
```

This will rebuild the Rust extractor, regenerate `teal.dbscheme` and `TreeSitter.qll`, and move them into the correct folders.

---

Made with love.

If you're into this kind of stuff, check out [TEALFuzz]() — a custom fuzzer for TEAL programs that uses TealQL to aid in fuzzing campaign setup.
