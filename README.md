# TealQL 

TealQL is an SAST powered by Github Advanced Security's CodeQL, bringing the latest in Static Analysis tooling to the Algorand Virtual Machine's native language.

## Instalation

## Database creation

```
codeql database create --overwrite --search-path codeql/teal/extractor-pack -l teal test-projects/db1 -s test-projects/
```

## Usage

## Features coming soon!

## How to contribute

## 

Made with love.
If you are into this kind of stuff you may also go check: [TEALFuzz](), a custom made fuzzer for TEAL programs that makes use of TealQL to aid in the creation of a fuzzing campaign setup.

## Others: rebuilding extractors
When encountering parsing errors, a grammar update is probably needed.\
Fix the appropriate rule in the grammar, commit and push to main.\
Then, move to the scripts folder and do:

```bash
./create-extractor-pack.sh
```

This will rebuild the rust extractor, regenerate `teal.dbscheme`, `TreeSitter.qll`, and move them into the correct folders.