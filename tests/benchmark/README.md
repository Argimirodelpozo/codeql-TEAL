# Detector precision/recall corpus

Ground-truth-labeled TEAL that measures detector quality as a number
(precision / recall / F1). Layout:

```
tests/benchmark/<detector>/
  vuln/*.teal    # contracts the detector SHOULD flag  (a miss = false negative)
  safe/*.teal    # contracts it should NOT flag         (a flag = false positive)
```

`<detector>` is the kebab-case name from `tealql detections --list`.

## Running

```bash
pytest tests/test_benchmark.py -s        # prints the confusion table
python -m tests.gen_precision            # regenerates docs/PRECISION.md
```

`test_benchmark.py` pins every detector's `(TP, FP, FN, TN)` in `_BASELINE`, so
a detector change (or a new fixture) fails the test until you update the
baseline **deliberately** — that is the point: behaviour changes are reviewed,
not silent.

## Adding a case (do this to grow the numbers)

1. Drop a `.teal` under the right `vuln/` or `safe/` dir. Make it **minimal and
   faithful** — a real representation of the pattern, not a contrived trigger.
   The highest-value additions are:
   - **`safe/` cases that STRESS false positives** — a contract that validates
     the field in a valid-but-unusual way (in a subroutine, on one branch, via
     an equivalent idiom). A detector that stays quiet on these earns its
     precision; one that fires reveals a real FP.
   - **`vuln/` cases that STRESS recall** — the vulnerability expressed in a way
     that's easy to miss (obfuscated, interprocedural, behind a dispatch).
2. Run `pytest tests/test_benchmark.py -s` and read the new row. Confirm the
   detector fires (vuln) / stays quiet (safe) **as you intended**. If it does
   the opposite, either the fixture is mislabeled (fix it) or you have found a
   real detector limitation — record it honestly by updating `_BASELINE` with
   the true FP/FN and note why in the commit.
3. Update `_BASELINE` in `test_benchmark.py` and regenerate `docs/PRECISION.md`.

Perfect scores on a curated corpus are a **specification**, not a field
false-positive rate (see the caveat in `docs/PRECISION.md`). The way the number
becomes representative is harder cases — especially adversarial `safe/` ones.
