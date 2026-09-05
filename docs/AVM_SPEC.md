# Pinned AVM metadata

The analysis target is AVM 13 at go-algorand `v5.0.0-stable`, commit
`da5946a14568c0cbaa2c9daf4241882de12f3c16`. This is a language target, not a claim
about the activation state of a network. Mechanical facts come from that release's
[`data/transactions/logic` specification](https://github.com/algorand/go-algorand/tree/da5946a14568c0cbaa2c9daf4241882de12f3c16/data/transactions/logic).

`language/op_specs.json` records versioned signatures, immediate fields, field
types and versions, modes, and cost descriptions for AVM 1–13. Input SHA-256
hashes are recorded in the generated artifact and pinned separately in
`tools/avm_sources.sha256.json`. Regenerate from the official source files:

```sh
python tools/generate_avm_spec.py /path/to/data/transactions/logic --check
```

The generator performs no network access and executes no upstream code. It
rejects changed input hashes. Updating the target requires deliberately reviewing
the new upstream revision, hashes, generated differences, and custom transfers.

`language.spec.support_inventory()` separates generic/custom analysis transfers
from opcode presence and unsupported fields in Puya 5.7. Opcode presence is not
a promise of successful lowering for every program. Foreign-box instructions,
`app_params_set`, and `poseidon2` now retain their operands in the frontend and
produce explicit unsupported-backend errors when lowered with Puya 5.7. The
versioned spec also covers the new block and application fields.

Fixed opcode costs now come from the pinned specification without importing
Puya. The existing explicit immediate/length formulas remain in the cost model;
`poseidon2` has its documented base and per-block formula. Dynamic or unsupported
costs remain non-exact. `int`, `byte`, `addr`, and `method` are source-level
pseudo-instructions; the historical `sumhash512` extension is not part of this
pinned consensus opcode inventory.
