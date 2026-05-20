# Non-Unique Box Key

**Severity:** high · **Applies to:** application

## What it looks for

A box whose key is derived from a **non-unique external field** without
mixing in anything distinguishing. A box's address space is keyed by an
arbitrary byte string; an ASA's `AssetName` is the canonical non-unique
field — multiple assets can legitimately share a name. If `AssetName`
(or a value derived from it) is used directly as a box key, two
different real-world entities collide on the same box. The mistake
surfaces as silent data overwrites: entity B's box write clobbers
entity A's because they hashed to the same key.

The fix is to mix a unique discriminator into the key — the asset ID,
the creator address, an app-assigned counter — so distinct entities
always land in distinct boxes.

## How it works

A taint analysis over `tealtools.dataflow.TaintAnalysis`:

- **Source** — the value output of `asset_params_get AssetName`.
- **Sinks** — the *key* operand of `box_create` and `box_put` (the
  stack-bottom argument).
- **Flow rules** — the standard propagation set: the taint survives a
  hash (`sha256` / `keccak256` / …), a slice (`extract` / `substring`),
  and `concat`-with-a-constant. Concatenating a *non-constant*
  distinguishing value breaks the flow — that's the intended fix, and
  the detector correctly stops flagging once it's present.

A finding means a tainted `AssetName` reached a box key along one of
those paths.

## Examples

Vulnerable — the detector flags this:

```teal
#pragma version 10
// VULN: ASA name flows directly into box_create + box_put as the key.
// Two ASAs with the same name collide on the same box.

txna ApplicationArgs 0
btoi
asset_params_get AssetName       // (name, exists)
assert                           // pop exists -> stack: [name]
pushint 64
box_create                       // KEY=name, LENGTH=64  <-- VIOLATION
pop

txna ApplicationArgs 0
btoi
asset_params_get AssetName
assert                           // stack: [name]
txna ApplicationArgs 1
box_put                          // KEY=name, VALUE=arg1  <-- VIOLATION

pushint 1
return
```

Fixed — the detector stays quiet:

```teal
#pragma version 10
// SAFE: composite key = itob(asset_id) ++ AssetName.
// asset_id makes the key unique even if two ASAs share a name.

txna ApplicationArgs 0
btoi                              // asset_id (uint64)
dup                               // [id, id]
itob                              // [id, id_bytes]
swap                              // [id_bytes, id]
asset_params_get AssetName        // [id_bytes, name, exists]
assert                            // [id_bytes, name]
concat                            // [id_bytes ++ name]   ← concat blocks taint
pushint 64
box_create
pop

pushint 1
return
```

## Files

- `box_key.py` — the detector (`NonUniqueBoxKeyDetector`), a configured
  `TaintAnalysis`. Run it via `tealtools detections --detector box-key`.

Test fixtures live under `tests/tealtools/box_key/`: `vuln` (direct
flow), `vuln_hash` / `vuln_extract` / `vuln_concat_const` (flow through
each rule), and `safe_id_prefix` (the fixed form — a unique prefix
mixed in, no finding).
