# Experimental policy obligations

`tealql obligations approval.teal --policy policy.json` checks explicitly supplied
contracts at selected source instructions and prints JSON. Exit 0 means every
requested obligation was proved within its stated scope and assumptions. Exit 2
means an invalid policy, incomplete input, an empty policy, or at least one unknown
obligation. This command is opt-in and does not change the default detector set.

`PROVED` is conditional on reaching the selected instruction successfully. It
does not prove reachability, safe initialization, or whole-contract correctness.
Missing evidence is `UNKNOWN`. The revision checkers can also return
`REFUTED` for conflicting declared contracts or differing constant execution outcomes. No checker constructs an exploit
or submits transactions.

The implementation shares immutable facts, path predicates, instruction identities,
effect roles, and `GuardEvidence` with the existing analysis layers. The bounded
difference-constraint solver admits `x - y <= c`, composes transitive bounds, and
refuses inconsistent premises or more than 64 atoms. Multiplication of two
variables, disjunctions, and general nonlinear arithmetic remain unknown.

## Policy format

An expression is an integer, a field such as `"txn Fee"`, `"global LatestTimestamp"`
or `"gtxn 0 Amount"`, a byte constant such as `"bytes:0x616263"`, an expression
`["+", expression, expression]` (also `-` or constant multiplication), or a source
value reference `{"line": 12, "output": 1}`. Output positions use public SSA's
top-first, one-based order. Different reads of mutable storage retain distinct
identities. All source points belong to the one input file.

The top-level keys are optional lists, except `initial_authorities`, which lists
initially trusted keys. An empty policy cannot return complete.

| Key | Required entries and bounded interpretation |
| --- | --- |
| `authority` | Global-key names. Every static writer must have a creator guard; any dynamic global-key writer prevents proof. `initial_authorities` explicitly supplies the trusted initial-state premise. Deletions count as writes. Initialization inference, delegated authority cycles, and upgrade preservation are not inferred. |
| `groups` | `line`, `size` (1–16), `members` (every index as a string, with `TypeEnum` and intended field bindings), and a nonempty `relations` list of `[left, relation, right]`. Relations are `eq`, `neq`, `lt`, `le`, `gt`, `ge`. The group size and every supplied binding must hold at the selected instruction. The user defines the complete application-specific policy. |
| `crypto` | `line` (use), `verify_line`, `public_key`, `domain`, ordered `fields` (`value`, `width`), and nonempty `assumptions`. Requires an accepted Ed25519 verification with the specified key, and exact fixed-width fields through concat, itob, and supported hashes. Cryptographic strength, replay-domain adequacy, and authority of the key are declared assumptions. Substrings and variable-width encodings are unsupported. |
| `lifecycle` | `line`, `proposal_line`, `proposed_at_line`, `delay`, and `authority`. Requires UpdateApplication, the intended approval-program proposal, elapsed time from the exact proposal-time read, and sender authorization. The two reads must use constant global keys. Atomic trusted proposal/time writes and clear-program policy remain assumptions. |
| `conservation` | `line`, `unit`, `left`, `right`. Checks the supplied linear identity. Additional rounding results distinguish exact uint64 division from possible floor loss. This does not infer units, beneficiaries, economic conservation, or absence of overflow failures. |
| `authority_uses` | `read_line`, `output` (default 1), `line` (guarded use). Combines authority provenance with an inferred read-to-use window containing no possibly aliasing writer. Storage reads require an acyclic, call-free program; initial authority and revision preservation remain premises. |
| `funding_groups` | `line`. Infers a fixed funding prefix: every preceding group member is a payment from the caller to the current app, the current call is the last member and NoOp, and close/rekey fields are constrained. Group size and all parties must follow from actual guards. |
| `payment_conservation` | `line` of an inner submit. Infers the funding prefix and actual inner payment fields, then proves equality of gross incoming/outgoing ALGO amounts by bounded linear elimination. Requires one basic block, current-app debits and explicit zero inner fees. Recipient authorization and spendable balance remain separate. |
| `replay` | All `crypto` fields plus `read_line` and `consume_line`. Requires a zero-checked global key, accepted signature before consumption, marker 1 before the selected use, signed dynamic key fields, and every potentially aliasing writer to preserve marker 1. No reset, deletion, loop or external call is admitted. Initial key persistence across revisions remains a premise. |
| `proposal_invariants` | All `lifecycle` fields. Infers every writer of the exact proposal/time keys: each block must write both once, under creator authorization, with the current timestamp. Neither key may change between the selected reads and upgrade. Initial pair consistency, future revisions and clear-program binding remain separate. |

For example, a program that asserts a one-member application-call group and caps
its fee can request:

```json
{
  "groups": [{
    "line": 15,
    "size": 1,
    "members": {"0": {"TypeEnum": 6}},
    "relations": [["gtxn 0 Fee", "le", 1000]]
  }]
}
```

The line must identify an instruction after the assertions. A fee bound on one
branch does not prove the obligation on another branch or at their join.

## Additional Python APIs

`tealql.tealtools.analysis.box_permissions` takes a closed list of
`BoxApplication` identities and `BoxCallFrame` values. `box_permission` checks
owner, foreign-read and family access permissions, including marked family
ancestors separated by non-family frames. `inherit_family_mark` handles a
matched return. `box_access_permissions` joins static source accesses with an
explicit application-reference mapping. Missing identities are incomplete.
The result names the owner responsible for balance obligations; it does not
prove resource availability or sufficient balance. The protocol rules are pinned
to AVM 13; see the official [box specification](https://dev.algorand.co/concepts/smart-contracts/storage/box/).

`trace_box_permissions(programs, apps, root, application_refs=...)` derives the
call frames and family marks from straight-line program bodies. `programs` maps
application IDs to SSA programs; `application_refs` maps each executing app's
reference operands to actual owner IDs. The root is an outer approval with no
active caller frames. Constant inner NoOp calls are followed,
and matched returns propagate marks only to callers with the same creator.
Missing targets, recursion, mutable permission flags and conditional control
flow make the trace incomplete. Access results are conditional on reaching the
site; a known permission denial terminates that path without claiming approval.

`resource_requirements(program)` adds explicit availability, box, fee, opcode
budget, balance, and recoverability obligations to the existing resource-demand
certificate. Environmental closure and recovery remain unknown. Syntax
classification alone never establishes execution sufficiency. These requirements
and unconfigured box permission sites are available through `tealql dump`.

`tealql.tealtools.analysis.resource_sufficiency.resource_sufficiency(program,
environment, retry=None)` adds quantitative bounds for a straight-line outer
approval under the pinned AVM 13 protocol. The environment supplies
`opcode_budget`, `fee_credit` remaining after outer minimum fees,
`spendable_balance` above the initial minimum balance, `box_io_budget`, and
`inner_transaction_credit` remaining in the pooled count (defaults to zero), plus
`boxes` mapping canonical hex names to initial sizes (`null` for an absent but
available box). Missing credit yields unknown bounds; missing box state or an
unsupported operation makes the whole resource fragment incomplete.

```python
from tealql.tealtools.analysis.resource_sufficiency import resource_sufficiency
from tealql.tealtools.ssa import SSAProgram

program = SSAProgram.from_text('''#pragma version 13
byte "k"
byte "abc"
box_put
int 1
return
''')
environment = dict(opcode_budget=700, fee_credit=0, spendable_balance=4100,
                   box_io_budget=2048, boxes={'0x6b': None})
report = resource_sufficiency(program, environment)
assert report.complete
assert all(bound.status == 'PROVED' for bound in report.value)
```

Bounds retain allocation peaks before deletion, box values read before a resize,
constant inner payment fees/debits, stack depth and log limits. Opcode cost
includes two possible assembler-generated constant-table initializers. A
supplied `retry` environment can prove resource coverage with the same initial
box state. It cannot establish that a caller can obtain the extra credit or that
the application will accept the retry. See [SAST_INFERENCE.md](SAST_INFERENCE.md)
for the operation fragment and conservative accounting rules.

`tealql dump --list-views` includes `analysis.authority`, `analysis.congruences`,
`analysis.numeric_calls`, `analysis.resource_bounds` and
`analysis.xcontract_health`. The resource view retains unknown environmental
credit, and the call-health view requires an AppID registry. Neither invents a
closed environment to turn an unknown into a proof.

`tealql.security.compatibility.compare_contracts(before, after)` accepts normalized
maps for `methods`, `storage`, `permissions`, and per-method `effects`. It checks
preservation of old signatures, storage entries and permissions, and prevents
new effects outside the declared old effect set. Every method must declare its
effects. This is a structural comparison of supplied contracts, not automatic
ARC-56 semantic equivalence. It always retains an unknown semantic-migration
obligation.

`tealql.security.compatibility.compare_programs(before, after)` compares actual
SSA program implementations in a bounded straight-line fragment. It normalizes
literal arithmetic and stack copies while retaining ordered effects, possible
traps and exported scratch. Equal canonical traces or equal fully constant
outcomes yield `PROVED`; different fully constant approval/log outcomes yield
`REFUTED`. Other differences remain `UNKNOWN`. Both revisions need the same AVM
version, identical existing-app NoOp inputs/state and sufficient resources.
Program-hash-bound verification, opcode-budget observations, program metadata,
external calls, branches and loops are unsupported. This proof does not replace
ABI/storage contracts or establish a safe migration.

These are bounded implemented fragments for the eight research directions. Extending
the supported fragments requires independent controls for negative, ambiguous,
and degraded inputs; removing an `UNKNOWN` result requires new evidence.
