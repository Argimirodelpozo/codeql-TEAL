# Experimental policy obligations

`tealql obligations approval.teal --policy policy.json` checks explicitly supplied
contracts at selected source instructions and prints JSON. Exit 0 means every
requested obligation was proved within its stated scope and assumptions. Exit 2
means an invalid policy, incomplete input, an empty policy, or at least one unknown
obligation. This command is opt-in and does not change the default detector set.

`PROVED` is conditional on reaching the selected instruction successfully. It
does not prove reachability, safe initialization, or whole-contract correctness.
Missing evidence is `UNKNOWN`. The structural revision checker can also return
`REFUTED` when the supplied contracts conflict. No checker constructs an exploit
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

`resource_requirements(program)` adds explicit availability, box, fee, opcode
budget, balance, and recoverability obligations to the existing resource-demand
certificate. Environmental closure and recovery remain unknown. Syntax
classification alone never establishes execution sufficiency. These requirements
and unconfigured box permission sites are available through `tealql dump`.

`tealql.security.compatibility.compare_contracts(before, after)` accepts normalized
maps for `methods`, `storage`, `permissions`, and per-method `effects`. It checks
preservation of old signatures, storage entries and permissions, and prevents
new effects outside the declared old effect set. Every method must declare its
effects. This is a structural comparison of supplied contracts, not automatic
ARC-56 semantic equivalence. It always retains an unknown semantic-migration
obligation.

These are first bounded milestones for the eight research directions. Extending
the supported fragments requires independent controls for negative, ambiguous,
and degraded inputs; removing an `UNKNOWN` result requires new evidence.
