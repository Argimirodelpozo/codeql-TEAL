# Resource-demand analysis

`tealql.tealtools.resource_demand(main, subs=())` computes a deterministic,
conservative demand certificate from canonical SSA. It reports parameter and
holding fields, existence checks, transaction resource-array observations,
resource-reference forms, foreign application-state reads, box names, and
inner-transaction syntax. Supplied subprograms are all scanned.

The analysis deliberately over-collects. It retains syntactic accesses even
when their results are unused, and an unclassified operation widens the
affected demand while adding an `unknowns` entry. Consequently, unknown means
wider demand or an incomplete certificate, never no demand.

`ResourceDemand.complete` means only that TealQL classified every observed
resource operation. It does **not** mean Accounts, Assets, or Applications are
a closed-world ledger inventory. Account counters and boxes, asset-manager and
existence requirements, inner application calls, and other ledger semantics
can require additional resources even when the program does not read them.

Consumers must independently validate every reported and encoded access and
compute their own semantic closure. The certificate is an optimization hint,
not a trusted soundness assumption. `to_dict()` provides a versioned,
JSON-compatible representation for cross-repository exchange and caching.
