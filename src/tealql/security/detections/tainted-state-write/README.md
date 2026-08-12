# tainted-state-write

Reports attacker-controlled keys of global/local state and box mutations. The
value is deliberately not a sink: accepting user data is normal; letting users
choose an unguarded destination slot is the security issue. Evaluated on lifted
pre-IR.

