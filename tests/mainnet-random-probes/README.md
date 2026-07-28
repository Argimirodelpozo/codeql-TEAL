# Mainnet random probes

Real deployed mainnet approval programs (disassembled TEAL), accumulated as a
behavioural regression corpus for the decompiler/lift. Each `app_<id>.teal` is
the on-chain approval program of application `<id>`.

Populated by `python -m tests.behavioral_lift.sweep_probes [count]`, which samples
diverse mainnet apps, saves their TEAL here, and dryruns the lift against each
contract's **deployed bytecode**. Contracts that surfaced lift bugs are kept here
permanently so the fix stays covered. Teal only — no DB, no bytecode.

## Deduplication

Probes are kept only when their CONTENT is new. Skipping by app id is not
enough: mainnet templates are deployed thousands of times under different ids,
so id-only dedup grew this directory to 929 files holding **141 distinct
programs**. That redundancy costs more than disk — it skews any corpus-wide
measurement toward whichever template happens to be popular, so a detector that
fires once on the most-deployed template looks like it fires on 15% of "the
corpus". `sweep_probes` now hashes the disassembled TEAL before saving, and
`tests/mainnet_ratchet.py` keys everything on the content hash.
