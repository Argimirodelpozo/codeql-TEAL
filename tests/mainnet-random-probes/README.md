# Mainnet random probes

Real deployed mainnet approval programs (disassembled TEAL), accumulated as a
behavioural regression corpus for the decompiler/lift. Each `app_<id>.teal` is
the on-chain approval program of application `<id>`.

Populated by `python -m tools.behavioral_lift.sweep_probes [count]`, which samples
diverse mainnet apps, saves their TEAL here, and dryruns the lift against each
contract's **deployed bytecode**. Contracts that surfaced lift bugs are kept here
permanently so the fix stays covered. Teal only — no DB, no bytecode.
