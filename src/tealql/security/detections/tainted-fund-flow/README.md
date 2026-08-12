# tainted-fund-flow

Reports attacker-controlled values reaching inner-payment and asset-transfer
fund fields without a dominating value or Sender guard.

This is the canonical lifted pre-IR policy. Interprocedural parameters, returns,
validation helpers, post-dominating assertions, and scratch round trips are all
handled at that representation. The old SSA implementation and `ir-` alias were
removed; a failed lift produces an incomplete-analysis notification.
