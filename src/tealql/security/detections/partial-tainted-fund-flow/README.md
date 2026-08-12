# partial-tainted-fund-flow

Reports the byte-granular validation bypass: one portion of an argument is
validated while different attacker-controlled bytes steer a payment.

SSA byte intervals are carried onto lifted registers through explicit provenance,
then the lifted guard engine handles the sink interprocedurally. Whole-value
findings owned by `tainted-fund-flow` are subtracted. There is one canonical
detector ID and no SSA fallback.
