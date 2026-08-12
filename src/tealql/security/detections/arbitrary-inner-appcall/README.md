# arbitrary-inner-appcall

Reports attacker-controlled `itxn_field ApplicationID` values that are not
constrained by a dominating value or Sender guard.

The detector runs on lifted pre-IR, where call arguments, frame parameters,
returns, scratch flow, and guard dominance are represented explicitly. The
detector name describes policy rather than implementation; there is no parallel
SSA detector or `ir-` alias. If lifting fails, analysis is reported incomplete.
