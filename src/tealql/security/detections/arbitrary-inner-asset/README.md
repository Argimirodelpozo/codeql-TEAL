# arbitrary-inner-asset

Reports attacker-controlled `XferAsset` selectors that can move an arbitrary ASA
from the application. A selector is suppressed when the same lifted inner
transaction returns the asset to a receiver derived from `txn Sender`.

Both taint/guard reasoning and inner-transaction correlation run on lifted
pre-IR. There is no representation-prefixed alias or weaker SSA fallback.
