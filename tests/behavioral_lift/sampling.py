"""Sample diverse mainnet app ids from the public indexer.

Split out of :mod:`sweep_probes` so it can be used without dragging in the
dryrun machinery (and therefore ``algosdk``): picking ids is pure indexer
paging, and :mod:`fetch_mainnet` needs only that.

Replaces an earlier ``chain.sample_app_ids``, which paged from a FIXED set of
cursors and so returned the same ids on every run — see the accounting in
RESULTS.md, where five overnight batches spent 300 fetches to obtain 60 distinct
apps. Cursors here are denser and pagination is followed per cursor, so repeat
sweeps reach genuinely new contracts.
"""
from __future__ import annotations

import json
import urllib.request

from tealql.tealtools._utils.chain import _indexer

# Diverse cursors across the whole id space (early -> newest); dense so a sweep
# pulls a broad, varied sample. The indexer paginates from each cursor, so more
# cursors => more distinct apps per run.
CURSORS = (
    "", "100000", "1000000", "10000000", "31000000", "60000000", "90000000",
    "120000000", "160000000", "250000000", "400000000", "550000000",
    "700000000", "850000000", "1050000000", "1300000000", "1600000000",
    "1900000000", "2200000000", "2500000000", "2800000000", "3100000000",
    "3300000000", "3450000000", "3500000000", "3550000000", "3600000000",
)


def sample(per_cursor: int = 8, pages: int = 1, skip: "set | None" = None) -> list:
    """App ids sampled from each cursor, INTERLEAVED round-robin across cursors so
    the result spans the whole id space evenly (a caller fetching a prefix gets a
    mix of old/new apps -> diverse AVM versions, not all the oldest first).
    ``pages`` follows the indexer's ``next-token`` that deep per cursor (so repeat
    sweeps reach genuinely new apps); ``skip`` drops ids already known."""
    skip = skip or set()
    seen: set = set()
    per: list = []                                # one id-list per cursor
    for after in CURSORS:
        token, lst = after, []
        for _ in range(pages):
            try:
                q = (f"{_indexer()}/v2/applications?limit={per_cursor}"
                     + (f"&next={token}" if token else ""))
                d = json.loads(urllib.request.urlopen(q, timeout=25).read())
            except Exception as e:  # pragma: no cover - network
                print(f"  cursor {after!r} err: {str(e)[:40]}", flush=True)
                break
            for a in d.get("applications", []):
                i = a["id"]
                if not a.get("deleted") and i not in seen and i not in skip:
                    seen.add(i)
                    lst.append(i)
            token = d.get("next-token")
            if not token:
                break
        per.append(lst)
    out = []                                      # round-robin merge
    for col in range(max((len(x) for x in per), default=0)):
        for lst in per:
            if col < len(lst):
                out.append(lst[col])
    return out
