"""Fetch deployed Algorand programs from chain.

:func:`fetch_approval` pulls an app's on-chain approval program (the public mainnet
API/indexer) and disassembles its bytecode to TEAL via a local algod. Used by the
cross-contract :func:`tealtools.xcontract.discover_registry` (auto-build a callee
registry, no hand-written yaml) and by the behavioural-validation tooling.

Network: the public mainnet API/indexer for the program bytes, and localnet
(:4001) for disassembly. This is the only network-touching module in the library;
everything else runs offline.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request

logger = logging.getLogger("tealtools.chain")

# Endpoints are env-overridable so this isn't pinned to the maintainer's setup:
#   TEAL_ALGOD_MAINNET / TEAL_ALGOD_INDEXER — program-bytes sources
#   TEAL_ALGOD_LOCAL   — the algod used for disassembly (needs a real node)
#   TEAL_ALGOD_TOKEN   — its X-Algo-API-Token
# Defaults: public algonode for reads, a localnet on :4001 with the standard
# dev token for disassembly. Resolved at CALL time (via the _* helpers) so a
# test or embedding app can set them without re-importing.
_DEFAULT_MAINNET = "https://mainnet-api.algonode.cloud"
_DEFAULT_INDEXER = "https://mainnet-idx.algonode.cloud"
_DEFAULT_LOCAL = "http://localhost:4001"
_DEFAULT_TOKEN = "a" * 64

# Back-compat module constants (the defaults); prefer the _* accessors, which
# honour the env overrides.
MAINNET = _DEFAULT_MAINNET
INDEXER = _DEFAULT_INDEXER
LOCAL = _DEFAULT_LOCAL


def _mainnet() -> str:
    return os.environ.get("TEAL_ALGOD_MAINNET", _DEFAULT_MAINNET)


def _indexer() -> str:
    return os.environ.get("TEAL_ALGOD_INDEXER", _DEFAULT_INDEXER)


def _local() -> str:
    return os.environ.get("TEAL_ALGOD_LOCAL", _DEFAULT_LOCAL)


def _token() -> str:
    return os.environ.get("TEAL_ALGOD_TOKEN", _DEFAULT_TOKEN)


def _get(url, data=None, ctype=None, token=None):
    req = urllib.request.Request(url, data=data)
    if ctype:
        req.add_header("Content-Type", ctype)
    if token:
        req.add_header("X-Algo-API-Token", token)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


def sample_app_ids(n=60):
    """A diverse batch of mainnet app ids (a few known protocols + indexer pages)."""
    ids = [1002541853, 971350278, 818179346, 605929989,
           971368268, 818176933, 354073718, 1284326447]
    ranges = ("", "1000000", "50000000", "100000000", "300000000", "600000000",
              "900000000", "1200000000", "1400000000", "1700000000", "2000000000", "2500000000")
    for after in ranges:
        try:
            q = f"{_indexer()}/v2/applications?limit=8" + (f"&next={after}" if after else "")
            d = json.loads(_get(q))
            ids += [a["id"] for a in d.get("applications", []) if not a.get("deleted")]
        except Exception as e:
            logger.debug("indexer page %r failed: %s", after or "first", e)
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out[:n]


def fetch_approval(app_id):
    """``(teal_text, deployed_bytecode)`` for an app's approval program. The
    bytecode is the on-chain program; keep it so a behavioural compare can dryrun
    it DIRECTLY (some valid contracts don't survive a disassemble -> reassemble
    round-trip through the strict assembler)."""
    d = json.loads(_get(f"{_mainnet()}/v2/applications/{app_id}"))
    bytecode = base64.b64decode(d["params"]["approval-program"])
    if not bytecode:
        raise ValueError("no approval program")
    resp = _get(f"{_local()}/v2/teal/disassemble", data=bytecode,
                ctype="application/x-binary", token=_token())
    return json.loads(resp)["result"], bytecode   # algod returns {"result": "<teal>"}
