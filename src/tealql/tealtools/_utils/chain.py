"""Fetch deployed Algorand programs from chain.

:func:`fetch_approval` pulls an app's on-chain approval program (the public mainnet
API) and disassembles its bytecode to TEAL via a local algod. Used by the
cross-contract :func:`tealql.tealtools.xcontract.discover_registry` (auto-build a callee
registry, no hand-written yaml) and by the behavioural-validation tooling.

Network: the public mainnet API for the program bytes, and localnet (:4001) for
disassembly. This is the only network-touching module in the library; everything
else runs offline.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request

# Endpoints are env-overridable so this isn't pinned to the maintainer's setup:
#   TEAL_ALGOD_MAINNET / TEAL_ALGOD_INDEXER — program-bytes sources
#   TEAL_ALGOD_LOCAL   — the algod used for disassembly (needs a real node)
#   TEAL_ALGOD_TOKEN   — its X-Algo-API-Token
# Defaults: public algonode for reads, a localnet on :4001 with the standard
# dev token for disassembly. Resolved at CALL time (via the _* helpers) so a
# test or embedding app can set them without re-importing -- which is also why
# there are no module-level MAINNET/INDEXER/LOCAL constants. Those froze the
# defaults at import time, so a caller reaching for one silently ignored the
# very env override the helper exists to honour (`sweep_probes` imported
# INDEXER and so never saw TEAL_ALGOD_INDEXER).
_DEFAULT_MAINNET = "https://mainnet-api.algonode.cloud"
_DEFAULT_INDEXER = "https://mainnet-idx.algonode.cloud"
_DEFAULT_LOCAL = "http://localhost:4001"
_DEFAULT_TOKEN = "a" * 64


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
