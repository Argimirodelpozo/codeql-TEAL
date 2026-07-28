"""Fetch deployed Algorand programs from chain — the public mainnet API for the
program bytes, a local algod (:4001) for disassembly.

This is the ONLY network-touching module in the library; everything else runs
offline.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request

# Endpoints are env-overridable: TEAL_ALGOD_MAINNET / TEAL_ALGOD_INDEXER (program
# bytes), TEAL_ALGOD_LOCAL + TEAL_ALGOD_TOKEN (the algod used for disassembly).
# Resolved at CALL time via the _* helpers, and deliberately NOT exposed as
# module-level constants: those froze the defaults at import, so any caller
# reaching for one silently ignored the env override.
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
    """``(teal_text, deployed_bytecode)`` for an app's approval program — the
    bytecode is returned so a behavioural compare can dryrun the ON-CHAIN program
    directly, since some contracts don't survive a disassemble -> reassemble
    round-trip through the strict assembler."""
    d = json.loads(_get(f"{_mainnet()}/v2/applications/{app_id}"))
    bytecode = base64.b64decode(d["params"]["approval-program"])
    if not bytecode:
        raise ValueError("no approval program")
    resp = _get(f"{_local()}/v2/teal/disassemble", data=bytecode,
                ctype="application/x-binary", token=_token())
    return json.loads(resp)["result"], bytecode   # algod returns {"result": "<teal>"}
