"""Robustness fixes: chain endpoint config (C5) + parse thread-safety (C6)."""
from __future__ import annotations

import concurrent.futures
from pathlib import Path

from tealql.tealtools.ssa import SSAProgram

TESTS_ROOT = Path(__file__).resolve().parent
SAMPLE = TESTS_ROOT / "benchmark" / "rekey-to" / "vuln" / "no_check.teal"


# --- C5: chain endpoints are env-overridable, not hardcoded ------------------


def test_chain_endpoints_env_overridable(monkeypatch):
    from tealql.tealtools._utils import chain
    # Defaults hold with no env.
    monkeypatch.delenv("TEAL_ALGOD_LOCAL", raising=False)
    monkeypatch.delenv("TEAL_ALGOD_TOKEN", raising=False)
    assert chain._local() == chain._DEFAULT_LOCAL
    assert chain._token() == chain._DEFAULT_TOKEN
    # Overrides are honoured at call time.
    monkeypatch.setenv("TEAL_ALGOD_LOCAL", "http://algod.internal:9999")
    monkeypatch.setenv("TEAL_ALGOD_TOKEN", "deadbeef")
    monkeypatch.setenv("TEAL_ALGOD_MAINNET", "https://my-node.example")
    assert chain._local() == "http://algod.internal:9999"
    assert chain._token() == "deadbeef"
    assert chain._mainnet() == "https://my-node.example"


# --- C6: parsing is thread-safe (per-thread tree-sitter Parser) --------------


def test_parse_nodes_thread_safe():
    from tealql.tealtools.ast.parse import parse_nodes
    srcs = {f"c{i}.teal": SAMPLE.read_text() for i in range(4)}
    # Baseline: node count parsing each single-threaded.
    baseline = {name: len(parse_nodes({name: text})) for name, text in srcs.items()}

    def work(item):
        name, text = item
        return name, len(parse_nodes({name: text}))

    # Hammer the parser from several threads; a shared non-reentrant Parser
    # would corrupt results (wrong/short node lists) under contention.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for _ in range(20):
            results = dict(ex.map(work, list(srcs.items())))
            assert results == baseline


def test_ssa_build_thread_safe():
    # End-to-end: building SSA concurrently must match the serial result.
    serial = len(SSAProgram(str(SAMPLE)).assignments)

    def build(_):
        return len(SSAProgram(str(SAMPLE)).assignments)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        counts = list(ex.map(build, range(16)))
    assert all(c == serial for c in counts), counts
