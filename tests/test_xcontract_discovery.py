"""xcontract auto-discovery: build the registry by fetching callees from chain.

Offline tests inject a stub ``fetch(app_id) -> (teal, bytecode)`` so no network is
touched; the default fetcher (mainnet indexer + localnet disassemble) is exercised
only in real use.
"""
from pathlib import Path


from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools import xcontract as XC
from helpers import make_xcontract

# Calls app 555 (inline constant) and app 777 (read from global state set to 777).
_CALLER = """#pragma version 10
    byte "target"
    int 777
    app_global_put
    itxn_begin
    int 6
    itxn_field TypeEnum
    int 555
    itxn_field ApplicationID
    itxn_submit
    itxn_begin
    int 6
    itxn_field TypeEnum
    byte "target"
    app_global_get
    itxn_field ApplicationID
    itxn_submit
    int 1
    return
"""


def _caller(tmp_path) -> SSAProgram:
    prog, _ = make_xcontract(tmp_path, _CALLER)
    return prog


def _stub_fetch(app_id):
    return (f"#pragma version 10\n// app {app_id}\nint 1\nreturn\n", b"")


def test_candidate_app_ids_const_and_state(tmp_path):
    assert XC.candidate_app_ids(_caller(tmp_path)) == [555, 777]


def test_discover_builds_and_writes_registry(tmp_path):
    caller = _caller(tmp_path)
    cache = tmp_path / "cache"
    reg = XC.discover_registry(caller, cache_dir=cache, fetch=_stub_fetch)
    assert set(reg) == {555, 777}
    for aid, path in reg.items():
        assert Path(path) == cache / f"app_{aid}.teal"
        assert Path(path).read_text().startswith("#pragma version 10")


def test_discover_is_cached(tmp_path):
    caller = _caller(tmp_path)
    cache = tmp_path / "cache"
    XC.discover_registry(caller, cache_dir=cache, fetch=_stub_fetch)

    def boom(app_id):
        raise AssertionError("should not re-fetch a cached callee")

    reg = XC.discover_registry(caller, cache_dir=cache, fetch=boom)
    assert set(reg) == {555, 777}


def test_unfetchable_callee_skipped(tmp_path):
    caller = _caller(tmp_path)
    cache = tmp_path / "cache"

    def flaky(app_id):
        if app_id == 777:
            raise RuntimeError("not found on chain")
        return _stub_fetch(app_id)

    reg = XC.discover_registry(caller, cache_dir=cache, fetch=flaky)
    assert set(reg) == {555}          # 777 skipped, no invented callee


def test_from_chain_end_to_end(tmp_path):
    caller = _caller(tmp_path)
    g = XC.XContractGraph.from_chain(
        caller, cache_dir=tmp_path / "cache", fetch=_stub_fetch)
    assert sorted(s.app_id for s in g.sites) == [555, 777]
    assert sorted(g.callees) == [555, 777]
