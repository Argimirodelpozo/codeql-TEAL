"""The mainnet findings ratchet — detector behaviour on REAL contracts.

See :mod:`tests.mainnet_ratchet` for why this exists. In short: the benchmark
measures the tool against cases we wrote and has scored 1.00 through every
false-positive swarm this project has shipped. This measures it against 231
distinct real mainnet programs and fails when the answer moves.

    # after an intended detector change
    UPDATE_MAINNET_DIGEST=1 pytest tests/test_mainnet_ratchet.py

CI runs the full distinct set, so it carries the ``slow`` marker for local
selection (``-m 'not slow'``). Normal verification is sharded one contract per
pytest item: ``-n auto`` can distribute the work and a hostile contract gets a
bounded ceiling, including a 3x allowance for coverage tracing. Explicit digest
regeneration remains one 900-second item because it must write one aggregate.
"""
from __future__ import annotations

import os

import pytest

from tests.mainnet_ratchet import (
    DIGEST,
    _TIMEOUT_S,
    _analyse,
    app_mode_detectors,
    compute_digest,
    distinct_probes,
    load_digest,
    save_digest,
    summarize_rows,
)

UPDATE = os.environ.get("UPDATE_MAINNET_DIGEST") == "1"

#: Cap for a quick local run. Unset (the default, and CI) means every contract.
_LIMIT = int(os.environ.get("MAINNET_RATCHET_LIMIT", "0")) or None
_PROBES = distinct_probes()
_SELECTED_PROBES = _PROBES[:_LIMIT] if _LIMIT is not None else _PROBES
# Coverage tracing is roughly a 3x slowdown on the largest real contract.  Keep
# a bounded per-contract ceiling while leaving enough room for the exact CI
# instrumentation; the uninstrumented analysis budget remains ``_TIMEOUT_S``.
_CONTRACT_TEST_TIMEOUT_S = 3 * _TIMEOUT_S


@pytest.mark.slow
@pytest.mark.timeout(900)
def test_regenerate_findings_digest():
    """Regenerate once, explicitly; normal CI never enters this slow path."""
    if not UPDATE:
        pytest.skip("digest regeneration not requested")
    if not _PROBES:
        pytest.skip("mainnet probe corpus not present")
    if _LIMIT is not None:
        pytest.fail("refusing to overwrite the digest from a partial corpus")

    save_digest(compute_digest())
    pytest.skip(f"digest regenerated ({DIGEST.name})")


@pytest.mark.slow
def test_findings_digest_manifest_unchanged():
    """The committed rows cover this corpus and aggregate consistently."""
    if UPDATE:
        pytest.skip("digest regeneration requested")
    if not _PROBES:
        pytest.skip("mainnet probe corpus not present")
    old = load_digest()
    assert old is not None, (
        f"{DIGEST.name} is missing — generate it with "
        "UPDATE_MAINNET_DIGEST=1 pytest tests/test_mainnet_ratchet.py")
    if _LIMIT is not None:
        pytest.skip("partial run does not validate the whole-corpus manifest")

    names = app_mode_detectors()
    probe_hashes = {content_hash for content_hash, _ in _PROBES}
    expected_rows = old.get("per_contract", {})
    assert old.get("distinct_contracts") == len(_PROBES)
    assert set(expected_rows) <= probe_hashes
    assert set(old.get("detectors", {})) == set(names)
    assert old["detectors"] == summarize_rows(names, expected_rows)


@pytest.mark.slow
@pytest.mark.timeout(_CONTRACT_TEST_TIMEOUT_S)
@pytest.mark.parametrize(
    ("content_hash", "path"),
    _SELECTED_PROBES,
    ids=[f"{path.stem}-{content_hash}" for content_hash, path in _SELECTED_PROBES],
)
def test_findings_digest_unchanged(content_hash, path):
    """One exact row per contract, so xdist can distribute the real corpus."""
    if UPDATE:
        pytest.skip("digest regeneration requested")
    old = load_digest()
    assert old is not None, f"{DIGEST.name} is missing"
    expected = old.get("per_contract", {}).get(content_hash, {})
    actual = _analyse(path, app_mode_detectors())
    assert actual == expected, (
        f"detector behaviour changed for {path.name} ({content_hash}):\n"
        f"expected {expected}\nactual   {actual}\n\n"
        "Regenerate only for an intended, classified detector change."
    )


@pytest.mark.slow
def test_no_detector_crashes_on_real_contracts():
    """No detector raises on any real contract.

    Separate from the digest so a new crash reads as a crash, not as a diff.
    The digest records crashes too (``CRASH:<type>``), but this asserts the
    property directly: 3,384 detector runs over v2-v11 bytecode from multiple
    compilers currently produce zero exceptions, and that is worth keeping.
    """
    if not distinct_probes():
        pytest.skip("mainnet probe corpus not present")

    digest = load_digest()
    if digest is None:
        pytest.skip("no committed digest")

    crashing = {name: d["crashes"]
                for name, d in digest["detectors"].items() if d["crashes"]}
    assert not crashing, f"detectors crash on real contracts: {crashing}"
