"""The mainnet findings ratchet — detector behaviour on REAL contracts.

See :mod:`tests.mainnet_ratchet` for why this exists. In short: the benchmark
measures the tool against cases we wrote and has scored 1.00 through every
false-positive swarm this project has shipped. This measures it against 141
distinct real mainnet programs and fails when the answer moves.

    # after an intended detector change
    UPDATE_MAINNET_DIGEST=1 pytest tests/test_mainnet_ratchet.py

CI runs the full distinct set; it takes ~10 minutes, so it carries the ``slow``
marker for local selection (``-m 'not slow'``).
"""
from __future__ import annotations

import os

import pytest

from tests.mainnet_ratchet import (
    DIGEST, compute_digest, diff_totals, distinct_probes, load_digest, save_digest,
)

UPDATE = os.environ.get("UPDATE_MAINNET_DIGEST") == "1"

#: Cap for a quick local run. Unset (the default, and CI) means every contract.
_LIMIT = int(os.environ.get("MAINNET_RATCHET_LIMIT", "0")) or None


@pytest.mark.slow
def test_findings_digest_unchanged():
    """Detector output over the real corpus matches the committed digest."""
    if not distinct_probes():
        pytest.skip("mainnet probe corpus not present")

    new = compute_digest(limit=_LIMIT)

    if UPDATE:
        save_digest(new)
        pytest.skip(f"digest regenerated ({DIGEST.name})")

    old = load_digest()
    assert old is not None, (
        f"{DIGEST.name} is missing — generate it with "
        "UPDATE_MAINNET_DIGEST=1 pytest tests/test_mainnet_ratchet.py")

    if _LIMIT is not None:
        pytest.skip("MAINNET_RATCHET_LIMIT set — partial run cannot be compared")

    deltas = diff_totals(old, new)
    assert not deltas, (
        "detector behaviour on real mainnet contracts changed:\n"
        + "\n".join(deltas)
        + "\n\nEvery line above is a behaviour change. If it is intended "
          "(a fix landing, a detector broadening), regenerate with "
          "UPDATE_MAINNET_DIGEST=1 and say WHY in the commit message. "
          "If it is not, you have found a regression the benchmark missed.")


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
