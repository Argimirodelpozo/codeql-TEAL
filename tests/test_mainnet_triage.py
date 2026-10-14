"""The mainnet ratchet's truth labels (``tests/mainnet_triage.json``).

See :mod:`tests.mainnet_triage`. The ratchet pins counts; these labels say
which counted findings are TRUE, and ``docs/FIELD_PRECISION.md`` publishes the
resulting field precision. Only two things fail here:

* a malformed label, or one whose anchor/evidence lines are not in the probe
  (a label must be checkable by opening the file it cites);
* a detector carrying FP labels whose published precision row is stale — a
  known false-positive count that the docs misstate is a claim we publish.

Detector drift (labels whose cell vanished, new unlabelled cells) is REPORTED,
not failed: engines move, and the triage is a measurement, not a gate.
"""
from __future__ import annotations

import pytest

from tests.mainnet_triage import (
    DOC,
    LABELS,
    POLICY,
    detector_table,
    doc_rows,
    load_digest,
    load_manifest,
    match,
    probe_paths,
    report,
    table_line,
    validate_label,
)


@pytest.fixture(scope="module")
def manifest():
    return load_manifest()


@pytest.fixture(scope="module")
def paths():
    return probe_paths()


@pytest.fixture(scope="module")
def matched(manifest, paths):
    return match(manifest, load_digest(), paths)


def test_labels_are_well_formed_and_cite_real_probe_lines(manifest, paths):
    errors = [e for rec in manifest["labels"] for e in validate_label(rec, paths)]
    keys = [(r["contract"], r["detector"], r["line"]) for r in manifest["labels"]]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not errors, "\n".join(errors[:40])
    assert not dupes, f"one label per cell: {sorted(dupes)[:10]}"
    assert set(manifest.get("label_semantics", {})) >= {r["detector"] for r in manifest["labels"]}, \
        "every labelled detector needs a written TP/FP/INTENDED meaning"


def test_policy_class_departs_from_its_label_only_through_an_explicit_override(manifest, paths):
    """An ungated Delete on an app with no inner txns is TP by policy
    (``POLICY``); relabelling such a cell needs a written ``override``."""
    rec = next(r for r in manifest["labels"]
               if (r["detector"], r["class"]) in POLICY and "override" not in r)
    assert rec["label"] == POLICY[(rec["detector"], rec["class"])] and not validate_label(rec, paths)
    quiet = {**rec, "label": "FP"}
    assert any("needs an explicit override" in e for e in validate_label(quiet, paths))
    assert not validate_label({**quiet, "override": "funds provably sit elsewhere"}, paths)
    # An override that departs from nothing is itself an error.
    assert validate_label({**rec, "override": "x"}, paths)
    other = next(r for r in manifest["labels"] if (r["detector"], r["class"]) not in POLICY)
    assert validate_label({**other, "override": "x"}, paths)


def test_matching_reports_resolved_and_unlabelled_without_failing(manifest, matched, paths):
    """The staleness instrument itself: a vanished cell is reported as
    resolved, a new one as unlabelled, and a moved anchor re-attaches by text."""
    rec = next(r for r in manifest["labels"] if r["label"] in LABELS)
    key = (rec["contract"], rec["detector"], rec["line"])
    digest = {"per_contract": {rec["contract"]: {rec["detector"]: str(rec["line"])}}}
    assert match({"labels": [rec]}, digest, paths).matched == {key: rec}
    gone = match({"labels": [rec]}, {"per_contract": {}}, paths)
    assert gone.resolved == [rec] and not gone.matched
    fresh = match({"labels": []}, digest, paths)
    assert fresh.unlabelled == [key]
    # The same text at another line of the same probe re-attaches (anchor moved).
    lines = paths[rec["contract"]].read_text().splitlines()
    twin = next((i + 1 for i, t in enumerate(lines)
                 if i + 1 != rec["line"] and " ".join(t.split("//")[0].split()) == rec["anchor"]), None)
    if twin is not None:
        moved = {"per_contract": {rec["contract"]: {rec["detector"]: str(twin)}}}
        assert list(match({"labels": [rec]}, moved, paths).matched) == [(key[0], key[1], twin)]
    print("\n" + report(matched))


def test_published_field_precision_is_current_for_detectors_with_fps(manifest, matched):
    """``docs/FIELD_PRECISION.md`` must state the current FP numbers. Only
    detectors with FP labels are held to it; regenerate with
    ``python -m tests.mainnet_triage --write-doc``."""
    rows = detector_table(matched)
    published = doc_rows(DOC.read_text())
    stale = [f"{det}:\n  doc  {published.get(det)}\n  now  {table_line(det, row)}"
             for det, row in sorted(rows.items())
             if row["FP"] and published.get(det) != table_line(det, row)]
    assert not stale, ("docs/FIELD_PRECISION.md is stale — run "
                       "`python -m tests.mainnet_triage --write-doc`:\n" + "\n".join(stale))
