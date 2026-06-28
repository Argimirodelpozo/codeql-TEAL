"""Unified, declarative detection options (security.scan.DetectionOptions).

One YAML controls: per-glob mode (app/logicsig), per-glob detector selection,
per-detector severity override, and a fail_on threshold so the scan only "fails"
on genuine problems (informational findings are reported but don't fail).
"""
from pathlib import Path

import pytest

from security.scan import DetectionOptions, scan, failures


def _opts(d: dict) -> DetectionOptions:
    return DetectionOptions.from_dict(d)


def test_superseded_detector_skipped_by_default():
    # tainted-fund-flow is superseded_by ir-tainted-fund-flow (which falls back to
    # it internally), so a default scan runs only the IR one -- no duplicate
    # findings. partial-tainted-fund-flow is a different detector, untouched.
    dets = _opts({}).detectors_for("a.teal")
    assert "ir-tainted-fund-flow" in dets
    assert "tainted-fund-flow" not in dets
    assert "partial-tainted-fund-flow" in dets


def test_superseded_overridable_by_explicit_only():
    o = _opts({"detectors": [{"match": "*.teal", "only": ["tainted-fund-flow"]}]})
    assert o.detectors_for("a.teal") == ["tainted-fund-flow"]


def test_parse_and_lookups():
    o = _opts({
        "modes": [{"match": "**/*.approval.teal", "mode": "app"}],
        "detectors": [{"match": "*.teal", "exclude": ["unsafe-lsig-args"]}],
        "severity": {"rekey-to": "high", "is-deletable": "informational"},
        "fail_on": "medium",
    })
    assert o.mode_for("x/y.approval.teal") == "app"
    assert o.mode_for("x/y.teal") is None                  # no rule, no auto_mode
    assert "unsafe-lsig-args" not in o.detectors_for("a.teal")
    assert o.severity_for("rekey-to") == "high"            # override
    assert o.severity_for("is-deletable") == "informational"
    assert o.severity_for("tainted-fund-flow") == "medium"  # default
    assert o.is_failure("high") and o.is_failure("medium")
    assert not o.is_failure("low") and not o.is_failure("informational")


def test_invalid_values_rejected():
    with pytest.raises(ValueError):
        _opts({"fail_on": "catastrophic"})
    with pytest.raises(ValueError):
        _opts({"severity": {"rekey-to": "nope"}})


_APP = """#pragma version 8
byte "c"
app_global_get
pop
txn OnCompletion
int 5
==
bnz d
int 1
return
d:
int 1
return
"""

_LSIG = """#pragma version 8
txn Fee
int 1000
<=
return
"""


def _write(tmp_path, name, teal):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / name).write_text(teal)
    return src


def test_mode_scopes_detectors(tmp_path):
    # is-deletable is app-only; with the file declared 'app' it can fire, and
    # with it declared 'logicsig' it is skipped (scoped out).
    _write(tmp_path, "prog.teal", _APP)
    root = tmp_path
    as_app = _opts({"modes": [{"match": "**/prog.teal", "mode": "app"}]})
    as_lsig = _opts({"modes": [{"match": "**/prog.teal", "mode": "logicsig"}]})
    names_app = {f.detector_name for f in scan(root, options=as_app)}
    names_lsig = {f.detector_name for f in scan(root, options=as_lsig)}
    assert "is-deletable" in names_app
    assert "is-deletable" not in names_lsig


def test_fail_on_excludes_informational(tmp_path):
    # An app declared as app: is-deletable (informational) fires but must NOT
    # count as a failure under the default threshold.
    _write(tmp_path, "prog.teal", _APP)
    o = _opts({
        "modes": [{"match": "**/prog.teal", "mode": "app"}],
        "detectors": [{"match": "**/*.teal", "only": ["is-deletable"]}],
        "fail_on": "low",
    })
    found = scan(tmp_path, options=o)
    assert any(f.detector_name == "is-deletable" for f in found)   # reported
    assert failures(found, o) == []                                # but not a failure


def test_auto_mode_opt_in(tmp_path):
    # No declared mode + auto_mode -> classify by opcode. The app (uses
    # app_global_get) is classified app, so is-deletable applies.
    _write(tmp_path, "prog.teal", _APP)
    o = _opts({"auto_mode": True})
    assert o.mode_for("prog.teal") is None                 # no prog -> declared only
    names = {f.detector_name for f in scan(tmp_path, options=o)}
    assert "is-deletable" in names                          # classified app
