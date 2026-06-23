"""Caller-guard-bypass detector over the super-CFG
(:func:`tealtools.cfg.super_auth.caller_guard_bypass_findings`).

Demonstrates a sound use of interprocedural super-dominance: a caller guards an
appcall with `txn Sender == ADMIN; assert`, so in the modelled call graph the
guard super-dominates the callee's sink. But the callee is independently
callable — an attacker invokes it DIRECTLY, bypassing the caller — UNLESS the
callee pins its caller via `global CallerApplicationID`. So:

  - vulnerable callee (no CallerApplicationID check) -> flagged.
  - safe callee (asserts CallerApplicationID) -> not flagged.
"""
from tealtools.cfg import SuperCFG
from tealtools.cfg.super_auth import caller_guard_bypass_findings
from helpers import make_xcontract


# Caller: admin-gates the appcall, then calls app 100.
_CALLER = """#pragma version 10
txn Sender
addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
==
assert
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
itxn_submit
int 1
return
"""

# Vulnerable callee: drains via an inner txn, no CallerApplicationID check.
_CALLEE_VULN = """#pragma version 10
itxn_begin
int 1
itxn_field TypeEnum
addr BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
itxn_field Receiver
int 1000000
itxn_field Amount
itxn_submit
int 1
return
"""

# Safe callee: pins its caller before the same drain.
_CALLEE_SAFE = """#pragma version 10
global CallerApplicationID
int 555
==
assert
itxn_begin
int 1
itxn_field TypeEnum
addr BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
itxn_field Receiver
int 1000000
itxn_field Amount
itxn_submit
int 1
return
"""


def _build(tmp_path, callee_src):
    caller, registry = make_xcontract(tmp_path, _CALLER, {100: callee_src})
    return SuperCFG.build(caller, registry)


# Caller that gates the appcall with a BRANCH (bnz to an admin block), not an
# assert — must be recognised exactly like the assert form.
_CALLER_BNZ = """#pragma version 10
txn Sender
addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
==
bnz admin
int 0
return
admin:
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
itxn_submit
int 1
return
"""


def test_vulnerable_callee_is_flagged(tmp_path):
    sc = _build(tmp_path, _CALLEE_VULN)
    findings = caller_guard_bypass_findings(sc)
    assert len(findings) == 1, [f.pretty() for f in findings]
    f = findings[0]
    assert f.app_id == 100                       # sink is in the callee
    assert f.sink.op == "itxn_submit"
    assert f.guard_app_id is None                # the caller (root) holds the guard
    assert f.guard_predicates                    # the gating auth predicate(s)


def test_bnz_form_caller_guard_is_recognised(tmp_path):
    # A branch-form (bnz) guard gates the appcall exactly like the assert form.
    caller, registry = make_xcontract(tmp_path, _CALLER_BNZ, {100: _CALLEE_VULN})
    sc = SuperCFG.build(caller, registry)
    findings = caller_guard_bypass_findings(sc)
    assert len(findings) == 1, [f.pretty() for f in findings]
    assert findings[0].app_id == 100 and findings[0].sink.op == "itxn_submit"


def test_safe_callee_is_not_flagged(tmp_path):
    sc = _build(tmp_path, _CALLEE_SAFE)
    findings = caller_guard_bypass_findings(sc)
    assert findings == [], [f.pretty() for f in findings]


def test_no_caller_guard_means_out_of_scope(tmp_path):
    # Caller WITHOUT the admin gate: the sink isn't relying on a cross-contract
    # guard, so this particular detector says nothing (a different detector
    # would flag the openly-callable drain on its own merits).
    open_caller = """#pragma version 10
itxn_begin
int 6
itxn_field TypeEnum
int 100
itxn_field ApplicationID
itxn_submit
int 1
return
"""
    caller, registry = make_xcontract(tmp_path, open_caller, {100: _CALLEE_VULN})
    sc = SuperCFG.build(caller, registry)
    assert caller_guard_bypass_findings(sc) == []
