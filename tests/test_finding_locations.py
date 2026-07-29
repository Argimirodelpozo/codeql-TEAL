"""Every violation carries a STRUCTURED location (the findings contract).

The old ``normalize()`` regex-parsed ``file.teal:line`` out of ``pretty()``
prose — machine locations were only as reliable as sentence wording. Now every
violation class exposes ``.line``/``.file`` (or a well-formed ``.location``
string, or an explicit ``line = None`` for whole-program findings), and the
prose fallback is GONE. These tests pin the contract end-to-end:

  * a corpus sweep — every finding the benchmark ground-truth corpus produces
    has an int line (or its rule is in the documented whole-program set);
  * the sink-anchor regression — the generic taint ``Violation`` anchors on
    the SINK (the violation point), where the old prose regex accidentally
    grabbed the first location in the message (the SOURCE);
  * whole-program findings stay line-less instead of inheriting a random
    line from their message.
"""
from __future__ import annotations

from pathlib import Path


from tealql.security.scan import scan

REPO = Path(__file__).resolve().parent.parent
BENCHMARK = REPO / "tests" / "benchmark"

# Rules whose finding is the ABSENCE of a validation — there is no anchor
# line, and the structured contract reports them whole-program (line=None).
WHOLE_PROGRAM_RULES = {"asset-close-to"}


def test_benchmark_findings_all_carry_structured_lines():
    findings = scan(BENCHMARK)
    assert findings, "benchmark corpus produced no findings at all?"
    rules_seen = set()
    for sf in findings:
        f = sf.to_finding()
        rules_seen.add(f.rule_id)
        if f.rule_id in WHOLE_PROGRAM_RULES:
            continue
        assert isinstance(f.line, int) and f.line >= 1, (
            f"{f.rule_id} on {f.file}: line={f.line!r} — violation class "
            f"{type(sf.violation).__name__} lost its structured location"
        )
        assert f.file, f"{f.rule_id}: finding has no file"
    # The sweep only proves rules that FIRE here; make sure it exercises a
    # meaningful spread so a regression can't hide behind an empty corpus.
    assert len(rules_seen) >= 5, f"benchmark corpus fired only {rules_seen}"


def test_taint_violation_anchors_on_sink_not_source():
    from tealql.security.detections.box_key import NonUniqueBoxKeyDetector
    from tealql.security.findings import normalize
    from tealql.tealtools.ssa import SSAProgram

    prog = SSAProgram(str(REPO / "tests" / "tealtools" / "box_key" / "vuln"))
    violations = NonUniqueBoxKeyDetector(prog).detect()
    assert violations, "box_key vuln fixture no longer fires?"
    for v in violations:
        f = normalize(v, rule_id="box-key")
        assert f.line == v.sink.location.line, "structured anchor must be the sink"
        assert f.file == v.sink.location.file
        # The old prose regex grabbed the FIRST location in pretty() — the
        # source. Prove the anchor genuinely moved (source != sink here).
        assert v.source.location.line != v.sink.location.line
        assert f.line != v.source.location.line


def test_whole_program_finding_has_no_line():
    findings = scan(BENCHMARK / "asset-close-to" / "vuln")
    acr = [sf for sf in findings if sf.detector_name == "asset-close-to"]
    assert acr, "asset-close-to vuln fixture no longer fires?"
    for sf in acr:
        f = sf.to_finding()
        assert f.line is None, "absence-style finding must stay whole-program"


def test_findings_carry_abi_method_when_source_has_it(tmp_path):
    """A finding inside an ABI method body is attributed to that method (source
    `method "sig"` router info) — an OPTIONAL enrichment on `.method` / format()."""
    (tmp_path / "p.teal").write_text(
        "#pragma version 10\n"
        "main:\n"
        "    txna ApplicationArgs 0\n"
        '    pushbytess 0x03b5c0af 0x7fad9780 // method "add_one(uint64)uint64", method "get_address()address"\n'
        "    match handle_add handle_addr\n"
        "    err\n"
        "handle_add:\n"                       # add_one body: an unguarded fund flow
        "    itxn_begin\n"
        "    int pay\n    itxn_field TypeEnum\n"
        "    txna ApplicationArgs 1\n    btoi\n    itxn_field Amount\n"
        "    txn Sender\n    itxn_field Receiver\n"
        "    itxn_submit\n"
        "    int 1\n    return\n"
        "handle_addr:\n"
        "    global ZeroAddress\n    return\n")
    findings = scan(tmp_path)
    add_findings = [f for f in findings if f.method_name == "add_one"]
    assert add_findings, "no finding attributed to add_one?"
    sf = add_findings[0]
    assert "[add_one]" in sf.format()
    assert sf.to_finding().method == "add_one"
    assert sf.to_dict().get("method") == "add_one"


def test_arc56_recovers_method_names_when_comments_stripped(tmp_path):
    """When the compiler's `method "sig"` comments are stripped, an ARC-56 spec
    still attributes findings to their method via the selector operands."""
    from tealql.tealtools.abi import method_selector
    from tealql.tealtools import arc56
    sel = "0x" + method_selector("withdraw(uint64)void").hex()
    (tmp_path / "p.teal").write_text(
        "#pragma version 10\n"
        "main:\n"
        "    txna ApplicationArgs 0\n"
        f"    pushbytess {sel} 0x00000000\n"            # NO `// method` comment
        "    match withdraw other\n"
        "    err\n"
        "withdraw:\n"                                    # an unguarded fund flow
        "    itxn_begin\n    int pay\n    itxn_field TypeEnum\n"
        "    txna ApplicationArgs 1\n    btoi\n    itxn_field Amount\n"
        "    txn Sender\n    itxn_field Receiver\n    itxn_submit\n"
        "    int 1\n    return\n"
        "other:\n    int 1\n    return\n")
    spec = arc56.from_dict({"methods": [
        {"name": "withdraw", "args": [{"type": "uint64", "name": "amt"}],
         "returns": {"type": "void"}}]})
    # without the spec: comments stripped -> no attribution
    assert all(f.method_name is None for f in scan(tmp_path))
    # with the spec: the selector operand resolves to `withdraw`
    with_spec = scan(tmp_path, arc56=spec)
    assert any(f.method_name == "withdraw" for f in with_spec)


def test_no_method_attribution_on_raw_bytecode(tmp_path):
    """No `method "sig"` info -> no attribution; findings degrade cleanly."""
    (tmp_path / "p.teal").write_text(
        "#pragma version 10\n"
        "itxn_begin\nint pay\nitxn_field TypeEnum\n"
        "txna ApplicationArgs 0\nbtoi\nitxn_field Amount\n"
        "txn Sender\nitxn_field Receiver\nitxn_submit\nint 1\nreturn\n")
    findings = scan(tmp_path)
    assert findings, "raw fixture produced no findings?"
    assert all(f.method_name is None for f in findings)
    assert all("[" not in f.format().split(": ", 1)[0].split("] ", 1)[1]
               for f in findings)   # no `[method]` chip after the path


def test_prose_only_violation_is_whole_program():
    """A violation satisfying none of the structured contract reports as
    whole-program — pretty() prose is deliberately NOT parsed."""
    from tealql.security.findings import normalize

    class _MsgOnly:
        def pretty(self):
            return "Approval exit at prog.teal:11 is reachable without a check."

    f = normalize(_MsgOnly(), rule_id="custom-rule", rel_path="prog.teal")
    assert f.line is None
    assert f.file == "prog.teal"  # the scanned path, not parsed prose
