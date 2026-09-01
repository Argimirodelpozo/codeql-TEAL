"""Puya-gated lifted-IR subcommands (abi-audit, box-audit,
storage-schema) plus the ABI metadata commands (methods, arc56)."""
from __future__ import annotations

import contextlib
import json as _json
import logging
import sys
from pathlib import Path

from tealql.tealtools.diagnostics.errors import TealQLError

from ._common import (
    _add_common_flags,
    _load_programs,
    logger,
)


def _lifted_programs(args, command: str):
    """Yield ``(label, main, subs)`` per target program lifted to real Puya IR —
    the shared preamble of the ``puya``-gated subcommands.

    HAZARD: a program that does not lift is a COVERAGE GAP, not a failure — it
    is warned about and SKIPPED, so results here are silently partial (one
    stubborn contract must not sink a directory-wide audit).

    HAZARD: puya's IR builder writes to STDOUT, and not through ``logging`` —
    it prints via structlog, so raising the ``puya`` logger's level silences
    nothing. Its lines landed ahead of the payload and made ``--json`` emit
    unparseable output, breaking the one path the flag exists for. The lift is
    therefore run with stdout redirected to STDERR: diagnostics still reach a
    human, and stdout carries only the payload. The redirect wraps ONLY the
    ``to_puya`` call — this is a generator, so holding it open would also
    capture whatever the CALLER prints between yields."""
    try:
        from tealql.tealtools.lift import to_puya
    except ImportError as e:
        raise TealQLError(
            f"{command} requires the 'puya' package (pip install puyapy)") from e
    logging.getLogger("puya").setLevel(logging.CRITICAL)   # the stdlib half
    for prog, name in _load_programs(args):
        label = name or Path(getattr(prog, "source_path", "") or "<program>").name
        try:
            with contextlib.redirect_stdout(sys.stderr):
                main_sub, subs = to_puya(prog)
        except Exception as e:                       # coverage gap, not a crash
            logger.warning("%s: %s did not lift (%s: %s) — skipped",
                           command, label, type(e).__name__, e)
            continue
        yield label, main_sub, subs


def _cmd_abi_audit(args) -> int:
    """Report caller-supplied ``arc4.Address`` values reaching a fund / asset sink,
    flagging the UNGUARDED ones (arbitrary recipient); exit 1 if any.

    The recovered ABI address type is what identifies a 32-byte operand as a
    caller-chosen recipient, and that recovery is SPECULATIVE."""
    leads: list = []
    for label, main, subs in _lifted_programs(args, "abi-audit"):
        from tealql.tealtools.lift import to_puya_ir
        for lead in to_puya_ir.abi_address_fund_flows(main, subs):
            leads.append({"file": label, **lead})

    danger = [x for x in leads
              if x["caller_supplied"] and not x["guarded"]]
    if args.json_out:
        print(_json.dumps(leads, indent=2))
        return 1 if danger else 0
    if not leads:
        print("(no arc4.Address values reach a fund/asset sink)")
        return 0
    print(f"abi-audit: {len(leads)} address→sink flow(s), "
          f"{len(danger)} arbitrary-recipient (caller-supplied & UNGUARDED)")
    for x in sorted(leads, key=lambda d: (not (d["caller_supplied"]
                                               and not d["guarded"]),
                                          d["file"], d["subroutine"], d["field"])):
        if x["caller_supplied"] and not x["guarded"]:
            tag = "  ⚠ CALLER-SUPPLIED, UNGUARDED"
        elif x["caller_supplied"]:
            tag = "  caller-supplied, guarded"
        else:
            tag = "  (not directly caller-supplied)"
        conf = "confident" if x.get("confident") else "somewhat"
        print(f"  {x['file']}: itxn_field {x['field']} (sub {x['subroutine']}) "
              f"<- {x['encoding']} [{conf}]{tag}")
    return 1 if danger else 0


def _cmd_box_audit(args) -> int:
    """Report address-keyed BoxMaps whose key is CALLER-SUPPLIED rather than bound
    to ``txn Sender`` — cross-user access to any account's slot; exit 1 if any."""
    rows: list = []
    for label, main, subs in _lifted_programs(args, "box-audit"):
        from tealql.tealtools.lift.box_recovery import box_access_control
        for f in box_access_control(main, subs):
            rows.append((label, f))

    if args.json_out:
        print(_json.dumps([
            {"file": lbl, "prefix": f.prefix.decode("latin-1"),
             "key_type": f.key_type, "written": f.written, "ops": sorted(f.ops)}
            for lbl, f in rows], indent=2))
        return 1 if rows else 0
    if not rows:
        print("(no cross-user box-access leads)")
        return 0
    for lbl, f in rows:
        print(f"  ⚠ {lbl}: {f.render()}")
    return 1


def _cmd_storage_schema(args) -> int:
    """Reconstruct the global / local / box storage schema with recovered key and
    value types: a constant key is one stored value, a computed or
    ``concat(prefix, encode(k))`` key is a map."""
    spec = None
    if getattr(args, "arc56", None):
        from tealql.tealtools.metadata import arc56 as _arc56
        spec = _arc56.load(args.arc56)          # explicit path -> surface errors

    rows: list = []
    for label, main, subs in _lifted_programs(args, "storage-schema"):
        from tealql.tealtools.lift.box_recovery import (
            annotate_with_arc56, recover_storage_schema)
        for entry in annotate_with_arc56(recover_storage_schema(main, subs), spec):
            rows.append((label, entry))

    if args.json_out:
        print(_json.dumps([
            {"file": lbl, "kind": s.kind, "is_map": s.is_map, "name": s.name,
             "key_or_prefix": s.key_or_prefix.decode("latin-1"),
             "arc56_key_type": s.arc56_key_type,
             "arc56_value_type": s.arc56_value_type,
             "storage_type": s.storage_type,
             "value_confident": s.value_confident, "ops": sorted(s.ops)}
            for lbl, s in rows], indent=2))
        return 0
    if not rows:
        print("(no app storage)")
        return 0
    for lbl, s in rows:
        print(f"  {lbl}: {s.render()}")
    return 0


def _fmt_abi_arg(t: str, name: str = "") -> str:
    """``name: type[NB]``, or bare ``type[NB]`` when the arg has no declared name
    (source-extracted signatures carry none); ``[NB]`` only for fixed widths."""
    from tealql.tealtools.metadata.abi import abi_type_byte_length
    n = abi_type_byte_length(t)
    core = f"{t}[{n}B]" if n is not None else t
    return f"{name}: {core}" if name else core


def _cmd_methods(args) -> int:
    """Print the ABI method table — selector, name, arg types, return type.

    HAZARD: the table comes only from HIGH-LEVEL info — an ``--arc56`` spec
    (authoritative) or the source's ``method "sig"`` pseudo-ops / ``// method``
    comments. NOTHING is reverse-engineered from the selector hash (it is
    irreversible; the selector is recomputed FORWARD and matched). Raw bytecode
    with neither simply reports no method info.

    Not every signature in the table is a method the contract SERVES: the same
    ``method "sig"`` pseudo-ops also carry the selectors of ARC-28 events it logs
    and of methods it CALLS on other contracts. Those are not attack surface, so
    each row is marked routable / not-routable by asking whether the router
    actually dispatches its selector. That question is only answerable when the
    dispatch shape is recognised; when it is not, every row is left unmarked
    rather than guessed at."""
    from tealql.tealtools.metadata.abi import (abi_type_byte_length, extract_method_table,
                                      method_line_ranges)
    rows = []   # (label, AbiMethod, routable: True | False | None-if-undetermined)
    if getattr(args, "arc56", None):
        from tealql.tealtools.metadata import arc56 as _arc56
        spec = _arc56.load(args.arc56)          # explicit path -> surface errors
        label = spec.name or Path(args.arc56).name
        # An ARC-56 spec lists what the contract SERVES, so every entry is routable
        # by construction — there is no router to consult and nothing to determine.
        rows = [(label, m, True) for m in spec.methods]
    elif not getattr(args, "target", None):
        print("error: a target (.teal file or directory) is required unless "
              "--arc56 SPEC.json is given", file=sys.stderr)
        return 2
    else:
        for prog, name in _load_programs(args):
            sources = getattr(prog, "sources", None)
            units = list(sources.files) if sources is not None else []
            label = name or (units[0].name if len(units) == 1 else "<program>")
            text = units[0].text() if len(units) == 1 else "\n".join(
                unit.text() for unit in units
            )
            # method_line_ranges is conservative: an unrecognised dispatch yields NO
            # attribution. Empty therefore means "could not tell", NOT "serves none" —
            # collapsing those two would silently blank the table on every contract
            # whose router this does not model yet.
            served = {m.selector for _, _, m in method_line_ranges(text)} or None
            for m in extract_method_table(text).values():
                rows.append((label, m, None if served is None else m.selector in served))
    rows.sort(key=lambda r: (r[0], r[1].name))
    if getattr(args, "routable", False):
        rows = [r for r in rows if r[2] is not False]     # keep undetermined rows
    if args.json_out:
        print(_json.dumps([
            {"file": lbl, "selector": m.selector_hex, "name": m.name,
             "arg_types": list(m.arg_types), "arg_names": list(m.arg_names),
             "return_type": m.return_type,
             "arg_byte_lengths": [abi_type_byte_length(a) for a in m.arg_types],
             "signature": m.signature, "routable": routable}
            for lbl, m, routable in rows], indent=2))
        return 0
    if not rows:
        print("(no ABI method info in source)")
        return 0
    for lbl, m, routable in rows:
        names = m.arg_names or ("",) * len(m.arg_types)
        args_str = ", ".join(_fmt_abi_arg(a, n) for a, n in zip(m.arg_types, names))
        mark = "" if routable is not False else "   [not routable: event or outgoing call]"
        print(f"  {lbl}: {m.selector_hex}  {m.name}({args_str}) -> {m.return_type}{mark}")
    return 0


def _cmd_arc56(args) -> int:
    """Dump an ARC-56 app spec's methods and state schema — the authoritative but
    OPTIONAL source of the ABI typing the analysis consumes; exit 2 on a bad spec."""
    from tealql.tealtools.metadata import arc56 as _arc56
    try:
        spec = _arc56.load(args.spec)
    except Exception as e:
        print(f"could not read ARC-56 spec {args.spec}: {e}", file=sys.stderr)
        return 2

    def _state(entries):
        return [
            {"name": s.name, "value_type": s.value_type, "key_type": s.key_type,
             "is_map": s.is_map,
             **({"prefix_b64": s.prefix_b64} if s.is_map else {"key_b64": s.key_b64})}
            for s in entries
        ]

    doc = {
        "name": spec.name,
        "structs": spec.structs,
        "methods": [
            {"selector": m.selector_hex, "name": m.name,
             "arg_types": list(m.arg_types), "arg_names": list(m.arg_names),
             "return_type": m.return_type, "signature": m.signature}
            for m in spec.methods],
        "state": {"global": _state(spec.global_state),
                  "local": _state(spec.local_state),
                  "box": _state(spec.box_state)},
    }
    if args.json_out:
        print(_json.dumps(doc, indent=2))
        return 0
    print(f"contract: {spec.name or '<unnamed>'}")
    if spec.structs:
        print("structs:")
        for nm, tt in sorted(spec.structs.items()):
            print(f"  {nm} = {tt}")
    print(f"methods ({len(spec.methods)}):")
    for m in sorted(spec.methods, key=lambda x: x.name):
        names = m.arg_names or ("",) * len(m.arg_types)
        args_str = ", ".join(_fmt_abi_arg(a, n) for a, n in zip(m.arg_types, names))
        print(f"  {m.selector_hex}  {m.name}({args_str}) -> {m.return_type}")
    for scope, entries in (("global", spec.global_state), ("local", spec.local_state),
                           ("box", spec.box_state)):
        if entries:
            print(f"{scope} state ({len(entries)}):")
            for s in sorted(entries, key=lambda x: x.name):
                kind = "map" if s.is_map else "key"
                print(f"  {kind} {s.name}: {s.key_type or '?'} -> {s.value_type or '?'}")
    return 0


def register(sub, add) -> None:
    methods_p = add("methods",
        "recover the ABI method table (name / args / selector) from source "
        "method signatures or an --arc56 spec — optional, empty on raw bytecode",
        _cmd_methods, optional_target=True)   # target unused with --arc56
    methods_p.add_argument(
        "--arc56", default=None, metavar="SPEC.json",
        help="use an ARC-56 app spec as the AUTHORITATIVE method table "
             "(struct-resolved arg/return types + arg names)")
    methods_p.add_argument(
        "--routable", action="store_true",
        help="list only methods the router actually dispatches — drops ARC-28 "
             "event signatures and selectors of methods called on OTHER contracts, "
             "which share the same method table but are not this app's surface")

    arc56_p = sub.add_parser(
        "arc56",
        help="ingest an ARC-56 app spec and dump its methods + state schema "
             "(the authoritative, optional high-level typing source)")
    arc56_p.add_argument("spec", help="path to an ARC-56 app-spec JSON file")
    _add_common_flags(arc56_p)
    arc56_p.set_defaults(handler=_cmd_arc56)

    add("abi-audit",
        "ABI type-driven audit: caller-supplied arc4.Address paid to a "
        "fund/asset sink unguarded (needs puya)", _cmd_abi_audit)
    storage_p = add("storage-schema",
        "reconstruct global/local/box storage schema (keys + maps) with "
        "recovered key/value types (needs puya)", _cmd_storage_schema)
    storage_p.add_argument(
        "--arc56", default=None, metavar="SPEC.json",
        help="annotate entries with authoritative names + value/key types from "
             "an ARC-56 app spec (matched on kind + key/prefix bytes)")
    add("box-audit",
        "box access-control: caller-supplied address-keyed BoxMap not bound to "
        "txn Sender = cross-user access (needs puya)", _cmd_box_audit)
