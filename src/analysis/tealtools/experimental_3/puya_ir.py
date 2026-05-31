"""Puya-style SSA IR render — toward the ``.ssa.slot.ir`` shape.

Built on the block-argument view (:func:`tealtools.block_args.to_block_args`):
per-block SSA, phi-at-join with predecessor labels. Emits

    block@<n>: // L<line>
        let <name>: <type> = (<op> <args>)
        let <phi>: <type> = φ(<arg> <- block@<n>, ...)
        goto <cond> ? block@<a> : block@<b>     // or  goto block@<n> / return / fail

toward https://github.com/algorandfoundation/puya 's ``.ssa.slot.ir``.

Decompiler limits (vs real Puya, which compiles *from* Python source):
- variable names are op-derived + positional (``tmp%3#0``, ``len%0#0``) — there
  are no source names (``asset``, ``previous_bid``);
- byte constants stay hex (no source strings);
- subroutine partitioning and switch-pattern recognition are not done yet
  (everything is flat under ``main``; ABI dispatch shows as a ``==``/branch
  chain). Those are the next tiers.
"""
from __future__ import annotations

from ..block_args import to_block_args
from ..ssa import Const, Phi, SSAProgram, SSAVar, _TERMINATOR_OPS

_BOOL_OPS = frozenset({"==", "!=", "<", ">", "<=", ">=", "!", "&&", "||",
                       "b==", "b!=", "b<", "b>", "b<=", "b>="})
_U64_OPS = frozenset({"+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr",
                      "bitlen", "len", "btoi", "getbyte", "getbit",
                      "extract_uint16", "extract_uint32", "extract_uint64"})
_BYTES_OPS = frozenset({"itob", "concat", "substring", "substring3", "extract",
                        "extract3", "replace2", "replace3", "sha256",
                        "sha512_256", "keccak256", "sha3_256", "bzero",
                        "setbyte", "setbit", "b+", "b-", "b*", "b/", "b%",
                        "b|", "b&", "b^", "b~", "bsqrt"})
_NAME_PREFIX = {"len": "len", "==": "eq", "!=": "ne", "<": "lt", ">": "gt",
                "<=": "le", ">=": "ge", "!": "not", "&&": "and", "||": "or",
                "btoi": "val", "concat": "concat", "itob": "enc"}
_COND_BRANCH = frozenset({"bnz", "bz"})

# Transaction-field accessors (txn/txna/gtxn/itxn families). The field name is
# one of the immediate tokens (position varies: gtxn has a group index first),
# so _field_type scans all tokens against the table.
_TXN_OPS = frozenset({"txn", "txna", "txnas", "gtxn", "gtxna", "gtxnas",
                      "gtxns", "gtxnsa", "gtxnsas", "itxn", "itxna", "itxnas",
                      "gitxn", "gitxna", "gitxnas"})
_TXN_FIELD_TYPE = {
    # uint64
    "Fee": "uint64", "FirstValid": "uint64", "FirstValidTime": "uint64",
    "LastValid": "uint64", "TypeEnum": "uint64", "GroupIndex": "uint64",
    "Amount": "uint64", "AssetAmount": "uint64", "OnCompletion": "uint64",
    "NumAppArgs": "uint64", "NumAccounts": "uint64", "NumAssets": "uint64",
    "NumApplications": "uint64", "NumLogs": "uint64", "AssetCloseAmount": "uint64",
    "GlobalNumUint": "uint64", "GlobalNumByteSlice": "uint64",
    "LocalNumUint": "uint64", "LocalNumByteSlice": "uint64",
    "ExtraProgramPages": "uint64", "ConfigAssetTotal": "uint64",
    "ConfigAssetDecimals": "uint64", "VoteFirst": "uint64", "VoteLast": "uint64",
    "VoteKeyDilution": "uint64", "NumApprovalProgramPages": "uint64",
    "NumClearStateProgramPages": "uint64",
    # bool
    "ConfigAssetDefaultFrozen": "bool", "FreezeAssetFrozen": "bool",
    "Nonparticipation": "bool",
    # account (addresses)
    "Sender": "account", "Receiver": "account", "CloseRemainderTo": "account",
    "AssetSender": "account", "AssetReceiver": "account", "Accounts": "account",
    "AssetCloseTo": "account", "RekeyTo": "account", "FreezeAssetAccount": "account",
    "ConfigAssetManager": "account", "ConfigAssetReserve": "account",
    "ConfigAssetFreeze": "account", "ConfigAssetClawback": "account",
    # asset / application ids
    "XferAsset": "asset", "ConfigAsset": "asset", "FreezeAsset": "asset",
    "CreatedAssetID": "asset", "Assets": "asset",
    "ApplicationID": "application", "Applications": "application",
    "CreatedApplicationID": "application",
    # bytes
    "Note": "bytes", "Lease": "bytes", "Type": "bytes", "GroupID": "bytes",
    "ApplicationArgs": "bytes", "Logs": "bytes", "LastLog": "bytes",
    "ApprovalProgram": "bytes", "ClearStateProgram": "bytes",
    "ApprovalProgramPages": "bytes", "ClearStateProgramPages": "bytes",
    "VotePK": "bytes", "SelectionPK": "bytes", "StateProofPK": "bytes",
    "ConfigAssetName": "bytes", "ConfigAssetUnitName": "bytes",
    "ConfigAssetURL": "bytes", "ConfigAssetMetadataHash": "bytes",
}
_GLOBAL_FIELD_TYPE = {
    "MinTxnFee": "uint64", "MinBalance": "uint64", "MaxTxnLife": "uint64",
    "GroupSize": "uint64", "LogicSigVersion": "uint64", "Round": "uint64",
    "LatestTimestamp": "uint64", "OpcodeBudget": "uint64",
    "AssetCreateMinBalance": "uint64", "AssetOptInMinBalance": "uint64",
    "PayoutsGoOnlineFee": "uint64", "PayoutsPercent": "uint64",
    "PayoutsMinBalance": "uint64", "PayoutsMaxBalance": "uint64",
    "PayoutsEnabled": "bool",
    "ZeroAddress": "account", "CreatorAddress": "account",
    "CurrentApplicationAddress": "account", "CallerApplicationAddress": "account",
    "CurrentApplicationID": "application", "CallerApplicationID": "application",
    "GenesisHash": "bytes",
}


def _field_type(op, immediates):
    """Type of a ``txn``-family / ``global`` field read, by scanning the
    immediate tokens for a known field name. ``None`` if not a field read or
    the field is unknown."""
    toks = immediates.split() if immediates else []
    if op in _TXN_OPS:
        table = _TXN_FIELD_TYPE
    elif op == "global":
        table = _GLOBAL_FIELD_TYPE
    else:
        return None
    for tk in toks:
        if tk in table:
            return table[tk]
    return None


def _typed_const(cv: Const) -> str:
    """Puya-style literal: ``<n>u`` for uint64, hex verbatim for bytes."""
    return f"{cv.value}u" if cv.kind == "uint64" else cv.value


def render_puya(prog: SSAProgram) -> str:
    form = to_block_args(prog)
    blocks = sorted(prog.blocks.values(), key=lambda b: (b.file, b.first_line))
    bidx = {bb: i for i, bb in enumerate(blocks)}
    line2block = {bb.first_line: bb for bb in blocks}
    label2line = {code.rstrip(":").strip(): ln for (_f, ln, code) in prog.labels}

    # ---- names: one per shown SSAVar (skip inlined consts) + each real-join phi
    names: dict = {}
    ctr: dict = {}

    def fresh(prefix: str) -> str:
        n = ctr.get(prefix, 0)
        ctr[prefix] = n + 1
        return f"{prefix}%{n}#0"

    for a in sorted(prog.assignments, key=lambda a: (a.location.file, a.location.line)):
        for o in a.outputs:
            if (isinstance(o, SSAVar) and o not in names
                    and getattr(o, "const_value", None) is None):
                names[o] = fresh(_NAME_PREFIX.get(a.op, "tmp"))
    for bb in blocks:
        if len(bb.predecessors) > 1:
            for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                if ph not in names:
                    names[ph] = fresh("tmp")

    def name_of(o) -> str:
        if o not in names:                       # unnamed (rare) — stable fallback
            names[o] = fresh("v")
        return names[o]

    # ---- operand rendering: inline consts + trivial single-pred phis
    def src(o, _seen=None):
        seen = _seen if _seen is not None else set()
        while isinstance(o, Phi) and o not in names:   # named (real-join) phi stops
            b = o.basic_block
            if b is None or len(b.predecessors) != 1 or id(o) in seen:
                break
            seen.add(id(o))
            es = b.predecessors[0].exit_stack
            k = o.stack_index
            nxt = es[-k] if 0 < k <= len(es) else None
            if nxt is None:
                break
            o = nxt
        cv = getattr(o, "const_value", None)
        if cv is not None:
            return _typed_const(cv)
        if o is None:
            return "?"
        if isinstance(o, Const):
            return _typed_const(o)
        return name_of(o)

    # ---- best-effort type
    def type_of(o, producer_op=None, producer_imm=None) -> str:
        # A comparison/boolean op reads as `bool` even though its value is a
        # uint64 0/1 (and the range pass seeds it [0..1]) -- match Puya.
        if producer_op in _BOOL_OPS:
            return "bool"
        ft = _field_type(producer_op, producer_imm)
        if ft:
            return ft
        t = getattr(o, "type", None)
        if t is not None and getattr(t, "kind", None):
            return t.kind
        if getattr(o, "range", None) is not None:
            return "uint64"
        if producer_op in _U64_OPS:
            return "uint64"
        if producer_op in _BYTES_OPS:
            return "bytes"
        return "?"

    def term_assign(bb):
        last = None
        for a in bb.assignments:
            if a.op in _TERMINATOR_OPS:
                last = a
        return last

    def control(bb) -> str:
        succ = bb.successors
        t = term_assign(bb)
        op = t.op if t is not None else None
        if not succ:
            if op == "return":
                # TEAL `return` has no SSA input (arity 0/0); the returned
                # value is the top of the block's exit stack.
                if t and t.inputs:
                    v = src(t.inputs[0])
                elif bb.exit_stack:
                    v = src(bb.exit_stack[-1])
                else:
                    v = ""
                return f"return {v}".rstrip()
            if op == "err":
                return "fail"
            if op == "retsub":
                vs = " ".join(src(i) for i in t.inputs) if t else ""
                return f"return {vs}".rstrip()
            return "exit 0u"
        if len(succ) == 1:
            return f"goto block@{bidx[succ[0]]}"
        if len(succ) == 2 and op in _COND_BRANCH and t is not None:
            cond = src(t.inputs[0]) if t.inputs else "?"
            tgt_line = label2line.get((t.immediates or "").strip())
            taken = line2block.get(tgt_line)
            if taken in succ:
                other = succ[0] if succ[1] is taken else succ[1]
            else:
                taken, other = succ[0], succ[1]
            if op == "bz":           # branch when zero -> taken on the false arm
                taken, other = other, taken
            return f"goto {cond} ? block@{bidx[taken]} : block@{bidx[other]}"
        # switch / match / other multi-way — Tier 5; show the targets plainly
        tgts = " | ".join(f"block@{bidx[s]}" for s in succ)
        return f"goto {op or 'branch'} -> {tgts}"

    # ---- emit
    out: list[str] = [f"main {blocks[0].file.split('/')[-1] if blocks else 'program'}:"]
    for bb in blocks:
        out.append(f"    block@{bidx[bb]}: // L{bb.first_line}")
        if len(bb.predecessors) > 1:
            for ph in sorted(bb.phis, key=lambda p: p.stack_index):
                srcs = []
                for pred in bb.predecessors:
                    e = form.edge(pred, bb)
                    i = list(form.params.get(bb, [])).index(ph) if ph in form.params.get(bb, []) else None
                    val = e.args[i] if (e is not None and i is not None and i < len(e.args)) else None
                    srcs.append(f"{src(val)} <- block@{bidx[pred]}")
                out.append(f"        let {name_of(ph)}: {type_of(ph)} = φ({', '.join(srcs)})")
        for a in bb.assignments:
            if a.op in _TERMINATOR_OPS:
                continue
            if a.op in ("intcblock", "bytecblock"):
                continue
            if (len(a.outputs) == 1 and not a.inputs
                    and getattr(a.outputs[0], "const_value", None) is not None):
                continue
            args = " ".join(src(i) for i in a.inputs)
            imm = f" {a.immediates}" if a.immediates else ""
            body = f"({a.op}{imm}{(' ' + args) if args else ''})"
            shown = [o for o in a.outputs if isinstance(o, SSAVar)]
            if shown:
                lhs = ", ".join(f"{name_of(o)}: {type_of(o, a.op, a.immediates)}"
                                for o in shown)
                out.append(f"        let {lhs} = {body}")
            else:
                out.append(f"        {body}")
        out.append(f"        {control(bb)}")
        out.append("")
    return "\n".join(out)
