"""sec-guide/unvalidated-group-sibling: trusting a sibling transfer it never checks.

The single most Algorand-native composition bug. A stateful app routinely relies
on a *sibling* transaction in the same atomic group — "transaction 0 is a payment
of N microAlgo to me" — and reads its value (``gtxn 0 Amount`` / ``gtxn 1
AssetAmount``). The bug is reading that value WITHOUT pinning the sibling's
receiver to this application:

    gtxn 0 Amount            // trust an incoming payment of this size ...
    // ... credit the caller, mint shares, release collateral ...

If the contract never asserts ``gtxn 0 Receiver == Global.CurrentApplicationAddress``,
the attacker submits a group whose transaction 0 pays *someone else* (or themselves)
— the app credits them for funds it never received. ``group-size-check`` only
validates the COUNT of transactions; this validates that a sibling the app draws
VALUE from actually pays the app.

Detection (group reads at a STATICALLY KNOWN sibling index — immediate-index
``gtxn``/``gtxna``/``gtxnas`` plus ``gtxns`` with a const-resolved index, e.g.
``int 0; gtxns Amount``; a genuinely dynamic ``gtxns`` index is skipped soundly):
for each sibling index that the program reads a value field from
(``Amount`` → a payment, ``AssetAmount`` → an asset transfer), require the
matching receiver pin — an equality comparing that sibling's ``Receiver`` /
``AssetReceiver`` against ``global CurrentApplicationAddress`` that reaches
enforcement (``assert`` / branch-to-reject) — ON EVERY PATH through the read:

    flag  ⟺  ∃ a CFG path  entry → read → approving exit  crossing NO pin-
              enforcement block.

The old check was a whole-program EXISTENCE test ("a pin exists somewhere"), so a
router whose ``deposit`` arm pins the receiver silently vouched for an unpinned
read in its ``swap`` arm — the exact per-arm bug this detector exists to catch.
Pin-enforcement blocks come from the shared must-reach machinery
(:func:`common._collect_field_enforcement_bbs`, scratch-aware); the tie check is
the phi/scratch/proto-frame-aware :func:`common._operand_flows_from_field_var`,
so a pin living behind a sub or a scratch slot still counts. Order within a path
is irrelevant (a failed ``assert`` rejects wherever it sits), which is why the
question is path-crossing, not anything-dominates-anything.

Two precision guards:

* TYPE EXCLUSION — a read of a value field whose CARRYING txn type is pinned
  away on every approving path through the read (``gtxn[i].TypeEnum == axfer``
  enforced ⇒ ``gtxn i Amount`` is constantly 0) is inert, not a trusted
  transfer; suppressed via the per-block group substrate
  (:func:`group_reasoning.constraints_at`).
* The escaping exit is labelled with the ABI method it belongs to (source
  ``method "sig"`` info, optional) so the finding names the vulnerable arm.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.tealtools.ssa import SSAProgram, SSAVar, const_int, operand_const

# Value field -> the receiver field that must be pinned for that transfer kind.
_VALUE_TO_RECEIVER = {
    "Amount": "Receiver",            # payment
    "AssetAmount": "AssetReceiver",  # asset transfer
}

# Value field -> the AVM txn type for which that field carries a real transfer.
# ``Amount`` is nonzero only on a ``pay``; ``AssetAmount`` only on an ``axfer`` —
# so a read whose sibling is pinned to any OTHER type is definitionally 0 (inert).
_FIELD_CARRYING_TYPE = {
    "Amount": "pay",
    "AssetAmount": "axfer",
}

# Value field -> the receiver field of the OTHER transfer kind. Pinning it to the
# app proves the sibling is that other type (a ``pay``'s ``AssetReceiver`` is the
# zero address, so ``AssetReceiver == CurrentApp`` can only hold on an ``axfer``,
# and vice-versa), which makes THIS field definitionally 0.
_COMPLEMENT_RECEIVER = {
    "Amount": "AssetReceiver",       # axfer-exclusive -> pins the sibling to axfer
    "AssetAmount": "Receiver",       # pay-exclusive  -> pins the sibling to pay
}


def _forward_reachable(starts) -> set:
    """Every basic block reachable from ``starts`` over CFG successors (the CFG is
    interprocedural, so a read inside a subroutine still reaches its callers'
    approving exits)."""
    seen = set(b for b in starts if b is not None)
    stack = list(seen)
    while stack:
        b = stack.pop()
        for s in b.successors:
            if s not in seen:
                seen.add(s)
                stack.append(s)
    return seen


def _pinned_typeenum(G, pp, exit_bb, index: int):
    """The symbolic txn-type name (``"pay"`` / ``"axfer"`` / …) that
    ``gtxn[index].TypeEnum`` is pinned to in force at ``exit_bb`` (via the group
    substrate), or ``None`` if it isn't pinned to a resolvable constant there."""
    from tealql.tealtools.avm import enum_field_name
    slot = f"gtxn[{index}]"
    for c in G.constraints_at(pp, exit_bb):
        if c.op == "==" and c.ref.slot == slot and c.ref.field == "TypeEnum":
            val = G._const_int(c.rhs)
            if val is not None:
                return enum_field_name("TypeEnum", val)
    return None


@dataclass
class UnvalidatedGroupSiblingViolation:
    prog: SSAProgram
    index: int = 0
    value_field: str = ""
    receiver_field: str = ""
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "value_field": self.value_field,
            "receiver_field": self.receiver_field,
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"UnvalidatedGroupSiblingViolation({self.message})"


class UnvalidatedGroupSiblingDetector:
    name: ClassVar[str] = "sec-guide/unvalidated-group-sibling"
    # HIGH — a trusted-but-unpinned sibling transfer drains/credits wrongly. The
    # messages say [HIGH]; declare it so machine severity (SARIF/JSON) agrees.
    severity: ClassVar[str] = "high"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # gtxn-relying apps
    violation_cls: ClassVar[type] = UnvalidatedGroupSiblingViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list:
        reads = self._gtxn_index_reads()                 # (index, field) -> [assigns]
        app_seeds = self._safe_receiver_targets()
        # The per-arm PATH-existence check relies on CFG reachability, which is
        # only trustworthy when the program has NO subroutines: `retsub` returns
        # context-insensitively, so a read inside a sub spuriously "reaches"
        # approving exits in unrelated callers. That's exactly where the cross-arm
        # false NEGATIVE bites too (inline ABI routers), so we run the path check
        # only there and fall back to the whole-program EXISTENCE check when subs
        # are present — sound, and never worse than the legacy behaviour.
        inline = not self._has_subroutines()
        out: list = []
        for (index, field), assigns in sorted(reads.items()):
            if field not in _VALUE_TO_RECEIVER:
                continue
            recv_field = _VALUE_TO_RECEIVER[field]
            gates = self._pin_gates(index, recv_field, reads, app_seeds)
            escape = None
            if gates:
                if not inline:
                    continue                 # a pin exists & is enforced (legacy: covered)
                escape = self._unpinned_path(assigns, gates)
                if escape is None:
                    continue                 # every approving path crosses the pin
            # else: the receiver is NEVER pinned+enforced anywhere — legacy finding.
            if self._type_excludes_field(index, field, assigns, reads, app_seeds):
                continue                     # inert read: sibling pinned to another type
            a = assigns[0]
            loc = common.loc(a)
            pin = (f"gtxn {index} {recv_field} == "
                   f"Global.CurrentApplicationAddress")
            if escape is None:
                msg = (f"[HIGH] reads gtxn {index} {field} ({loc}) but never pins "
                       f"{pin} — the app trusts a sibling transfer that may not "
                       f"pay it")
            else:
                exit_line, method = escape
                where = f"{method}() at " if method else ""
                msg = (f"[HIGH] reads gtxn {index} {field} ({loc}) on a path that "
                       f"can approve ({where}line {exit_line}) without enforcing "
                       f"{pin} — the pin exists on another arm, but this arm "
                       f"trusts a sibling transfer that may not pay it")
            out.append(UnvalidatedGroupSiblingViolation(
                self.prog, index, field, recv_field, loc, msg))
        return out

    def _has_subroutines(self) -> bool:
        return any(a.op in ("callsub", "retsub", "proto")
                   and common.file_match(a.location.file, self.file)
                   for a in self.prog.assignments)

    # -- internals ------------------------------------------------------

    def _gtxn_index_reads(self) -> dict:
        """``(index, field) -> [assignments]`` for every group read with a
        STATICALLY KNOWN sibling index:

        * the immediate-index opcodes ``gtxn`` / ``gtxna`` / ``gtxnas`` (index in
          the first immediate), and
        * the stack-index ``gtxns`` when its popped index operand is a
          compile-time constant — e.g. ``int 0; gtxns Amount``, the usual
          compiler output for ``gtxn.PaymentTxn(0)``.

        A genuinely DYNAMIC ``gtxns`` index (one not const-resolvable) is still
        skipped: the sibling it reads isn't statically known, so there is no fixed
        index to demand a receiver pin for."""
        out: dict = {}
        for a in self.prog.assignments:
            if not common.file_match(a.location.file, self.file):
                continue
            if a.op in ("gtxn", "gtxna", "gtxnas"):
                toks = a.immediates.split()
                if len(toks) < 2 or not toks[0].lstrip("-").isdigit():
                    continue
                out.setdefault((int(toks[0]), toks[1]), []).append(a)
            elif a.op == "gtxns":
                # field is the only immediate; the sibling index is the popped
                # stack operand, usable only when it is a compile-time constant.
                toks = a.immediates.split()
                if not toks or not a.inputs:
                    continue
                idx = const_int(a.inputs[0])
                if idx is None:
                    continue
                out.setdefault((idx, toks[0]), []).append(a)
        return out

    def _global_seeds(self, gfield: str) -> set:
        return common.ssavar_outputs(
            common.global_field_reads(self.prog, gfield, file=self.file)
        )

    def _safe_receiver_targets(self) -> set:
        """SSAVars holding an address the ATTACKER CANNOT CHOOSE — the only values
        a receiver pin can meaningfully constrain to. A pin ``gtxn i Receiver == X``
        protects the app iff ``X`` is not attacker-controlled:

          * ``Global.CurrentApplicationAddress`` / ``Global.CreatorAddress`` — the
            app's / creator's account;
          * a value read from the app's OWN state (``app_global_get`` /
            ``app_local_get``) — the ESCROW pattern (funds routed to a
            contract-designated account stored in state), extremely common in
            older AMM / game contracts.

        Constants are handled directly in :meth:`_pin_gates`. A pin against
        ``ApplicationArgs`` / a ``gtxn`` field / ``Sender`` is NOT here — the
        attacker supplies those, so the pin is vacuous and the read stays flagged.
        (Positive safe-set, the SOUND dual of "X is not user-tainted": an
        unmodelled address form fails safe — still flagged — not silently trusted.)"""
        seeds: set = set()
        for gf in ("CurrentApplicationAddress", "CreatorAddress"):
            seeds |= self._global_seeds(gf)
        state_ops = ("app_global_get", "app_local_get",
                     "app_global_get_ex", "app_local_get_ex")
        for a in self.prog.assignments:
            if a.op in state_ops and common.file_match(a.location.file, self.file):
                seeds |= {o for o in a.outputs if isinstance(o, SSAVar)}
        return seeds

    def _pin_gates(self, index: int, recv_field: str, reads: dict,
                   app_seeds: set) -> set:
        """The BASIC BLOCKS that ENFORCE the receiver pin — an ``assert`` /
        branch-to-reject whose condition SSA-derives from an equality tying
        ``gtxn <index> <recv_field>`` to ``Global.CurrentApplicationAddress``.
        Crossing one of these on a path means that path enforced the pin. Empty
        when the receiver is never compared, or compared but never enforced."""
        recv_assigns = reads.get((index, recv_field), [])
        recv_seeds = {o for a in recv_assigns for o in a.outputs
                      if isinstance(o, SSAVar)}
        gates: set = set()
        if not recv_seeds:                # a constant pin still counts w/o app_seeds
            return gates
        label_lines = common._label_to_bb_first_line(self.prog)
        scratch_fwd = common.scratch_forward_map(self.prog)

        def _safe(op):
            # A not-attacker-controlled pin target: flows from a safe address
            # source, or is a constant (a hard-coded address literal).
            return (common._operand_flows_from_field_var(self.prog, op, app_seeds)
                    or operand_const(op) is not None)

        for cmp in self.prog.assignments:
            if cmp.op != "==" or len(cmp.inputs) != 2:
                continue
            if not common.file_match(cmp.location.file, self.file):
                continue
            x, y = cmp.inputs
            tied = (
                (common._operand_flows_from_field_var(self.prog, x, recv_seeds)
                 and _safe(y))
                or
                (common._operand_flows_from_field_var(self.prog, y, recv_seeds)
                 and _safe(x))
            )
            if not tied:
                continue
            if cmp.outputs and isinstance(cmp.outputs[0], SSAVar):
                common._collect_field_enforcement_bbs(
                    self.prog, cmp.outputs[0], label_lines, gates, set(),
                    scratch_fwd)
        return gates

    def _unpinned_path(self, assigns: list, gates: set):
        """``(exit_line, abi_method | None)`` witnessing a pin-free approving
        path through one of these reads — a CFG path entry → read → approving
        exit that crosses NO gate — or ``None`` when every such path is gated.

        Decomposed as prefix ∧ suffix (independent through the read block):
        some entry→read path avoids the gates AND some read→approving-exit path
        avoids them. Order within the path is irrelevant (an ``assert`` after
        the read still rejects the whole txn), which is exactly what gate-
        crossing captures and a dominance test would not."""
        exits = set(common.approving_exits(self.prog, file=self.file))
        if not exits:
            return None
        method_of = None
        for rbb in sorted({a.basic_block for a in assigns
                           if a.basic_block is not None},
                          key=lambda b: (b.file, b.first_line)):
            if rbb in gates:
                continue                     # pin enforced in the read's own block
            if gates and common._all_entry_paths_cross(rbb, gates):
                continue                     # every way to reach the read is gated
            hit = self._gate_free_exit(rbb, gates, exits)
            if hit is None:
                continue                     # every way to approve is gated
            if method_of is None:
                from tealql.tealtools.group_reasoning import exit_method_lookup
                method_of = exit_method_lookup(self.prog)
            line = getattr(hit, "last_line", None) or hit.first_line
            return line, method_of(hit)
        return None

    @staticmethod
    def _gate_free_exit(start, gates: set, exits: set):
        """The first approving exit reachable from ``start`` over CFG successors
        WITHOUT crossing a gate block, or ``None``."""
        seen = {start}
        stack = [start]
        while stack:
            b = stack.pop()
            if b in exits:
                return b
            for s in b.successors:
                if s in gates or s in seen:
                    continue
                seen.add(s)
                stack.append(s)
        return None

    # -- type-precision suppression -------------------------------------

    def _pp(self):
        pp = getattr(self, "_pp_cache", None)
        if pp is None:
            from tealql.tealtools.path_predicates import PathPredicateAnalysis
            pp = self._pp_cache = PathPredicateAnalysis(self.prog)
        return pp

    def _type_excludes_field(self, index: int, field: str, assigns: list,
                             reads: dict, app_seeds: set) -> bool:
        """True when sibling ``gtxn[index]`` is provably NOT the transfer type this
        field carries on every approving path through the read, so the value is
        definitionally 0 (an inert read — e.g. ``gtxn 1 Amount`` of a sibling the
        app pins as an ``axfer``), not a trusted transfer. Two independent signals,
        either sufficient:

        1. COMPLEMENTARY RECEIVER PIN — the other kind's receiver
           (``AssetReceiver`` for an ``Amount`` read, ``Receiver`` for
           ``AssetAmount``) is pinned to the app on EVERY approving path through
           the read. That pin can only hold on the other txn type (a ``pay``'s
           ``AssetReceiver`` is the zero address), so this field is 0. Reuses the
           detection gate machinery (must-cross on every path).
        2. EXPLICIT ``TypeEnum`` pinned to an incompatible type at every reachable
           approving exit.

        Conservative — suppresses only under a proof that holds on all relevant
        paths; anything weaker leaves the finding standing."""
        carrying = _FIELD_CARRYING_TYPE.get(field)
        if carrying is None:
            return False
        # Signal 1: complementary receiver pinned on every path through the read.
        comp_field = _COMPLEMENT_RECEIVER.get(field)
        if comp_field:
            comp_gates = self._pin_gates(index, comp_field, reads, app_seeds)
            if comp_gates and self._unpinned_path(assigns, comp_gates) is None:
                return True
        # Signal 2: explicit TypeEnum excluded at every reachable approving exit.
        exits = common.approving_exits(self.prog, file=self.file)
        reach = _forward_reachable({a.basic_block for a in assigns
                                    if a.basic_block is not None})
        reachable_exits = [e for e in exits if e in reach]
        if not reachable_exits:
            return False
        from tealql.tealtools import group_reasoning as G
        pp = self._pp()
        for e in reachable_exits:
            pinned = _pinned_typeenum(G, pp, e, index)
            if pinned is None or pinned == carrying:
                return False        # unpinned or the carrying type IS possible here
        return True
