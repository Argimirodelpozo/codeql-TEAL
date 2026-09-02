"""sec-guide/unvalidated-group-sibling: the app draws VALUE from a sibling txn
(``gtxn i Amount`` / ``AssetAmount``) without pinning that sibling's receiver to
``Global.CurrentApplicationAddress``, so the attacker can pay someone else and
still be credited.

Flag ⟺ ∃ a CFG path entry → read → approving exit crossing NO pin-enforcement
block. The question is PATH-CROSSING, not dominance: a failed ``assert`` rejects
wherever it sits, so a pin after the read still protects it. It is also per-path,
not whole-program existence — a router whose ``deposit`` arm pins the receiver
must not vouch for an unpinned read in its ``swap`` arm.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security._enforcement import _label_to_bb_first_line, scratch_forward_map
from tealql.security._field_protection import (
    _all_entry_paths_cross,
    _collect_disequality_pin_bbs,
    _collect_field_enforcement_bbs,
)
from tealql.security._program_shape import (
    approving_exits,
    file_match,
    global_field_reads,
    loc,
    ssavar_outputs,
)
from tealql.security._value_flow import (
    _operand_flows_from_field_var,
    cached_path_predicates,
)
from tealql.tealtools.ssa import SSAProgram, SSAVar, const_int, operand_const

# Value field -> the receiver field that must be pinned for that transfer kind.
_VALUE_TO_RECEIVER = {
    "Amount": "Receiver",            # payment
    "AssetAmount": "AssetReceiver",  # asset transfer
}

# Value field -> the only AVM txn type on which it carries a real transfer; a
# sibling pinned to any OTHER type reads definitionally 0 (inert).
_FIELD_CARRYING_TYPE = {
    "Amount": "pay",
    "AssetAmount": "axfer",
}

# Value field -> the receiver field of the OTHER transfer kind. Pinning it to the
# app proves the sibling is that other type (a ``pay``'s ``AssetReceiver`` is the
# zero address), which makes THIS field definitionally 0.
_COMPLEMENT_RECEIVER = {
    "Amount": "AssetReceiver",       # axfer-exclusive -> pins the sibling to axfer
    "AssetAmount": "Receiver",       # pay-exclusive  -> pins the sibling to pay
}


def _forward_reachable(starts) -> set:
    """Blocks reachable from ``starts`` over CFG successors (interprocedural — a read
    inside a subroutine reaches its callers' approving exits)."""
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
    """The txn-type name (``"pay"``/``"axfer"``/…) ``gtxn[index].TypeEnum`` is pinned
    to at ``exit_bb``, or ``None`` when it is not pinned to a resolvable constant."""
    from tealql.tealtools.language.avm import enum_field_name
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
    # Declared so machine severity (SARIF/JSON) agrees with the [HIGH] messages.
    severity: ClassVar[str] = "high"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # gtxn-relying apps
    violation_cls: ClassVar[type] = UnvalidatedGroupSiblingViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list:
        reads = self._gtxn_index_reads()                 # (index, field) -> [assigns]
        app_seeds = self._safe_receiver_targets()
        # HAZARD: the per-arm PATH check is gated on there being NO subroutines.
        # `retsub` returns context-insensitively, so a read inside a sub spuriously
        # "reaches" approving exits in unrelated callers and the path check turns
        # into an FP machine. With subs present, fall back to the whole-program
        # EXISTENCE check — never worse than the legacy behaviour.
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
            location = loc(a)
            pin = (f"gtxn {index} {recv_field} == "
                   f"Global.CurrentApplicationAddress")
            if escape is None:
                msg = (f"[HIGH] reads gtxn {index} {field} ({location}) but never pins "
                       f"{pin} — the app trusts a sibling transfer that may not "
                       f"pay it")
            else:
                exit_line, method = escape
                where = f"{method}() at " if method else ""
                msg = (f"[HIGH] reads gtxn {index} {field} ({location}) on a path that "
                       f"can approve ({where}line {exit_line}) without enforcing "
                       f"{pin} — the pin exists on another arm, but this arm "
                       f"trusts a sibling transfer that may not pay it")
            out.append(UnvalidatedGroupSiblingViolation(
                self.prog, index, field, recv_field, location, msg))
        return out

    def _has_subroutines(self) -> bool:
        return any(a.op in ("callsub", "retsub", "proto")
                   and file_match(a.location.file, self.file)
                   for a in self.prog.assignments)

    # -- internals ------------------------------------------------------

    def _gtxn_index_reads(self) -> dict:
        """``(index, field) -> [assignments]`` for every group read at a STATICALLY
        KNOWN sibling index: ``gtxn``/``gtxna``/``gtxnas`` (immediate index) plus
        ``gtxns`` with a const-resolvable index operand.

        A genuinely dynamic ``gtxns`` index is skipped — no fixed sibling to demand
        a receiver pin for (a deliberate FN)."""
        out: dict = {}
        for a in self.prog.assignments:
            if not file_match(a.location.file, self.file):
                continue
            if a.op in ("gtxn", "gtxna", "gtxnas"):
                toks = a.immediates.split()
                if len(toks) < 2 or not toks[0].lstrip("-").isdigit():
                    continue
                out.setdefault((int(toks[0]), toks[1]), []).append(a)
            elif a.op == "gtxns":
                # field is the only immediate; the sibling index is the popped
                # operand, usable only when it is a compile-time constant.
                toks = a.immediates.split()
                if not toks or not a.inputs:
                    continue
                idx = const_int(a.inputs[0])
                if idx is None:
                    continue
                out.setdefault((idx, toks[0]), []).append(a)
        return out

    def _global_seeds(self, gfield: str) -> set:
        return ssavar_outputs(
            global_field_reads(self.prog, gfield, file=self.file)
        )

    def _safe_receiver_targets(self) -> set:
        """SSAVars holding an address the ATTACKER CANNOT CHOOSE: the app's/creator's
        address, or a read of the app's OWN state (the escrow pattern). Constants are
        handled in :meth:`_pin_gates`.

        HAZARD: this is a POSITIVE safe-set, not "X is not user-tainted". An
        unmodelled address form must fail SAFE (still flagged), never be trusted —
        pinning ``Receiver`` to ``ApplicationArgs``/``Sender`` protects nothing."""
        seeds: set = set()
        for gf in ("CurrentApplicationAddress", "CreatorAddress"):
            seeds |= self._global_seeds(gf)
        state_ops = ("app_global_get", "app_local_get",
                     "app_global_get_ex", "app_local_get_ex")
        for a in self.prog.assignments:
            if a.op in state_ops and file_match(a.location.file, self.file):
                seeds |= {o for o in a.outputs if isinstance(o, SSAVar)}
        return seeds

    def _pin_gates(self, index: int, recv_field: str, reads: dict,
                   app_seeds: set) -> set:
        """Blocks ENFORCING the receiver pin (``assert``/branch-to-reject/approving
        ``return`` on an equality tying ``gtxn <index> <recv_field>`` to a safe
        address, or a ``!=`` whose TRUTH rejects); crossing one means that path
        enforced the pin. Empty when never compared or never enforced."""
        recv_assigns = reads.get((index, recv_field), [])
        recv_seeds = {o for a in recv_assigns for o in a.outputs
                      if isinstance(o, SSAVar)}
        gates: set = set()
        if not recv_seeds:                # a constant pin still counts w/o app_seeds
            return gates
        label_lines = _label_to_bb_first_line(self.prog)
        scratch_fwd = scratch_forward_map(self.prog)

        def _safe(op):
            # A not-attacker-controlled pin target: flows from a safe address
            # source, or is a constant (a hard-coded address literal).
            return (_operand_flows_from_field_var(self.prog, op, app_seeds)
                    or operand_const(op) is not None)

        for cmp in self.prog.assignments:
            if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
                continue
            if not file_match(cmp.location.file, self.file):
                continue
            x, y = cmp.inputs
            tied = (
                (_operand_flows_from_field_var(self.prog, x, recv_seeds)
                 and _safe(y))
                or
                (_operand_flows_from_field_var(self.prog, y, recv_seeds)
                 and _safe(x))
            )
            if not tied:
                continue
            if not cmp.outputs or not isinstance(cmp.outputs[0], SSAVar):
                continue
            if cmp.op == "==":
                _collect_field_enforcement_bbs(
                    self.prog, cmp.outputs[0], label_lines, gates, set(),
                    scratch_fwd)
            else:
                # `!=`: only a rejection on TRUE leaves the equality alive;
                # `assert`/reject-on-FALSE demand the disequality (anti-pin).
                _collect_disequality_pin_bbs(
                    self.prog, cmp.outputs[0], label_lines, gates, set(),
                    scratch_fwd)
        return gates

    def _unpinned_path(self, assigns: list, gates: set):
        """``(exit_line, abi_method | None)`` witnessing a gate-free entry → read →
        approving-exit path, or ``None`` when every such path is gated. Decomposed
        as prefix ∧ suffix, independent through the read block."""
        exits = set(approving_exits(self.prog, file=self.file))
        if not exits:
            return None
        method_of = None
        for rbb in sorted({a.basic_block for a in assigns
                           if a.basic_block is not None},
                          key=lambda b: (b.file, b.first_line)):
            if rbb in gates:
                continue                     # pin enforced in the read's own block
            if gates and _all_entry_paths_cross(self.prog, rbb, gates):
                continue                     # every way to reach the read is gated
            hit = self._gate_free_exit(rbb, gates, exits)
            if hit is None:
                continue                     # every way to approve is gated
            if method_of is None:
                from tealql.tealtools.cfg.group import exit_method_lookup
                method_of = exit_method_lookup(self.prog)
            line = getattr(hit, "last_line", None) or hit.first_line
            return line, method_of(hit)
        return None

    @staticmethod
    def _gate_free_exit(start, gates: set, exits: set):
        """First approving exit reachable from ``start`` crossing no gate, or ``None``."""
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
            pp = self._pp_cache = cached_path_predicates(self.prog)
        return pp

    def _type_excludes_field(self, index: int, field: str, assigns: list,
                             reads: dict, app_seeds: set) -> bool:
        """Sibling ``gtxn[index]`` is provably NOT the transfer type this field
        carries, on every approving path through the read, so the value is
        definitionally 0 (inert). Either signal suffices: the COMPLEMENTARY
        receiver is pinned to the app on every such path, or ``TypeEnum`` is
        explicitly pinned to an incompatible type at every reachable exit.

        Suppresses only under a proof holding on ALL relevant paths — anything
        weaker must leave the finding standing."""
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
        exits = approving_exits(self.prog, file=self.file)
        reach = _forward_reachable({a.basic_block for a in assigns
                                    if a.basic_block is not None})
        reachable_exits = [e for e in exits if e in reach]
        if not reachable_exits:
            return False
        from tealql.tealtools.cfg import group as G
        pp = self._pp()
        for e in reachable_exits:
            pinned = _pinned_typeenum(G, pp, e, index)
            if pinned is None or pinned == carrying:
                return False        # unpinned or the carrying type IS possible here
        return True
