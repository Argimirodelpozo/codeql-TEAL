"""Unit tests for ``subroutines.identify_subroutines`` — the CFG analysis that
recovers subroutine entries, bodies, and ``callsub``→continuation wiring
(consumed by ``structure.analyze_structure`` → the lift).

It reads only a small duck-typed interface (``prog.labels``, ``prog.blocks``, and
per-block ``.first_line`` / ``.assignments`` / ``.successors``), so these run on
hand-built mock CFGs. They pin the core wiring plus the behaviours needed for
real contracts: reentrant entries resolved from the
``callsub`` label when the CFG edge is absent, never-returning callees getting no
continuation, and a continuation mis-picked inside the callee's own body being
dropped and refilled from the real retsub target.
"""
from tealql.tealtools.cfg.subroutines import identify_subroutines


class _Loc:
    def __init__(self, line: int, file: str = "t.teal"):
        self.file = file
        self.line = line


class _Op:
    def __init__(self, op: str, line: int, imm: str = ""):
        self.op = op
        self.immediates = imm
        self.location = _Loc(line)


class _BB:
    def __init__(self, first_line: int, *ops: _Op):
        self.first_line = first_line
        self.assignments = list(ops)
        self.successors: list = []


class _Prog:
    def __init__(self, blocks, labels=()):
        self.blocks = {i: b for i, b in enumerate(blocks)}
        self.labels = list(labels)


def test_basic_callsub_retsub_wiring():
    # main: `callsub sub1` (L1) → continuation `return` (L2); sub1 entry is a
    # single `retsub` (L10). retsub's CFG successor is the return point.
    m = _BB(1, _Op("callsub", 1, "sub1"))
    c = _BB(2, _Op("return", 2))
    e = _BB(10, _Op("retsub", 10))
    m.successors = [e]          # callsub → entry
    e.successors = [c]          # retsub → continuation (the return edge)
    info = identify_subroutines(_Prog([m, c, e]))
    assert info["entries"] == {e}
    assert info["callsub_target"][m] is e
    assert info["continuations"][m] is c


def test_reentrant_entry_resolved_by_label():
    # The `callsub → entry` CFG edge is absent (reentrant sub whose entry block
    # merged into a loop header); the entry is recovered from the `callsub sub1`
    # immediate via prog.labels.
    m = _BB(1, _Op("callsub", 1, "sub1"))
    c = _BB(2, _Op("return", 2))
    e = _BB(10, _Op("retsub", 10))
    e.successors = [c]          # m.successors deliberately empty
    info = identify_subroutines(_Prog([m, c, e], labels=[("t.teal", 10, "sub1:")]))
    assert info["entries"] == {e}
    assert info["callsub_target"][m] is e


def test_non_returning_callee_has_no_continuation():
    # The callee ends in `return` (never `retsub`) — it doesn't return, so its
    # callsub gets NO continuation; heuristic-1's next-source guess is dropped.
    m = _BB(1, _Op("callsub", 1, "sub1"))
    c = _BB(2, _Op("return", 2))        # spurious next-source guess
    e = _BB(10, _Op("return", 10))      # callee path ends in return, not retsub
    m.successors = [e]
    info = identify_subroutines(_Prog([m, c, e]))
    assert info["callsub_target"][m] is e
    assert info["continuations"][m] is None


def test_body_stops_at_retsub():
    # body = intraprocedural reachability entry→retsub; the continuation past the
    # retsub is NOT part of the body.
    m = _BB(1, _Op("callsub", 1, "sub1"))
    c = _BB(2, _Op("return", 2))
    e = _BB(10, _Op("int", 10))         # entry (non-terminator → falls through)
    b = _BB(11, _Op("int", 11))
    r = _BB(12, _Op("retsub", 12))
    m.successors = [e]
    e.successors = [b]
    b.successors = [r]
    r.successors = [c]
    info = identify_subroutines(_Prog([m, c, e, b, r]))
    assert info["bodies"][e] == {e, b, r}


def test_one_sub_two_call_sites():
    # One entry, two callsub sites; each call site gets its own continuation.
    m1 = _BB(1, _Op("callsub", 1, "sub1"))
    c1 = _BB(2, _Op("return", 2))
    m2 = _BB(3, _Op("callsub", 3, "sub1"))
    c2 = _BB(4, _Op("return", 4))
    e = _BB(10, _Op("retsub", 10))
    m1.successors = [e]
    m2.successors = [e]
    e.successors = [c1, c2]
    info = identify_subroutines(_Prog([m1, c1, m2, c2, e]))
    assert info["entries"] == {e}
    assert info["callsub_target"][m1] is e
    assert info["callsub_target"][m2] is e
    assert info["continuations"][m1] is c1
    assert info["continuations"][m2] is c2


def test_continuation_in_callee_body_dropped_and_refilled():
    # The linker placed the callee body right after the callsub, so heuristic-1
    # mis-picks a callee block (B, not a retsub target) as the continuation. It's
    # dropped (it's in the callee's pure body) and heuristic-2 refills the real
    # continuation C from the retsub target.
    m = _BB(1, _Op("callsub", 1, "sub1"))
    e = _BB(2, _Op("int", 2))           # entry, immediately after the callsub
    b = _BB(3, _Op("int", 3))           # callee body block (heuristic-1's bad pick)
    r = _BB(4, _Op("retsub", 4))
    c = _BB(5, _Op("return", 5))        # the real continuation (retsub target)
    m.successors = [e]
    e.successors = [b]
    b.successors = [r]
    r.successors = [c]
    info = identify_subroutines(_Prog([m, e, b, r, c]))
    assert info["callsub_target"][m] is e
    assert info["bodies"][e] == {e, b, r}
    assert info["continuations"][m] is c        # not the mis-picked b


def test_nested_callsub_body_includes_continuation():
    # subA itself calls subB: subA's body must include the continuation of its
    # internal callsub (spliced in via the cut-callsub model), so the block that
    # runs after the inner call — before subA's own retsub — stays in subA rather
    # than leaking to the frame-less main flow.
    m = _BB(1, _Op("callsub", 1, "subA"))
    c = _BB(2, _Op("return", 2))
    ea = _BB(10, _Op("callsub", 10, "subB"))    # subA entry: calls subB
    ca = _BB(11, _Op("retsub", 11))             # subA's after-inner-call block
    eb = _BB(20, _Op("retsub", 20))             # subB entry
    m.successors = [ea]
    ea.successors = [eb]
    ca.successors = [c]
    eb.successors = [ca]
    info = identify_subroutines(_Prog([m, c, ea, ca, eb]))
    assert info["entries"] == {ea, eb}
    assert info["continuations"][ea] is ca
    assert info["bodies"][ea] == {ea, ca}       # inner call's continuation spliced in
