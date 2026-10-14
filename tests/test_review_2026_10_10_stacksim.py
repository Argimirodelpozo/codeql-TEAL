"""Stack-simulation soundness pins from the 2026-10-10 review (branch `rev`).

Four shapes where the simulator claimed a definite constant/range for an
operand the AVM can deliver another value at, with ``health().complete``.
Each test runs the program on an INDEPENDENT concrete AVM-subset interpreter
(below: fails on overflow, underflow, ``retsub`` without a frame, failed
``assert``; no analysis imports) over a small input domain and checks that
the claim CONTAINS every value the oracle observed at the instruction — or
that the simulator refused (missing operand) and ``health()`` says so. A
``partial`` phi is a claim like any other: its listed arms must still cover
the oracle. One test per defect; the single-caller / non-loop / non-recursive
twins ride along as controls so a fix cannot regress the shape it refines.
"""
from __future__ import annotations

import pytest

from tealql.tealtools.analysis import FactDomain
from tealql.tealtools.ssa import SSAProgram, stacksim
from tealql.tealtools.ssa.models import Phi

MAX = 2 ** 64 - 1


class _Fail(Exception):
    pass


def _parse(text):
    ops, labels, lines = [], {}, []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split('//')[0].strip()
        if not line or line.startswith('#'):
            continue
        if line.endswith(':'):
            labels[line[:-1]] = len(ops)
        else:
            ops.append(line.split())
            lines.append(number)
    return ops, labels, lines


def _execute(text, fields, max_steps=5000):
    """Top-of-stack consumed per source line, for one concrete input."""
    ops, labels, lines = _parse(text)
    stack, scratch, frames, consumed = [], [0] * 256, [], {}
    pc = 0

    def u64(v):
        if not 0 <= v <= MAX:
            raise _Fail('arithmetic')
        return v

    def pop():
        if not stack:
            raise _Fail('underflow')
        return stack.pop()

    try:
        for _ in range(max_steps):
            if pc >= len(ops):
                return consumed
            op, *imm = ops[pc]
            line = lines[pc]
            pc += 1
            if op in ('itob', 'store', 'assert', 'pop', '+', '-', 'bz', 'bnz') and stack:
                top = stack[-1]
                consumed.setdefault(line, set()).add(
                    int.from_bytes(top, 'big') if isinstance(top, bytes) else top)
            if op == 'int':
                stack.append(u64(int(imm[0])))
            elif op == 'txn':
                stack.append(fields.get(imm[0], 0))
            elif op == 'dup':
                v = pop()
                stack += [v, v]
            elif op == 'pop':
                pop()
            elif op == 'store':
                scratch[int(imm[0])] = pop()
            elif op == 'load':
                stack.append(scratch[int(imm[0])])
            elif op in ('+', '-'):
                b, a = pop(), pop()
                stack.append(u64(a + b if op == '+' else a - b))
            elif op == 'itob':
                stack.append(pop().to_bytes(8, 'big'))
            elif op == 'log':
                pop()
            elif op == 'b':
                pc = labels[imm[0]]
            elif op in ('bz', 'bnz'):
                if bool(pop()) == (op == 'bnz'):
                    pc = labels[imm[0]]
            elif op == 'callsub':
                frames.append({'ret': pc, 'height': len(stack), 'proto': None})
                pc = labels[imm[0]]
            elif op == 'proto':
                if not frames:
                    raise _Fail('proto outside sub')
                a, r = int(imm[0]), int(imm[1])
                frames[-1]['proto'] = (a, r)
                frames[-1]['height'] = len(stack) - a
            elif op == 'retsub':
                if not frames:
                    raise _Fail('retsub without callsub')
                f = frames.pop()
                if f['proto'] is not None:
                    a, r = f['proto']
                    if len(stack) < f['height'] + a + r:
                        raise _Fail('retsub depth')
                    top = stack[len(stack) - r:] if r else []
                    del stack[f['height']:]
                    stack += top
                pc = f['ret']
            elif op == 'frame_dig':
                if not frames or frames[-1]['proto'] is None:
                    raise _Fail('frame op outside proto')
                a, _r = frames[-1]['proto']
                idx = frames[-1]['height'] + a + int(imm[0])
                if not 0 <= idx < len(stack):
                    raise _Fail('frame_dig range')
                stack.append(stack[idx])
            elif op == 'assert':
                if not pop():
                    raise _Fail('assert')
            elif op == 'return':
                pop()
                return consumed
            else:  # pragma: no cover - the programs below use only these ops
                raise AssertionError(f'oracle: unsupported op {op}')
        return consumed
    except _Fail:
        return consumed


FIELDS = [{'NumAppArgs': n, 'Fee': f} for n in (0, 1, 2, 3) for f in (0, 1)]


def oracle(text, line):
    out = set()
    for fields in FIELDS:
        out |= _execute(text, fields).get(line, set())
    return out


def program(body):
    return SSAProgram.from_text('#pragma version 10\n' + body, name='review.teal', strict=False)


def assignment(p, line, op):
    return next(a for a in p.assignments if a.location.line == line and a.op == op)


def claim(p, line, op):
    """``(operand, range)`` of the top-of-stack operand at ``line`` or
    ``(None, None)`` when the simulator refused to name it."""
    a = assignment(p, line, op)
    if not a.inputs:
        return None, None
    value = a.inputs[0]
    return value, p.facts(FactDomain.CONSTANTS, FactDomain.RANGES).range_at(value, a)


def assert_contains(p, line, op, truth, *, refusal_ok):
    """The claim covers every oracle value, or is an honest, reported refusal."""
    assert truth, 'the oracle never reached the instruction'
    value, rng = claim(p, line, op)
    missing = {d.line for d in p.health().degradations if d.code == 'missing-stack-operand'}
    if value is None:
        assert refusal_ok, f'line {line} {op}: refused where recovery was expected'
        assert line in missing, 'a refused operand must be reported in health'
        return
    assert line not in missing
    if rng is None:
        return                               # unbounded: contains everything
    assert rng.lo <= min(truth) and rng.hi >= max(truth), (
        f'line {line} {op}: claim {rng} excludes oracle values {sorted(truth)}')


# ---------------------------------------------------------------------------
# Finding 1 (regression vs main): a call continuation that is also a loop
# header lost the divergent callee's residual arm.
# ---------------------------------------------------------------------------

_F1 = ('int 55\ntxn NumAppArgs\ncallsub choose\ng:\nassert\nstore 0\nload 0\nitob\nlog\n'
       'txn Fee\nbz g\nint 1\nreturn\nchoose:\nbnz yes\nint 0\nretsub\nyes:\nint 42\nint 1\nretsub\n')


def test_a_loop_header_continuation_keeps_the_divergent_callees_residual_arm():
    """``choose`` returns ``[0]`` or ``[42, 1]`` under the caller's 55. On the
    second lap (Fee == 0) the ``assert`` consumes that 55: the per-path
    shift-merge left the cell BELOW the one-cell return as ``None``, the loop
    header turned that into an empty phi arm, and the public phi claimed
    ``{0, 1}`` — ``partial`` was never propagated through the chain."""
    p = program(_F1)
    truth = oracle('#pragma version 10\n' + _F1, 6)
    assert truth == {0, 1, 55}
    assert_contains(p, 6, 'assert', truth, refusal_ok=False)
    value, rng = claim(p, 6, 'assert')
    assert isinstance(value, Phi) and value.partial, (
        'the cell is absent on the shallow path: the merge must say so')
    assert {a.const_value.value for a in value.args} == {'0', '1', '55'}
    assert (rng.lo, rng.hi) == (0, 55)
    assert p.health().complete

    # Control: the non-loop twin keeps the exact two-valued, non-partial join.
    twin = program(_F1.replace('txn Fee\nbz g\n', ''))
    value, rng = claim(twin, 6, 'assert')
    assert isinstance(value, Phi) and not value.partial
    assert (rng.lo, rng.hi) == (0, 1) and twin.health().complete

    # Mechanism control: a join arm whose VALUE is unknown (a frame read the
    # simulator could not place) must refuse the whole phi, not publish the
    # resolved arm as the answer.
    unknown = program('callsub s\nint 1\nreturn\ns:\nproto 0 1\ntxn Fee\nbz a\n'
                      'frame_dig -3\nb j\na:\nint 3\nj:\nitob\nlog\nint 0\nretsub\n')
    assert claim(unknown, 14, 'itob') == (None, None)
    assert 14 in {d.line for d in unknown.health().degradations
                  if d.code == 'missing-stack-operand'}


# ---------------------------------------------------------------------------
# Finding 2: a callsub target that another routine `b`-branches into was
# owned by that routine, so the call targeting it ran as arity (0, 0).
# ---------------------------------------------------------------------------

_F2 = ('int 5\nint 6\ncallsub helper\nitob\nlog\ncallsub outer\nitob\nlog\nint 1\nreturn\n'
       'outer:\nint 10\nint 20\nb helper\nhelper:\n+\nretsub\n')


def test_a_callsub_target_reached_by_another_routines_branch_owns_itself():
    """``outer`` precedes ``helper`` in source, so its DFS claimed the
    ``helper`` block; ``_callee_of`` then found no self-owned successor for
    ``callsub helper`` and the caller's ``int 6`` passed straight through to
    ``itob`` where the AVM delivers 5 + 6. Every callsub target now owns
    itself; the branch becomes a shared tail executed in both contexts."""
    text = '#pragma version 10\n' + _F2
    p = program(_F2)
    py = p._pyssa
    for block in py.blocks:
        if block.ops and block.ops[-1].op == 'callsub':
            assert stacksim._callee_of(block, py._bb_to_sub) is not None
    assert_contains(p, 5, 'itob', oracle(text, 5), refusal_ok=False)      # {11}
    assert_contains(p, 17, '+', oracle(text, 17), refusal_ok=False)       # {6, 20}
    plus = assignment(p, 17, '+')
    assert {a.const_value.value for a in plus.inputs[0].args} == {'6', '20'}
    assert {a.const_value.value for a in plus.inputs[1].args} == {'5', '10'}
    # The branching routine returns through the foreign tail, so its own
    # caller's continuation is live too: ``outer`` leaves 10 + 20.
    assert_contains(p, 8, 'itob', oracle(text, 8), refusal_ok=False)      # {30}
    assert p.health().complete

    # Control: with ``helper`` first in source the ownership was already
    # right; the claims must be identical.
    twin = program(_F2.replace('outer:\nint 10\nint 20\nb helper\nhelper:\n+\nretsub\n',
                               'helper:\n+\nretsub\nouter:\nint 10\nint 20\nb helper\n'))
    _, rng = claim(twin, 5, 'itob')
    assert (rng.lo, rng.hi) == (11, 30) and twin.health().complete


# ---------------------------------------------------------------------------
# Finding 4 (work-list item 2): a routine entry that is also a loop header
# took the initial stack verbatim and never merged the back edge.
# ---------------------------------------------------------------------------

_F3 = ('int 7\nint 8\ncallsub legacy\nitob\nlog\nint 1\nreturn\nlegacy:\nstore 0\nload 0\n'
       'itob\nlog\ntxn NumAppArgs\nbnz legacy\nint 9\nretsub\n')


def test_a_routine_entry_that_is_a_loop_header_merges_its_back_edge():
    """Lap 1 stores the argument 8; lap 2 stores the caller's 7 underneath
    it. The entry's initial stack is the forward arm of the header merge;
    in a SUB the cell the back edge lacks is the caller's next cell down
    (not an underflow), so the operand is refused and reported."""
    text = '#pragma version 10\n' + _F3
    p = program(_F3)
    assert oracle(text, 10) == {7, 8}
    assert_contains(p, 10, 'store', {7, 8}, refusal_ok=True)
    assert claim(p, 10, 'store') == (None, None)
    assert not p.health().complete
    # The caller's view stays sound: whatever the lap count, the call leaves
    # its 9 on top (the lap-2 dip only shortens what is underneath).
    assert oracle(text, 5) == {9}
    assert_contains(p, 5, 'itob', {9}, refusal_ok=False)
    _, rng = claim(p, 5, 'itob')
    assert (rng.lo, rng.hi) == (9, 9)

    # Same defect with the loop header one block below the entry: the lap-1
    # argument was published as a definite constant (marked partial) where
    # lap 2 stores the caller's 7.
    below_body = (_F3.replace('legacy:\nstore 0', 'legacy:\nint 0\npop\nloop:\nstore 0')
                  .replace('bnz legacy', 'bnz loop'))
    below = program(below_body)
    assert oracle('#pragma version 10\n' + below_body, 13) == {7, 8}
    assert claim(below, 13, 'store') == (None, None) and not below.health().complete

    # Control: in MAIN the model bottom is the physical bottom, so the same
    # loop is exact — the header merges 8 and 7 and lap 3 dies underflowing.
    main = program('int 7\nint 8\nloop:\nstore 0\nload 0\nitob\nlog\ntxn NumAppArgs\n'
                   'bnz loop\nint 1\nreturn\n')
    assert oracle('#pragma version 10\n' + 'int 7\nint 8\nloop:\nstore 0\nload 0\nitob\n'
                  'log\ntxn NumAppArgs\nbnz loop\nint 1\nreturn\n', 5) == {7, 8}
    _, rng = claim(main, 5, 'store')
    assert (rng.lo, rng.hi) == (7, 8) and main.health().complete
    # Control: a main entry that is its own loop header, with nothing to
    # merge on lap 1, still simulates and names the value left after it.
    entry = program('start:\nint 7\ntxn NumAppArgs\nbnz start\npop\nint 1\nreturn\n')
    _, rng = claim(entry, 6, 'pop')
    assert (rng.lo, rng.hi) == (7, 7) and entry.health().complete


# ---------------------------------------------------------------------------
# Finding 3 (work-list item 4): a join reached at two depths inside a legacy
# sub was not divergent, so the caller residual was misaligned.
# ---------------------------------------------------------------------------

_F4 = ('int 55\ntxn NumAppArgs\ncallsub choose\nassert\nstore 0\nload 0\nitob\nlog\nitob\nlog\n'
       'int 1\nreturn\nchoose:\ndup\nbz base\ntxn Fee\nbz direct\nint 1\n-\ncallsub choose\n'
       'join:\nretsub\ndirect:\nint 7\nint 1\nb join\nbase:\npop\nint 42\nint 1\nretsub\n')


def test_a_join_reached_at_two_depths_makes_the_legacy_sub_divergent():
    """``join`` is reached at depth 1 from the recursive call and at depth 2
    from ``direct`` (which does not consume the argument): the sub returns
    ``[n, 7, 1]`` there. Recording only the first-reached depth gave a fixed
    2-cell window, and the second ``itob`` claimed the caller's 55 where the
    AVM delivers ``n``."""
    text = '#pragma version 10\n' + _F4
    p = program(_F4)
    truth = oracle(text, 10)
    assert truth == {1, 2, 3, 55}
    assert ('review.teal', 14, 16) in p._pyssa._divergent_legacy
    assert_contains(p, 10, 'itob', truth, refusal_ok=True)
    value, _ = claim(p, 10, 'itob')
    if value is None:
        assert not p.health().complete
    else:
        # Recovered: the merge lists the caller's 55 and the argument.
        assert isinstance(value, Phi)
        assert p.facts(FactDomain.CONSTANTS).constant(value) is None
    assert_contains(p, 6, 'store', oracle(text, 6), refusal_ok=True)   # {7, 42}

    # Control: the non-recursive twin with the same two-depth join is
    # divergent for the same reason and its caller sees both residual cells.
    twin_body = _F4.replace('txn Fee\nbz direct\nint 1\n-\ncallsub choose\njoin:\nretsub\n'
                            'direct:\nint 7\nint 1\nb join\n', 'int 7\nint 1\nretsub\n')
    twin = program(twin_body)
    assert ('review.teal', 14, 16) in twin._pyssa._divergent_legacy
    assert_contains(twin, 10, 'itob', oracle('#pragma version 10\n' + twin_body, 10),
                    refusal_ok=False)
    value, rng = claim(twin, 10, 'itob')
    assert isinstance(value, Phi) and rng is not None and rng.lo == 0 and rng.hi == 55
    assert twin.health().complete


# ---------------------------------------------------------------------------
# Open: a FORWARD join arm absent inside a subroutine is the caller's cell
# at a fixed depth (recoverable), not an underflow; today it is published as
# a `partial` constant. Strict xfail: whoever recovers it removes the marker.
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason='forward absent arm in a sub reads the caller cell; '
                                       'publish a phi over the caller residual or refuse')
def test_a_forward_absent_arm_inside_a_sub_is_the_callers_cell():
    body = ('int 55\ncallsub s\nint 1\nreturn\ns:\nproto 0 1\ntxn Fee\nbz a\nint 1\nint 2\n'
            'b j\na:\nint 3\nj:\npop\nitob\nlog\nint 0\nretsub\n')
    p = program(body)
    truth = oracle('#pragma version 10\n' + body, 17)
    assert truth == {1, 55}
    assert_contains(p, 17, 'itob', truth, refusal_ok=True)
