"""Differential: the clean stacksim vs the incumbent Braun+6c operands.

Compares per-op operand lists in PyVar space. Resolves through the FAT-BAND
rename before comparing, because the incumbent rewrites a frame op into a wide
band whose outputs are fresh vars — the new sim reads the slot directly, so raw
identity would report every frame chain as a disagreement (the trap that has
caught every metric in this codebase).
"""
import sys, glob, random, logging
sys.path.insert(0, "src")
logging.disable(logging.CRITICAL)

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.ssa import PyPhi, PyVar
from tealql.tealtools.ssa import stacksim
from tealql.tealtools.subroutines import pyblock_partition, _pyblock_return_point
from tealql.tealtools.ssa.models import _shuffle_mapping


class _FakePhi:
    __slots__ = ("block", "slot", "args")

    def __init__(self, block, slot):
        self.block, self.slot, self.args = block, slot, []

    def __repr__(self):
        return f"simphi{self.slot}@L{self.block.key[1]}"


def _leaves(v, prod, seen=None):
    """Collapse a value to the set of leaf keys it can stand for, following phis
    and the fat-band shuffle rename."""
    if seen is None:
        seen = set()
    key = id(v)
    if key in seen or v is None:
        return set()
    seen.add(key)
    if isinstance(v, (PyPhi, _FakePhi)):
        out = set()
        for a in getattr(v, "args", ()):
            out |= _leaves(a, prod, seen)
        return out
    if isinstance(v, stacksim._Param):
        return {("param", v.sub_key, v.index)}
    if isinstance(v, PyVar):
        d = prod.get(v.key())
        if d is not None:
            o, i = d
            m = _shuffle_mapping(o)
            if m is not None and i < len(m) and m[i] < len(o.inputs):
                src = o.inputs[m[i]]
                if src is not None:
                    return _leaves(src, prod, seen)
        return {v.key()}
    return {("other", repr(v))}


def check(path):
    prog = SSAProgram(path)
    py = prog._pyssa
    prod = {}
    for b in py.blocks:
        for o in b.ops:
            for i, v in enumerate(o.outputs):
                prod[v.key()] = (o, i)

    part = pyblock_partition(py.blocks)
    rp = _pyblock_return_point(py.blocks)
    res = stacksim.simulate(py.blocks, part, py._proto_io, rp,
                            lambda b, s: _FakePhi(b, s))

    compared = agree = disagree = missing = parambound = 0
    cases = []
    for b in py.blocks:
        for o in b.ops:
            if o.op in ("frame_dig", "frame_bury", "callsub", "retsub",
                        "proto", "intcblock", "bytecblock"):
                continue
            got = res.args.get(id(o))
            if got is None:
                missing += 1
                continue
            if id(o) in res.unresolved:
                continue
            if len(got) != len(o.inputs):
                disagree += 1
                if len(cases) < 4:
                    cases.append((o.line, o.op, "arity", len(o.inputs), len(got)))
                continue
            for i, (old, new) in enumerate(zip(o.inputs, got)):
                if old is None:
                    continue
                compared += 1
                lo, ln = _leaves(old, prod), _leaves(new, prod)
                if any(isinstance(k, tuple) and k and k[0] == "param" for k in ln):
                    # The new sim stops at the routine boundary by design; the
                    # incumbent threads the caller's value inline. Not comparable.
                    parambound += 1
                    compared -= 1
                    continue
                if lo & ln:
                    agree += 1
                else:
                    disagree += 1
                    if len(cases) < 4:
                        cases.append((o.line, o.op, i, repr(old), repr(new)))
    return compared, agree, disagree, missing, cases, parambound


def main():
    random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 4)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    files = random.sample(sorted(glob.glob("tests/mainnet-random-probes/*.teal")), n)
    C = A = D = M = P = 0
    worst = []
    for f in files:
        try:
            c, a, d, m, cases, pb = check(f)
        except Exception as e:
            print(f"  CRASH {f.split('/')[-1]}: {type(e).__name__}: {str(e)[:60]}")
            continue
        C += c; A += a; D += d; M += m; P += pb
        if d:
            worst.append((f.split("/")[-1], d, cases))
    print(f"comparable operands: {C}   agree: {A}   DISAGREE: {D}   "
          f"ops-missing: {M}   param-boundary (excluded): {P}")
    for name, d, cases in sorted(worst, key=lambda x: -x[1])[:4]:
        print(f"  {name}: {d}")
        for c in cases:
            print("      ", c)


main()
