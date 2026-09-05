"""Random mainnet probe sweep that PERSISTS every contract it fetches.

Samples diverse mainnet apps, saves each approval program's disassembled TEAL to
``tests/mainnet-random-probes/app_<id>.teal`` (a growing regression corpus), then
lifts -> recompiles -> dryruns the lift against the contract's DEPLOYED bytecode
(not a reassembly of the disasm -- some valid contracts don't survive the strict
assembler round-trip; see :func:`compare.compare`). Reports faithful / divergent /
lift-fail per contract.

    python -m tests.behavioral_lift.sweep_probes [count]

Probes are kept (teal only) so a contract that surfaced a bug becomes a permanent
test case. Re-runs skip ids already on disk for the dryrun but never re-delete.

A fetched program is saved only when its CONTENT is new. Skipping by app id is
not enough -- mainnet templates are deployed thousands of times under different
ids, so id-only dedup let the corpus grow to 929 files holding 141 distinct
programs. Redundancy costs more than disk: it skews every corpus-wide
measurement toward whichever template happens to be popular.
"""
from __future__ import annotations

import hashlib
import signal
import sys
from pathlib import Path

from . import compare as C
from tealql.tealtools._utils.chain import fetch_approval
from .sampling import sample

PROBES = Path(__file__).resolve().parents[2] / "tests" / "mainnet-random-probes"
class _Timeout(Exception):
    pass


def _pragma_version(teal: str) -> str:
    first = teal.lstrip().splitlines()[0] if teal.strip() else ""
    return first.split("version")[-1].strip() if "version" in first else "?"


def _validate(az, clear, aid, teal, bc, tally: dict) -> None:
    """Lift -> recompile -> dryrun vs deployed bytecode; record into ``tally``
    (keys faithful/diverge/liftfail/compfail). The probe teal is already saved."""
    nl = teal.count("\n")
    try:
        lifted = C.lift_to_teal(str(PROBES / f"app_{aid}.teal"))
    except Exception as e:
        signal.alarm(0)
        tally["liftfail"] += 1
        print(f"LIFTFAIL {aid} ({nl}L): {type(e).__name__}: {str(e)[:60]}", flush=True)
        return
    try:
        lb = C._compile(az, lifted)
    except Exception as e:
        signal.alarm(0)
        tally["compfail"] += 1
        print(f"COMPFAIL {aid} ({nl}L): {str(e)[:60]}", flush=True)
        return
    inputs = [[]] + [[s] for s in C._selectors(lifted)] + [[b"\x01\x02\x03\x04"]]
    result = C.compare_bytecode(az, bc, lb, clear, inputs,
                                C.required_effects(teal, lifted))
    signal.alarm(0)
    status = result["status"]
    key = {"DIVERGES": "diverge", "FAITHFUL": "faithful", "INCONCLUSIVE": "inconclusive"}[status]
    tally[key] = tally.get(key, 0) + 1
    print(f"{status} {aid} (v{_pragma_version(teal)}, {nl}L) "
          f"completed={result['completed']} errors={result['errors']} "
          f"diverge={result['diverge']} {result['diffs'][:3]}", flush=True)


def _corpus_hashes() -> set:
    """Content hashes of every probe already on disk."""
    return {hashlib.sha256(p.read_bytes()).hexdigest()
            for p in PROBES.glob("*.teal")}


def _run(az, clear, ids: list, tally: dict, seen_hashes: set | None = None) -> None:
    seen_hashes = _corpus_hashes() if seen_hashes is None else seen_hashes
    for aid in ids:
        signal.alarm(220)
        try:
            teal, bc = fetch_approval(aid)
            # PERSIST the probe -- but only when it is a program we do not
            # already have. Skipping by app id (which `sample` does) is not
            # enough: mainnet templates are deployed thousands of times under
            # different ids, so every "new" id was saved even when its bytecode
            # was byte-identical to a probe already on disk. That is how 929
            # committed files came to hold 141 distinct programs -- 6.6x of pure
            # redundancy, which also silently skews any corpus-wide measurement
            # toward whichever template happens to be popular.
            h = hashlib.sha256(teal.encode()).hexdigest()
            if h in seen_hashes:
                tally["dupe"] = tally.get("dupe", 0) + 1
                signal.alarm(0)
                continue
            seen_hashes.add(h)
            (PROBES / f"app_{aid}.teal").write_text(teal)
            _validate(az, clear, aid, teal, bc, tally)
        except _Timeout:
            tally["skip"] += 1
            print(f"TIMEOUT {aid}", flush=True)
        except Exception as e:
            signal.alarm(0)
            tally["skip"] += 1
            print(f"SKIP {aid}: {type(e).__name__}: {str(e)[:45]}", flush=True)


def _corpus_versions() -> dict:
    from collections import Counter
    c = Counter()
    for p in PROBES.glob("app_*.teal"):
        try:
            c[_pragma_version(p.read_text())] += 1
        except Exception:
            pass
    return dict(c)


def main(argv) -> int:
    PROBES.mkdir(parents=True, exist_ok=True)
    az = C.algod_client()
    clear = C._compile(az, "#pragma version 10\nint 1")
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))
    have = {int(p.stem.split("_")[1]) for p in PROBES.glob("app_*.teal")}
    # Content hashes, so a program already on disk is not saved again under a
    # different app id -- see the note in `_run`.
    seen_hashes = _corpus_hashes()
    tally = dict(faithful=0, diverge=0, liftfail=0, compfail=0, skip=0, dupe=0)

    if argv and argv[0] == "byver":
        # Fetch broadly, keeping a contract only while its AVM version is still
        # under `target`; balances the corpus across versions. `max_fetch` caps
        # disassembles spent hunting rare (old/newest) versions.
        target = int(argv[1]) if len(argv) > 1 else 8
        max_fetch = int(argv[2]) if len(argv) > 2 else 300
        per_ver = _corpus_versions()
        print(f"corpus versions: {dict(sorted(per_ver.items()))} ; target {target}/ver", flush=True)
        cand = sample(pages=12, skip=have)
        print(f"{len(cand)} candidate new ids; fetching to balance versions", flush=True)
        fetched = 0
        for aid in cand:
            if fetched >= max_fetch:
                break
            if all(per_ver.get(str(v), 0) >= target for v in range(2, 12)):
                break                       # every v2..v11 satisfied
            signal.alarm(220)
            try:
                teal, bc = fetch_approval(aid)
                fetched += 1
                ver = _pragma_version(teal)
                if per_ver.get(ver, 0) >= target:
                    signal.alarm(0)
                    continue                # this version already has enough
                h = hashlib.sha256(teal.encode()).hexdigest()
                if h in seen_hashes:        # same PROGRAM under another id
                    signal.alarm(0)
                    continue
                seen_hashes.add(h)
                (PROBES / f"app_{aid}.teal").write_text(teal)
                _validate(az, clear, aid, teal, bc, tally)
                per_ver[ver] = per_ver.get(ver, 0) + 1
            except _Timeout:
                tally["skip"] += 1
                print(f"TIMEOUT {aid}", flush=True)
            except Exception as e:
                signal.alarm(0)
                tally["skip"] += 1
                print(f"SKIP {aid}: {type(e).__name__}: {str(e)[:45]}", flush=True)
        print(f"\nfetched {fetched} ; final versions: {dict(sorted(_corpus_versions().items()))}",
              flush=True)
    else:
        count = int(argv[0]) if argv else 60
        pages, ids = 1, []
        while len(ids) < count and pages <= 12:
            ids = sample(pages=pages, skip=have)
            pages += 1
        ids = ids[:count]
        print(f"sampled {len(ids)} NEW ids ({len(have)} already in corpus) -> {PROBES}", flush=True)
        _run(az, clear, ids, tally, seen_hashes)

    kept = len(list(PROBES.glob("*.teal")))
    distinct = len(_corpus_hashes())
    print(f"\n=== faithful={tally['faithful']} diverge={tally['diverge']} "
          f"liftfail={tally['liftfail']} compfail={tally['compfail']} skip={tally['skip']} "
          f"inconclusive={tally.get('inconclusive', 0)} dupe={tally.get('dupe', 0)} "
          f"| corpus now {kept} probes, {distinct} DISTINCT programs ===", flush=True)
    return 1 if tally["diverge"] else 2 if any(tally.get(k, 0) for k in ("inconclusive", "liftfail", "compfail", "skip")) or not tally["faithful"] else 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    raise SystemExit(main(sys.argv[1:]))
