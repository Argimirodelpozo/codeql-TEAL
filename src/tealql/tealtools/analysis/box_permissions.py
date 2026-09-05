"""AVM 13 box permission obligations for an explicit closed call environment.

The supplied frames include inherited family-state marks. This is a conditional
check at an access, not an inferred inter-contract execution or resource proof.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..diagnostics.health import AnalysisDegradation, AnalysisHealth, AnalysisResult


@dataclass(frozen=True)
class BoxApplication:
    id: int
    creator: str
    foreign_reads: bool
    family_access: bool


@dataclass(frozen=True)
class BoxCallFrame:
    app: int
    family_state_used: bool


@dataclass(frozen=True)
class BoxPermission:
    permitted: bool | None
    owner: int
    minimum_balance_owner: int | None
    marks_family_state: bool
    reason: str


def box_permission(apps, frames, owner, *, write, version=13):
    apps = tuple(apps)
    by_id = {app.id: app for app in apps}
    if (version != 13 or type(write) is not bool or type(owner) is not int
            or len(by_id) != len(apps) or not frames or owner not in by_id
            or any(type(a.id) is not int or a.id <= 0 or not isinstance(a.creator, str) or not a.creator
                   or type(a.foreign_reads) is not bool or type(a.family_access) is not bool for a in apps)
            or any(type(f.app) is not int or f.app not in by_id or type(f.family_state_used) is not bool for f in frames)
            or len({f.app for f in frames}) != len(frames)):
        return AnalysisResult(BoxPermission(None, owner, None, False, 'incomplete or invalid call environment'),
            AnalysisHealth((AnalysisDegradation('box-environment', 'requires AVM 13, unique app identities and every active frame'),)))
    current, owning = by_id[frames[-1].app], by_id[owner]
    family = current.creator == owning.creator
    shared = owning.family_access and family
    permitted = (current.id == owner or shared or not write and owning.foreign_reads)
    reason = 'owner/family/read permission' if permitted else 'owner has not granted this permission'
    if write and shared:
        # Scan outward from the current frame. Once a non-family frame is
        # crossed, any marked family ancestor forbids this write. Owner writes
        # run the same check when family sharing is enabled.
        foreign_between = False
        for frame in reversed(frames[:-1]):
            if by_id[frame.app].creator != current.creator:
                foreign_between = True
            elif foreign_between and frame.family_state_used:
                permitted, reason = False, 'marked family ancestor separated by a non-family frame'
                break
    return AnalysisResult(BoxPermission(permitted, owner, owner if write else None,
                                       shared, reason), AnalysisHealth())


def inherit_family_mark(apps, caller, returned):
    """Apply the protocol's same-creator mark inheritance on a matched return."""
    by_id = {a.id: a for a in apps}
    return BoxCallFrame(caller.app, caller.family_state_used or (
        by_id[caller.app].creator == by_id[returned.app].creator and returned.family_state_used))


def box_access_permissions(program, apps, frames, *, application_refs):
    """Extract static box accesses, requiring an explicit app-reference mapping.

    Frames describe the environment at each access. Callers analyzing multiple
    sites must supply conservative inherited marks, or query sites separately.
    """
    from .context import FactDomain
    from ..language.effects import STATE_EFFECTS
    from ..language.spec import opcode_spec
    from ..ssa import const_int
    from ..diagnostics.health import health_for
    facts = program.facts(FactDomain.CONSTANTS)
    out = []
    degradations = list(health_for(program).degradations)
    for assignment in program.assignments:
        if not assignment.op.startswith(('box_', 'app_box_')):
            continue
        foreign = assignment.op.startswith('app_box_')
        spec = opcode_spec(assignment.op)
        effect = STATE_EFFECTS.get(assignment.op)
        key_index = effect.key_index if effect else len(spec.args) - 1 - int(foreign)
        key = facts.constant(assignment.inputs[key_index]) if len(assignment.inputs) > key_index else None
        owner = frames[-1].app if frames else None
        if foreign:
            raw = const_int(facts.constant(assignment.inputs[-1])) if len(assignment.inputs) == len(spec.args) else None
            owner = application_refs.get(raw)
        permission = box_permission(apps, frames, owner, write=effect is not None)
        degradations.extend(permission.degradations)
        out.append((assignment.location, key, permission))
    return AnalysisResult(tuple(out), AnalysisHealth(tuple(dict.fromkeys(degradations))))


@dataclass(frozen=True)
class TracedBoxAccess:
    app: int
    line: int
    stack: tuple[BoxCallFrame, ...]
    permission: BoxPermission


def trace_box_permissions(programs, apps, root, *, application_refs=None, max_steps=4096, max_depth=8):
    """Infer family marks through closed, straight-line inner application calls.

    Root is an outer approval with no active caller frames. Creator identities,
    permission flags and app-reference mappings describe the supplied AVM 13
    environment. Marks and matched return inheritance are derived
    from the code. Results are conditional on execution reaching each access;
    resource availability and guard feasibility are separate obligations.
    """
    from .context import FactDomain
    from .execution_trace import execution_trace
    from ..language.effects import STATE_EFFECTS
    from ..ssa import const_int
    apps = tuple(apps)
    by_id = {app.id: app for app in apps}
    references = application_refs or {}
    accesses, notes = [], []
    remaining = max_steps

    def unknown(message, app=None, line=None):
        notes.append(AnalysisDegradation('box-trace', message, str(app) if app is not None else None, line))
        return False

    def walk(app, frames):
        nonlocal remaining
        if app not in programs or app not in by_id or len(frames) > max_depth or any(f.app == app for f in frames):
            return unknown('missing, recursive, or depth-limited application target', app), None
        current = BoxCallFrame(app, False)
        frames = (*frames, current)
        trace = execution_trace(programs[app], max_steps=max(0, remaining))
        if not trace.complete:
            return unknown(trace.reason, app), None
        facts = programs[app].facts(FactDomain.CONSTANTS)
        pending = None
        for assignment in trace.operations:
            remaining -= 1
            if remaining < 0:
                return unknown('instruction budget exhausted', app), None
            op = assignment.op
            if op == 'app_params_set':
                return unknown('permission or program parameters may change', app, assignment.location.line), None
            if op in {'assert', 'return'} and assignment.inputs and const_int(facts.constant(assignment.inputs[0])) == 0:
                return False, current
            if op == 'err':
                return False, current
            if op.startswith(('box_', 'app_box_')):
                owner = app
                if op.startswith('app_box_'):
                    raw = const_int(facts.constant(assignment.inputs[-1])) if assignment.inputs else None
                    owner = app if raw == 0 else references.get(app, {}).get(raw)
                result = box_permission(apps, frames, owner, write=op in STATE_EFFECTS)
                notes.extend(result.degradations)
                accesses.append(TracedBoxAccess(app, assignment.location.line, frames, result.value))
                if result.value.permitted is not True:
                    return False, current
                if result.value.marks_family_state:
                    current = BoxCallFrame(app, True)
                    frames = (*frames[:-1], current)
            if op == 'itxn_begin':
                if pending is not None:
                    return unknown('nested unsubmitted transaction builder', app), None
                pending = [{}]
            elif op == 'itxn_next':
                if pending is None or len(pending) >= 16:
                    return unknown('invalid or oversized inner group', app), None
                pending.append({})
            elif op == 'itxn_field':
                if pending is None or len(assignment.inputs) != 1:
                    return unknown('inner field without a complete builder', app), None
                # Only scalar fields affect target and completion selection.
                if assignment.immediates.strip() in {'TypeEnum', 'ApplicationID', 'OnCompletion'}:
                    pending[-1][assignment.immediates.strip()] = const_int(facts.constant(assignment.inputs[0]))
            elif op == 'itxn_submit':
                if pending is None:
                    return unknown('inner submit without a builder', app), None
                for transaction in pending:
                    kind = transaction.get('TypeEnum')
                    if kind not in {1, 2, 3, 4, 5, 6}:
                        return unknown('inner transaction type is unresolved', app), None
                    if kind != 6:
                        continue
                    if transaction.get('OnCompletion', 0) != 0:
                        return unknown('inner lifecycle transition is outside the fixed-program environment', app), None
                    accepted, child = walk(transaction.get('ApplicationID'), frames)
                    if not accepted:
                        return False, current
                    current = inherit_family_mark(apps, current, child)
                    frames = (*frames[:-1], current)
                pending = None
        return True, current

    environment = box_permission(apps, [BoxCallFrame(root, False)], root, write=False)
    if not environment.complete:
        notes.extend(environment.degradations)
    elif len(by_id) != len(apps) or root not in by_id:
        unknown('app identities are missing or duplicated')
    else:
        walk(root, ())
    return AnalysisResult(tuple(accesses), AnalysisHealth(tuple(dict.fromkeys(notes))))
