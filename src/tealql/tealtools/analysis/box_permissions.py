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
    if (version != 13 or len(by_id) != len(apps) or not frames or owner not in by_id
            or any(f.app not in by_id for f in frames) or len({f.app for f in frames}) != len(frames)):
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
