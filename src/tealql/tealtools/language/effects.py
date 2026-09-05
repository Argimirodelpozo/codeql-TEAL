"""Persistent effects and operand roles, in public SSA's top-first order."""
from dataclasses import dataclass, replace
from types import MappingProxyType


@dataclass(frozen=True)
class StateEffect:
    storage: str
    action: str
    key_index: int
    value_index: int | None
    severity: str
    owner_index: int | None = None

    @property
    def category(self) -> str:
        if self.storage == "box":
            return "box-delete" if self.action == "delete" else "box-write"
        return f"{self.storage}-state-write"


STATE_EFFECTS = {
    "app_global_put": StateEffect("global", "put", 1, 0, "critical"),
    "app_local_put": StateEffect("local", "put", 1, 0, "high"),
    "app_global_del": StateEffect("global", "delete", 0, None, "critical"),
    "app_local_del": StateEffect("local", "delete", 0, None, "high"),
    "box_put": StateEffect("box", "put", 1, 0, "high"),
    "box_create": StateEffect("box", "create", 1, None, "medium"),
    "box_replace": StateEffect("box", "replace", 2, 0, "high"),
    "box_splice": StateEffect("box", "splice", 3, 0, "high"),
    "box_resize": StateEffect("box", "resize", 1, None, "medium"),
    "box_del": StateEffect("box", "delete", 0, None, "medium"),
}

# Foreign box forms prepend an app owner below the original operands, leaving
# the top-first key/value roles unchanged. Availability is not write permission.
from .spec import opcode_spec

STATE_EFFECTS.update({
    'app_' + op: replace(effect, owner_index=len(opcode_spec('app_' + op).args) - 1)
    for op, effect in tuple(STATE_EFFECTS.items()) if effect.storage == 'box'
})
STATE_EFFECTS = MappingProxyType(STATE_EFFECTS)
