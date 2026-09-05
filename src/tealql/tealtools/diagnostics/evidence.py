"""Explicit proof subjects, scope and assumptions shared by analysis policies."""
from dataclasses import dataclass

from .location import InstructionPoint


@dataclass(frozen=True)
class GuardEvidence:
    subject: str
    relation: str
    value: str = ""
    point: InstructionPoint | None = None
    scope: tuple[str, ...] = ()
    extent: tuple[int, int] | None = None
    basis: str = "assertion-dependency"
    assumptions: tuple[str, ...] = ()

    @property
    def is_proof(self) -> bool:
        """Dependency on an assertion alone does not establish its predicate."""
        return self.basis in {"constant", "must-predicate", "verified-obligation"}
