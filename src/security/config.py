"""Detection-mode config.

A TEAL artifact is either an **application** (stateful — approval /
clear-state programs, an OnCompletion lifecycle) or a **logicsig**
(stateless — a logic signature attached to an account). Several
detections only make sense for one mode: the OnCompletion-lifecycle
family (`is-deletable`, `unprotected-updatable`, …) is meaningless for
a logicsig, which has no lifecycle; `unsafe-lsig-args` is meaningless
for an application, which has no `arg` opcodes.

Rather than *infer* the mode from opcode heuristics — which misfires on
genuine logicsigs that happen to read `ApplicationArgs` (every
AlgoPlonk-style proof verifier, for one) — the mode is **declared**
in a config file the caller passes:

.. code-block:: yaml

    # First matching rule wins. `match` is one or more glob patterns
    # tested against the artifact path the caller resolved.
    modes:
      - match: "**/*Verifier.teal"
        mode: logicsig
      - match: ["**/*.approval.teal", "**/approval.teal"]
        mode: app

When an artifact matches no rule (or no config is supplied) the mode is
``None`` — callers treat that as "run every detector, unfiltered". No
inference happens anywhere.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

VALID_MODES = ("app", "logicsig")


@dataclass(frozen=True)
class ModeRule:
    """One mode declaration. ``match`` is one or more ``fnmatch`` glob
    patterns (``*`` matches anything including ``/``, so ``*Verifier*``
    matches at any depth). ``mode`` is one of :data:`VALID_MODES`."""

    match: tuple[str, ...]
    mode: str

    def matches(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pat) for pat in self.match)


@dataclass(frozen=True)
class DetectionConfig:
    """Ordered list of :class:`ModeRule`, evaluated first-match-wins.
    An empty config classifies nothing — every lookup returns ``None``."""

    rules: tuple[ModeRule, ...] = ()

    @classmethod
    def empty(cls) -> "DetectionConfig":
        return cls(())

    @classmethod
    def from_path(cls, path: Path) -> "DetectionConfig":
        """Load from a ``.yml`` / ``.yaml`` / ``.json`` file."""
        text = Path(path).read_text()
        if str(path).endswith((".yml", ".yaml")):
            import yaml
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionConfig":
        rules: list[ModeRule] = []
        for raw in data.get("modes", []):
            match = raw.get("match")
            if match is None:
                raise ValueError(f"mode rule missing 'match': {raw!r}")
            patterns = (match,) if isinstance(match, str) else tuple(match)
            mode = raw.get("mode")
            if mode not in VALID_MODES:
                raise ValueError(
                    f"mode rule has invalid 'mode' {mode!r} "
                    f"(expected one of {VALID_MODES}): {raw!r}"
                )
            rules.append(ModeRule(match=patterns, mode=mode))
        return cls(tuple(rules))

    def mode_for(self, path: str) -> Optional[str]:
        """Return the declared mode for ``path``, or ``None`` if no rule
        matches. ``path`` is whatever string the caller wants to match
        against the config globs (typically the artifact path)."""
        for rule in self.rules:
            if rule.matches(path):
                return rule.mode
        return None
