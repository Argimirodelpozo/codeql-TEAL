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

from tealtools.errors import TealQLError

VALID_MODES = ("app", "logicsig")


class ConfigError(TealQLError, ValueError):
    """A detection config file is invalid — bad schema, unknown detector
    name, contradictory rule. Raised at LOAD time so a typo fails the run
    instead of silently changing scan coverage."""


def glob_match(path: str, pattern: str) -> bool:
    """``fnmatch`` with the doc-style ``**/`` prefix fixed. ``fnmatch`` has
    no ``**``: a literal ``**/x.teal`` demands a ``/`` in the path, so the
    natural catch-all pattern silently missed files sitting at the scan
    root. A ``**/``-prefixed pattern therefore also matches with the prefix
    stripped. (Plain ``*`` already crosses ``/`` in fnmatch.)"""
    if fnmatch.fnmatch(path, pattern):
        return True
    return pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:])


@dataclass(frozen=True)
class ModeRule:
    """One mode declaration. ``match`` is one or more ``fnmatch`` glob
    patterns (``*`` matches anything including ``/``, so ``*Verifier*``
    matches at any depth; a ``**/`` prefix also matches at the root).
    ``mode`` is one of :data:`VALID_MODES`."""

    match: tuple[str, ...]
    mode: str

    def matches(self, path: str) -> bool:
        return any(glob_match(path, pat) for pat in self.match)


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
        """Load from a ``.yml`` / ``.yaml`` / ``.json`` file. The file may
        contain only a ``modes:`` section — an unknown top-level key is a
        :class:`ConfigError` (a typo'd section would otherwise be ignored
        wholesale)."""
        text = Path(path).read_text()
        if str(path).endswith((".yml", ".yaml")):
            import yaml
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        unknown = set(data) - {"modes"}
        if unknown:
            raise ConfigError(
                f"{path}: unknown top-level key(s) {sorted(unknown)} "
                f"(a mode config holds only 'modes:')")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionConfig":
        rules: list[ModeRule] = []
        for raw in data.get("modes", []):
            unknown = set(raw) - {"match", "mode"}
            if unknown:
                raise ConfigError(
                    f"mode rule has unknown key(s) {sorted(unknown)}: {raw!r}")
            match = raw.get("match")
            if match is None:
                raise ConfigError(f"mode rule missing 'match': {raw!r}")
            patterns = (match,) if isinstance(match, str) else tuple(match)
            mode = raw.get("mode")
            if mode not in VALID_MODES:
                raise ConfigError(
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
