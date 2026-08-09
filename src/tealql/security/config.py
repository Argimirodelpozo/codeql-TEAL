"""Detection-mode config: is a TEAL artifact an **application** (stateful,
OnCompletion lifecycle) or a **logicsig** (stateless)? Detections are scoped by
it — the lifecycle family is meaningless on a logicsig, ``unsafe-lsig-args`` on
an app.

The mode is DECLARED, never inferred here — opcode heuristics misfire on genuine
logicsigs that read ``ApplicationArgs`` (every proof verifier). An artifact
matching no rule gets ``None``, which callers treat as "run everything".

.. code-block:: yaml

    modes:                                     # first matching rule wins
      - {match: "**/*Verifier.teal", mode: logicsig}
      - {match: ["**/*.approval.teal", "**/approval.teal"], mode: app}
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tealql.tealtools.diagnostics.errors import TealQLError

VALID_MODES = ("app", "logicsig")


class ConfigError(TealQLError, ValueError):
    """An invalid config, raised at LOAD time so a typo fails the run instead of
    silently changing scan coverage."""


def glob_match(path: str, pattern: str) -> bool:
    """``fnmatch`` with the doc-style ``**/`` prefix fixed: fnmatch has no ``**``,
    so a literal ``**/x.teal`` demands a ``/`` and the natural catch-all pattern
    silently missed files at the scan root. Prefix-stripped is retried."""
    if fnmatch.fnmatch(path, pattern):
        return True
    return pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:])


@dataclass(frozen=True)
class ModeRule:
    """One mode declaration: ``match`` globs (see :func:`glob_match`) plus a
    ``mode`` from :data:`VALID_MODES`."""

    match: tuple[str, ...]
    mode: str

    def matches(self, path: str) -> bool:
        return any(glob_match(path, pat) for pat in self.match)


@dataclass(frozen=True)
class DetectionConfig:
    """:class:`ModeRule` list, first-match-wins; empty classifies nothing."""

    rules: tuple[ModeRule, ...] = ()

    @classmethod
    def empty(cls) -> "DetectionConfig":
        return cls(())

    @classmethod
    def from_path(cls, path: Path) -> "DetectionConfig":
        """Load from ``.yml``/``.yaml``/``.json``; only a ``modes:`` section is
        allowed, since a typo'd section would otherwise be ignored wholesale."""
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
        """The declared mode for ``path``, or ``None`` when no rule matches."""
        for rule in self.rules:
            if rule.matches(path):
                return rule.mode
        return None
