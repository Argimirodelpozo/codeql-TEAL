"""Immutable TEAL source snapshots shared by parsing, SSA, lift and reports."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Optional


def _numbered_source_name(name: str, ordinal: int) -> str:
    """Add a stable display suffix without hiding the source's extension."""
    slash = name.rfind("/") + 1
    dot = name.rfind(".")
    if dot < slash:
        dot = len(name)
    return f"{name[:dot]}[{ordinal}]{name[dot:]}"


def _read_raw_sources(source) -> tuple[dict[str, bytes], Optional[Path], bool]:
    """Return canonical identities, physical origin, and its captured kind."""
    from ..diagnostics.errors import TargetError, TargetNotFoundError

    if isinstance(source, Mapping):
        resolved = [
            (str(name), text.encode("utf-8") if isinstance(text, str) else bytes(text))
            for name, text in source.items()
        ]
        basenames: dict[str, int] = {}
        for rel, _data in resolved:
            base = Path(rel).name
            basenames[base] = basenames.get(base, 0) + 1
        out: dict[str, bytes] = {}
        used: set[str] = set()
        for rel, data in resolved:
            base = Path(rel).name
            preferred = (
                Path(rel).as_posix() if basenames.get(base, 0) > 1 else base
            )
            name = preferred
            ordinal = 2
            while name in used:
                # Mapping keys are opaque source identities.  Distinct spellings
                # such as ``./approval.teal`` and ``approval.teal`` may collapse
                # through Path normalization, but their programs must not.
                name = _numbered_source_name(preferred, ordinal)
                ordinal += 1
            used.add(name)
            out[name] = data
        return out, None, False

    path = Path(source).resolve()
    if path.is_file() and path.suffix == ".teal":
        return {path.name: path.read_bytes()}, path, False
    if path.is_file():
        raise TargetError(f"{path}: not a .teal file")
    if path.is_dir():
        out = {
            file.relative_to(path).as_posix(): file.read_bytes()
            for file in sorted(path.rglob("*.teal"))
        }
        if out:
            return out, path, True
        raise TargetNotFoundError(f"no .teal files found under {path}")
    raise TargetNotFoundError(f"no .teal files found under {path}")


@dataclass(frozen=True)
class SourceFile:
    """One reported TEAL file, before and after parser normalization."""

    name: str
    raw: bytes
    normalized: bytes
    digest: str

    @classmethod
    def build(cls, name: str, raw: bytes, normalized: bytes) -> "SourceFile":
        return cls(name, raw, normalized, hashlib.sha256(raw).hexdigest())

    def text(self, *, normalized: bool = False) -> str:
        data = self.normalized if normalized else self.raw
        return data.decode("utf-8", "replace")

    def lines(self, *, normalized: bool = False) -> tuple[str, ...]:
        return tuple(self.text(normalized=normalized).splitlines())


@dataclass(frozen=True)
class ProgramSources:
    """Content-addressed source bundle captured at graph construction time."""

    files: tuple[SourceFile, ...]
    origin: Optional[Path]
    origin_is_directory: bool
    digest: str

    @classmethod
    def load(
        cls,
        source,
        *,
        normalize: Callable[[bytes], bytes] = lambda data: data,
    ) -> "ProgramSources":
        raw, origin, origin_is_directory = _read_raw_sources(source)
        files = tuple(
            SourceFile.build(name, data, normalize(data))
            for name, data in sorted(raw.items())
        )
        h = hashlib.sha256()
        for file in files:
            h.update(file.name.encode("utf-8", "surrogatepass"))
            h.update(b"\0")
            h.update(file.raw)
            h.update(b"\0")
        return cls(files, origin, origin_is_directory, h.hexdigest())

    @classmethod
    def empty(cls, origin: Optional[Path] = None) -> "ProgramSources":
        return cls((), origin, False, hashlib.sha256(b"").hexdigest())

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(file.name for file in self.files)

    def _file(self, name: str) -> Optional[SourceFile]:
        return next((file for file in self.files if file.name == name), None)

    def raw_bytes(self) -> dict[str, bytes]:
        return {file.name: file.raw for file in self.files}

    def normalized_bytes(self) -> dict[str, bytes]:
        return {file.name: file.normalized for file in self.files}

    def text(self, name: str, *, normalized: bool = False) -> Optional[str]:
        file = self._file(name)
        return file.text(normalized=normalized) if file is not None else None

    def line_map(self, *, normalized: bool = False) -> dict[str, tuple[str, ...]]:
        return {file.name: file.lines(normalized=normalized) for file in self.files}

    def select(self, names) -> "ProgramSources":
        wanted = frozenset(names)
        files = tuple(file for file in self.files if file.name in wanted)
        h = hashlib.sha256()
        for file in files:
            h.update(file.name.encode("utf-8", "surrogatepass"))
            h.update(b"\0")
            h.update(file.raw)
            h.update(b"\0")
        # A one-file projection keeps the historical per-file ``source_path``
        # without consulting the filesystem again. The captured origin kind is
        # load-time metadata: editing, renaming, or deleting the target cannot
        # change the program's identity later.
        origin = self.origin
        origin_is_directory = self.origin_is_directory
        if origin is not None and origin_is_directory and len(files) == 1:
            origin = origin / files[0].name
            origin_is_directory = False
        return ProgramSources(files, origin, origin_is_directory, h.hexdigest())

    def physical_path(self, name: str) -> Optional[Path]:
        if self.origin is None:
            return None
        if not self.origin_is_directory:
            return self.origin if len(self.files) == 1 and self.files[0].name == name else None
        return self.origin / name

    @property
    def label(self) -> str:
        return str(self.origin) if self.origin is not None else "<memory>"


__all__ = ["ProgramSources", "SourceFile"]
