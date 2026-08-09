"""Shared projection/cache plumbing for pre-IR lift entry points."""
from __future__ import annotations


_MISSING = object()


class LifterRequest:
    """One cache slot and optional single-file projection for a lift request."""

    __slots__ = ("prog", "file", "projected", "cache")

    def __init__(self, prog, file=None):
        self.prog = prog
        self.file = file
        self.projected = len(getattr(prog, "source_files", ())) > 1 and file is not None
        if self.projected:
            cache = getattr(prog, "_ir_lifters_by_file", None)
            if cache is None:
                cache = {}
                try:
                    prog._ir_lifters_by_file = cache
                except AttributeError:
                    pass
            self.cache = cache
        else:
            self.cache = None

    def lookup(self):
        """Return ``(hit, value)`` for the program's CURRENT revision.

        Cached ``None`` is a real hit only for the revision whose failed build
        produced it; a later pass is allowed to make the lift succeed.
        """
        revision = getattr(self.prog, "revision", 0)
        if self.cache is not None:
            entry = self.cache.get(self.file, _MISSING)
            if entry is _MISSING or not isinstance(entry, tuple) or entry[0] != revision:
                value = _MISSING
            else:
                value = entry[1]
        elif getattr(self.prog, "_ir_lifter_revision", _MISSING) == revision:
            value = getattr(self.prog, "_ir_lifter", _MISSING)
        else:
            value = _MISSING
        return value is not _MISSING, None if value is _MISSING else value

    def target(self):
        return (self.prog.for_file(self.file, strict=False)
                if self.projected else self.prog)

    def store(self, lifter) -> None:
        try:
            revision = getattr(self.prog, "revision", 0)
            if self.cache is not None:
                self.cache[self.file] = (revision, lifter)
            else:
                self.prog._ir_lifter = lifter
                self.prog._ir_lifter_revision = revision
        except AttributeError:
            pass
