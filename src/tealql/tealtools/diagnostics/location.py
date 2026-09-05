"""Structured identities at analysis and presentation boundaries."""
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class InstructionPoint:
    file: str
    line: int
    op: str = ""
    role: str = ""


def split_location(location: str) -> tuple[str | None, int | None]:
    """Decode a legacy file:line string without restricting the filename."""
    file, sep, number = location.rpartition(":")
    if sep and file and number.isascii() and number.isdecimal() and int(number) > 0:
        return file, int(number)
    return None, None
