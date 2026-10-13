"""Pure bounded epoch transitions (PRIM-EPOCH-01).

A transition is monotonic, never wraps and never silently resets epochs.
Durable rollback prevention belongs to the trusted registry adapter.
"""
from __future__ import annotations

from ..errors import SecretsError


def advance(current: int, *, maximum: int = 2**31 - 1) -> int:
    if (type(current) is not int or type(maximum) is not int
            or maximum < 0 or not 0 <= current <= maximum):
        raise SecretsError('invalid_capability')
    if current == maximum:
        raise SecretsError('revoked')
    return current + 1


def require_current(actual: int, expected: int) -> None:
    if (type(actual) is not int or type(expected) is not int
            or actual < 0 or expected < 0 or actual != expected):
        raise SecretsError('invalid_capability')
