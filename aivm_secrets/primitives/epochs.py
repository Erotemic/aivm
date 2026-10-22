"""Pure bounded epoch transitions (PRIM-EPOCH-01).

A transition is monotonic, never wraps and never silently resets epochs.
Durable rollback prevention belongs to the trusted registry adapter.

Every epoch, and every ``maximum``, is a non-negative integer that fits a
signed 64-bit word: a value no ``i64`` can hold is refused rather than
compared, so an implementation with fixed-width integers decides the same.
"""
from __future__ import annotations

from ..errors import SecretsError

MAX_VALUE = 2**63 - 1


def advance(current: int, *, maximum: int = 2**31 - 1) -> int:
    if (type(current) is not int or type(maximum) is not int
            or not 0 <= maximum <= MAX_VALUE
            or not 0 <= current <= maximum):
        raise SecretsError('invalid_capability')
    if current == maximum:
        raise SecretsError('revoked')
    return current + 1


def require_current(actual: int, expected: int) -> None:
    # Equality carries the range check over to ``expected``.
    if (type(actual) is not int or type(expected) is not int
            or not 0 <= actual <= MAX_VALUE or actual != expected):
        raise SecretsError('invalid_capability')
