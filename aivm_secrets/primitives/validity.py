"""Pure half-open time windows (PRIM-TIME-01).

`now` is a trusted caller-provided sample, never read inside the primitive.
"""
from __future__ import annotations

from ..errors import SecretsError

MAX_TIME = 2**63 - 1


def require_active(now: int, not_before: int, expires_at: int,
                   *, code: str = 'invalid_capability') -> None:
    """Require `not_before <= now < expires_at` with exact int types."""
    if (any(type(v) is not int for v in (now, not_before, expires_at))
            or not 0 <= not_before <= MAX_TIME
            or not 0 <= expires_at <= MAX_TIME
            or not not_before <= now < expires_at):
        raise SecretsError(code)
