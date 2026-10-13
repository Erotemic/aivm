"""Pure equality of externally authenticated identity fields (PRIM-BIND-01).

The primitive cannot determine whether the TLS peer and signed claims are
authentic; only callers with verified inputs may depend on its result.
"""
from __future__ import annotations

from ..errors import SecretsError


def require_match(actual: str, expected: str) -> None:
    if (type(actual) is not str or type(expected) is not str
            or actual != expected):
        raise SecretsError('invalid_capability')
