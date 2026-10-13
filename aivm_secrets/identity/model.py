"""Backward-compatible identity claim imports; the sole implementation
lives in `identity.garrett.claims`.
"""
from .garrett.claims import (
    B64URL, MAX_EPOCH, MAX_IDENTITY_LIFETIME,
    IdentityClaims, IdentityExpectation, assess_binding,
)

__all__ = [
    'B64URL', 'MAX_EPOCH', 'MAX_IDENTITY_LIFETIME',
    'IdentityClaims', 'IdentityExpectation', 'assess_binding',
]
