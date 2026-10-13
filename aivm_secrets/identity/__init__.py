"""Experimental certificate-bound identity extension for aivm-secrets.

This is an opt-in host-side building block, NOT an enabled AIVM transport.
The deterministic decisions live in ``identity.garrett`` and have
versioned contracts for an independent future Rust implementation.
"""

from .garrett.claims import IdentityExpectation, IdentityClaims, assess_binding

__all__ = ['IdentityExpectation', 'IdentityClaims', 'assess_binding']
