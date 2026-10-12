"""Experimental certificate-bound identity extension for aivm-secrets.

This is an opt-in host-side building block, NOT an enabled AIVM transport.
The deterministic decision rules in ``model`` are designed for a second,
independent safe-Rust implementation and shared conformance vectors.
"""

from .model import IdentityExpectation, IdentityClaims, assess_binding

__all__ = ['IdentityExpectation', 'IdentityClaims', 'assess_binding']
