"""Standalone *pure* Garrett-style identity protocol and decisions.

Only depends on primitives, errors, and pure stdlib. Real TLS, signing,
credential ownership, enrollment storage, broker and VM lifecycle remain
separately trusted adapters. Importing this package performs no I/O.
"""
from .claims import IdentityClaims, IdentityExpectation, assess_binding
from .protocol import IssueIntent, Presentation, prepare_issue, present

__all__ = [
    'IdentityClaims', 'IdentityExpectation', 'assess_binding',
    'IssueIntent', 'Presentation', 'prepare_issue', 'present',
]
