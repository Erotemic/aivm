"""Backward-compatible enrollment state-machine API, implemented in Garrett.
"""
from .garrett.registry import (
    SCHEMA, MAX_SUBJECTS, MAX_TIME, validate, enroll, revoke, expectation,
)

__all__ = [
    'SCHEMA', 'MAX_SUBJECTS', 'MAX_TIME', 'validate', 'enroll', 'revoke',
    'expectation',
]
