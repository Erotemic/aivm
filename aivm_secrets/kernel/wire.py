"""Compatibility facade over the stand-alone aivm_secrets.primitives.wire.

Security decisions are implemented only in the primitives package.
"""

from ..primitives.wire import (
    VERSION,
    VERBS,
    MAX_CAPABILITY,
    MAX_RESPONSE,
    MAX_REPLY,
    Frame,
    parse_frame,
    success,
    failure,
)

__all__ = ['VERSION', 'VERBS', 'MAX_CAPABILITY', 'MAX_RESPONSE', 'MAX_REPLY', 'Frame', 'parse_frame', 'success', 'failure']
