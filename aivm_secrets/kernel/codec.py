"""Compatibility facade over the stand-alone aivm_secrets.primitives.codec.

Security decisions are implemented only in the primitives package.
"""

from ..primitives.codec import (
    MAX_FRAME,
    MAX_DEPTH,
    _pairs,
    _constant,
    _float,
    _check_depth,
    loads,
    dumps,
    digest,
)

__all__ = ['MAX_FRAME', 'MAX_DEPTH', '_pairs', '_constant', '_float', '_check_depth', 'loads', 'dumps', 'digest']
