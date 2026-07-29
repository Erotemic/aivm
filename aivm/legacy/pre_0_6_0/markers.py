"""Semantic markers for code that still handles pre-0.6 compatibility."""

from __future__ import annotations

from typing import TypeVar


T = TypeVar('T')
SUPPORT_BOUNDARY = 'pre_0_6_0'


def compatibility_surface(obj: T) -> T:
    """Mark an otherwise hard-to-extract compatibility surface.

    The decorator changes no execution behavior.  It adds searchable metadata
    so mixed core code remains visibly tied to the pre-0.6 support window.
    Prefer moving implementation into this package over using the marker.
    """
    setattr(obj, '__aivm_legacy_support__', SUPPORT_BOUNDARY)
    return obj
