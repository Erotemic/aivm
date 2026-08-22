"""Compatibility for installations created before AIVM 0.6.0.

This package owns the released per-user-store adapter and the explicit
migration workflow into the 0.6 machine/profile architecture.  Imports from
this namespace are deliberate compatibility surfaces and should disappear
when pre-0.6 support is retired.
"""

from .markers import compatibility_surface

__all__ = ['compatibility_surface']
