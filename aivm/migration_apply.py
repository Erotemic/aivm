"""Removed internal import path for pre-0.6 migration execution.

Import from :mod:`aivm.legacy.pre_0_6_0.migration_apply` instead.  The old
module is kept as a tiny failure surface so overlay-based upgrades cannot leave
a stale copy of the former implementation behind.
"""


def __getattr__(name: str) -> object:
    raise AttributeError(
        f'{name!r} moved to aivm.legacy.pre_0_6_0.migration_apply'
    )
