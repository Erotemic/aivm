"""Removed internal path for pre-0.6 virtiofsd-wrapper compatibility.

Use :mod:`aivm.legacy.pre_0_6_0.virtiofsd_wrapper` explicitly.
"""


def __getattr__(name: str) -> object:
    raise AttributeError(
        f'{name!r} moved to aivm.legacy.pre_0_6_0.virtiofsd_wrapper'
    )
