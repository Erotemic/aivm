"""Best-effort process hardening for the credential-holding broker.

None of this is a security boundary on its own; root and the owning user's
other processes remain trusted (see the design document). It removes two
cheap ways for a credential to leave the process by accident: core dumps,
and ``ptrace``/``/proc/<pid>/mem`` access by an unrelated same-user process.
"""

from __future__ import annotations

import ctypes
import resource

PR_SET_DUMPABLE = 4


def harden_process() -> bool:
    """Disable core dumps and mark the process non-dumpable. Never raises."""
    hardened = True
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        hardened = False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            hardened = False
    except (OSError, AttributeError):
        hardened = False
    return hardened
