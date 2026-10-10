"""Best-effort process hardening for the credential-holding broker.

None of this is a security boundary on its own; root and the owning user's
other processes remain trusted (see the design document). It removes two
cheap ways for a credential to leave the process by accident: core dumps,
and ``ptrace``/``/proc/<pid>/mem`` access by an unrelated same-user process.
"""

from __future__ import annotations

import ctypes
import os
import resource
import sys
from pathlib import Path

from .files import Roots, outside

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


def verify_runtime(untrusted: Roots) -> None:
    """Refuse to serve from code the guest could have supplied.

    A broker is only a boundary if the party it constrains cannot choose
    what it runs. This checks where the running interpreter, every entry of
    its module search path and every module already loaded actually came
    from, and refuses if any of them lies under an ``untrusted`` root -- a
    ``PYTHONPATH`` pointing into the shared workspace, a virtualenv or an
    editable install inside it, a stray ``sitecustomize.py``.

    It runs after that code was imported, so it detects rather than
    prevents; a caller that starts the broker for an adversarial guest must
    also start it isolated (``python -I`` and a scrubbed environment), as
    AIVM does. Both halves exist so that neither is the only one.
    """
    if not untrusted:
        return
    # This package first, so that the commonest mistake -- an editable
    # install inside the shared workspace -- is named for what it is.
    outside(Path(__file__), untrusted, what='broker code')
    for place in (sys.executable, sys.prefix, sys.base_prefix):
        outside(Path(place), untrusted, what='broker python environment')
    for entry in sys.path:
        outside(
            Path(entry or os.getcwd()),
            untrusted,
            what='broker module search path entry',
        )
    for name, module in list(sys.modules.items()):
        origin = getattr(module, '__file__', None)
        if isinstance(origin, str):
            what = (
                'broker code'
                if name.split('.')[0] == 'aivm_secrets'
                else f'loaded module {name}'
            )
            outside(Path(origin), untrusted, what=what)
