"""Canonical local caller identity derived from kernel credentials."""

from __future__ import annotations

import os
import pwd
from dataclasses import dataclass

from .errors import AIVMError


@dataclass(frozen=True)
class HostIdentity:
    """One local caller as identified by the kernel and passwd database."""

    uid: int
    gid: int
    username: str


def current_host_identity() -> HostIdentity:
    """Return the invoking process identity without trusting login variables."""
    uid = int(os.getuid())
    gid = int(os.getgid())
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError as ex:
        raise AIVMError(
            f'No passwd entry exists for invoking uid {uid}; AIVM cannot '
            'attribute this command to a stored access identity.'
        ) from ex
    return HostIdentity(uid=uid, gid=gid, username=username)
