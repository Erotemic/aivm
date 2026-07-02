"""Privilege and runtime mode enumerations.

These name the small closed sets of strings that flow through the command
manager, config store, and CLI.  They are ``StrEnum`` values so a member
compares equal to its wire string (``PrivilegeMode.SUDOLESS == 'sudoless'``)
and serializes to TOML unchanged --- existing string comparisons keep
working while call sites gain a typo-proof vocabulary.

This module deliberately imports nothing from :mod:`aivm` so the lowest
layers (``commands``) can share the same vocabulary as the policy modules
(``privilege``, ``runtime``) without an import cycle.
"""

from __future__ import annotations

from enum import StrEnum


class PrivilegeMode(StrEnum):
    """How aivm obtains privileges for host operations.

    - AUTO: probe what already works unprivileged, escalate to sudo only
      when needed (the default).
    - SUDO: classic behavior --- privileged host operations run via sudo.
    - SUDOLESS: hard guarantee that aivm never invokes sudo; privileged
      operations must already be reachable unprivileged or they fail.
    """

    AUTO = 'auto'
    SUDO = 'sudo'
    SUDOLESS = 'sudoless'


class RuntimeMode(StrEnum):
    """Which libvirt daemon a VM is managed through.

    - SYSTEM: the privileged system daemon (``qemu:///system``) with a
      managed NAT network, shared storage, and the sudo escalation policy.
    - SESSION: the per-user daemon (``qemu:///session``) with user-owned
      storage, passt networking, and a structural never-sudo guarantee.
    """

    SYSTEM = 'system'
    SESSION = 'session'
