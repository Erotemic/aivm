"""Privilege mode enumeration.

This names the small closed set of strings that flows through the command
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
