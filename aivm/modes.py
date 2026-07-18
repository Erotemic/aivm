"""Privilege mode enumeration and normalization.

This names the small closed set of strings that flows through the command
manager, config store, and CLI.  ``PrivilegeMode`` is a ``StrEnum`` so a
member compares equal to its wire string
(``PrivilegeMode.NEVER == 'never'``) and serializes to TOML unchanged.

All three values answer the same question --- *when does aivm invoke
sudo?* --- so they read as an ordered scale rather than three unrelated
words.

This module imports only :mod:`aivm.errors` (itself a leaf), so the lowest
layers (``commands``) can share the vocabulary with the policy modules
(``privilege``) without an import cycle.
"""

from __future__ import annotations

from enum import StrEnum

from .errors import PrivilegeModeError


class PrivilegeMode(StrEnum):
    """When aivm invokes sudo for privileged host operations.

    - NEVER: refuse rather than escalate. Operations with no unprivileged
      implementation (nftables, apt-get, a *new* ``mount --bind``) fail
      with guidance. An assertion, suited to CI, not a daily posture.
    - AS_NEEDED: probe what already works unprivileged and escalate only
      where required (the default).
    - ALWAYS: escalate for every privileged-capable operation.
    """

    NEVER = 'never'
    AS_NEEDED = 'as-needed'
    ALWAYS = 'always'


#: The default when ``behavior.privilege_mode`` is unset or empty.
DEFAULT_PRIVILEGE_MODE = PrivilegeMode.AS_NEEDED

PRIVILEGE_MODES = tuple(m.value for m in PrivilegeMode)


def normalize_privilege_mode(value: object) -> PrivilegeMode:
    """Coerce a configured privilege mode, defaulting when unset.

    An unset or empty value means "not configured" and yields the default.
    A non-empty value that names no mode is an error rather than a silent
    fallback: every fallback would have to guess, and guessing wrong on a
    privilege setting means escalating when the user asked us not to.
    """
    raw = str(value or '').strip().lower()
    if not raw:
        return DEFAULT_PRIVILEGE_MODE
    try:
        return PrivilegeMode(raw)
    except ValueError:
        raise PrivilegeModeError(
            f'Unknown behavior.privilege_mode {str(value)!r}.\n'
            f'Valid values: {", ".join(PRIVILEGE_MODES)}\n'
            'aivm does not guess a privilege mode: picking one for you would '
            'mean either escalating when you asked it not to, or refusing '
            'work you expected to succeed.'
        ) from None
