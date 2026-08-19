"""Pure attachment policy schema helpers.

This module contains only small, persistence-safe values shared by the
configuration store, user profile, CLI, and runtime attachment layers.  It
must remain independent of VM/runtime implementation details.
"""

from __future__ import annotations

from typing import Literal, cast

MirrorHomePolicy = Literal['auto', 'yes', 'no']

MIRROR_HOME_AUTO: MirrorHomePolicy = 'auto'
MIRROR_HOME_YES: MirrorHomePolicy = 'yes'
MIRROR_HOME_NO: MirrorHomePolicy = 'no'
MIRROR_HOME_POLICIES = frozenset(
    {MIRROR_HOME_AUTO, MIRROR_HOME_YES, MIRROR_HOME_NO}
)


def normalize_mirror_home_policy(value: object) -> MirrorHomePolicy:
    """Normalize a persisted or user-supplied mirror-home policy.

    ``auto`` means inherit the next broader preference.  Boolean spellings are
    accepted for hand-edited TOML compatibility, while the renderer always
    writes the canonical string form.
    """
    if isinstance(value, bool):
        return MIRROR_HOME_YES if value else MIRROR_HOME_NO
    raw = str(value or '').strip().lower().replace('_', '-').replace(' ', '-')
    aliases = {
        '': MIRROR_HOME_AUTO,
        'auto': MIRROR_HOME_AUTO,
        'default': MIRROR_HOME_AUTO,
        'inherit': MIRROR_HOME_AUTO,
        'inherited': MIRROR_HOME_AUTO,
        'yes': MIRROR_HOME_YES,
        'true': MIRROR_HOME_YES,
        'on': MIRROR_HOME_YES,
        '1': MIRROR_HOME_YES,
        'no': MIRROR_HOME_NO,
        'false': MIRROR_HOME_NO,
        'off': MIRROR_HOME_NO,
        '0': MIRROR_HOME_NO,
    }
    normalized = aliases.get(raw)
    if normalized is None:
        allowed = ', '.join(sorted(MIRROR_HOME_POLICIES))
        raise ValueError(
            f'Invalid mirror_home policy {value!r}; expected one of: {allowed}'
        )
    return cast(MirrorHomePolicy, normalized)


def resolve_mirror_home_enabled(
    attachment_policy: object,
    user_preference: object,
    vm_preference: bool,
) -> bool:
    """Resolve attachment -> user -> VM mirror-home policy precedence."""
    attachment = normalize_mirror_home_policy(attachment_policy)
    if attachment == MIRROR_HOME_YES:
        return True
    if attachment == MIRROR_HOME_NO:
        return False

    user = normalize_mirror_home_policy(user_preference)
    if user == MIRROR_HOME_YES:
        return True
    if user == MIRROR_HOME_NO:
        return False

    return bool(vm_preference)
