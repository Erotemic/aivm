"""Per-host-user profile state for shared AIVM machines.

The machine store owns VM, network, attachment, and principal declarations.
This module owns only the invoking user's interaction preferences and private
SSH path references.  It intentionally uses a separate small schema rather
than reusing :class:`aivm.config_store.models.Store`, which prevents profile
writes from ever redefining machine state.
"""

from __future__ import annotations

import json
import os
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .attachment_schema import (
    MIRROR_HOME_AUTO,
    normalize_mirror_home_policy,
)
from .config import BehaviorConfig
from .user_paths import user_app_dir

PROFILE_SCHEMA_VERSION = 2
PROFILE_FILE_MODE = 0o600
PROFILE_DIRECTORY_MODE = 0o700


@dataclass
class UserProfileStore:
    """Caller-owned configuration layered over the machine store."""

    schema_version: int = PROFILE_SCHEMA_VERSION
    active_vm: str = ''
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    ssh_identity_file: str = ''
    ssh_pubkey_path: str = ''
    state_dir: str = '~/.cache/aivm'
    # Preferred default for attachments whose mirror_home policy is ``auto``.
    # ``auto`` here defers once more to the selected VM's policy.
    mirror_shared_home_folders: str = MIRROR_HOME_AUTO
    # Used only while creating a VM from global defaults. Once the VM exists,
    # its guest login is authoritative in the persisted principal record.
    default_guest_user: str = 'agent'


def profile_store_path() -> Path:
    """Return the current user's shared-machine profile path."""
    return (
        user_app_dir(
            'aivm',
            'config',
            mode=PROFILE_DIRECTORY_MODE,
        )
        / 'profile.toml'
    )


def _toml_escape(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"')


def render_user_profile(profile: UserProfileStore) -> str:
    """Render one profile as stable TOML."""
    lines = [
        f'schema_version = {int(profile.schema_version)}',
        f'active_vm = "{_toml_escape(profile.active_vm)}"',
        f'ssh_identity_file = "{_toml_escape(profile.ssh_identity_file)}"',
        f'ssh_pubkey_path = "{_toml_escape(profile.ssh_pubkey_path)}"',
        f'state_dir = "{_toml_escape(profile.state_dir)}"',
        f'default_guest_user = "{_toml_escape(profile.default_guest_user)}"',
        'mirror_shared_home_folders = '
        f'"{_toml_escape(normalize_mirror_home_policy(profile.mirror_shared_home_folders))}"',
        '',
        '[behavior]',
        f'yes_sudo = {str(profile.behavior.yes_sudo).lower()}',
        'auto_approve_readonly_sudo = '
        f'{str(profile.behavior.auto_approve_readonly_sudo).lower()}',
        f'verbose = {int(profile.behavior.verbose)}',
        f'privilege_mode = "{_toml_escape(profile.behavior.privilege_mode)}"',
        'credential_directory_permission_policy = '
        f'"{_toml_escape(profile.behavior.credential_directory_permission_policy)}"',
        '',
    ]
    return '\n'.join(lines)


def parse_user_profile(text: str) -> UserProfileStore:
    """Parse a profile, rejecting unsupported future schema versions."""
    raw = tomllib.loads(text) if text.strip() else {}
    version = int(raw.get('schema_version', PROFILE_SCHEMA_VERSION))
    if version > PROFILE_SCHEMA_VERSION:
        raise ValueError(
            f'Unsupported AIVM profile schema version {version}; '
            f'this build supports up to {PROFILE_SCHEMA_VERSION}.'
        )
    profile = UserProfileStore(schema_version=version)
    profile.active_vm = str(raw.get('active_vm', '')).strip()
    profile.ssh_identity_file = str(raw.get('ssh_identity_file', '')).strip()
    profile.ssh_pubkey_path = str(raw.get('ssh_pubkey_path', '')).strip()
    profile.state_dir = str(raw.get('state_dir', '~/.cache/aivm')).strip()
    profile.default_guest_user = str(
        raw.get('default_guest_user', 'agent') or 'agent'
    ).strip()
    profile.mirror_shared_home_folders = normalize_mirror_home_policy(
        raw.get('mirror_shared_home_folders', MIRROR_HOME_AUTO)
    )
    behavior = raw.get('behavior', {})
    if isinstance(behavior, dict):
        for key, value in behavior.items():
            if hasattr(profile.behavior, str(key)):
                setattr(profile.behavior, str(key), value)
    return profile


def load_user_profile(path: Path | None = None) -> UserProfileStore:
    """Load a profile or return defaults when it does not exist."""
    target = (path or profile_store_path()).expanduser().resolve()
    if not target.exists():
        return UserProfileStore()
    if target.is_symlink() or not target.is_file():
        raise RuntimeError(f'Unsafe AIVM profile path: {target}')
    return parse_user_profile(target.read_text(encoding='utf-8'))


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_user_profile(
    profile: UserProfileStore, path: Path | None = None
) -> Path:
    """Atomically save one private profile with mode ``0600``."""
    # Once this build writes the profile, advertise the newest schema it may
    # contain so older builds fail closed instead of silently dropping newer
    # caller-owned preferences on their next save.
    profile.schema_version = max(
        int(profile.schema_version), PROFILE_SCHEMA_VERSION
    )
    target = (path or profile_store_path()).expanduser().resolve()
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=PROFILE_DIRECTORY_MODE,
    )
    os.chmod(target.parent, PROFILE_DIRECTORY_MODE)
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise RuntimeError(f'Unsafe AIVM profile path: {target}')
    text = render_user_profile(profile)
    with tempfile.NamedTemporaryFile(
        'w',
        encoding='utf-8',
        dir=str(target.parent),
        prefix=f'.{target.name}.',
        delete=False,
    ) as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
        tmp = Path(file.name)
    try:
        os.chmod(tmp, PROFILE_FILE_MODE)
        os.replace(tmp, target)
        os.chmod(target, PROFILE_FILE_MODE)
        _fsync_dir(target.parent)
    finally:
        tmp.unlink(missing_ok=True)
    return target


def profile_debug_json(profile: UserProfileStore) -> str:
    """Return a deterministic non-secret representation for diagnostics/tests."""
    payload = {
        'schema_version': profile.schema_version,
        'active_vm': profile.active_vm,
        'ssh_identity_file': profile.ssh_identity_file,
        'ssh_pubkey_path': profile.ssh_pubkey_path,
        'state_dir': profile.state_dir,
        'default_guest_user': profile.default_guest_user,
        'mirror_shared_home_folders': profile.mirror_shared_home_folders,
        'behavior': {
            key: getattr(profile.behavior, key)
            for key in profile.behavior.__dataclass_fields__
        },
    }
    return json.dumps(payload, sort_keys=True)
