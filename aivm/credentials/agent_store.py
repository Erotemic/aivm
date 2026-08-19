"""Pure desired-state and host-key storage for agent credentials.

Host-agent grants live in ``Store.agent_credentials`` and are deliberately
separate from the existing guest-key ``Store.credentials`` collection.  Only
private key material is user-local.  This module has no provider, ssh-agent,
or guest-transport behavior.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

from ..config_store.models import AgentCredentialEntry, Store
from ..config_store.paths import app_data_dir
from ..errors import AIVMError
from .agent_schema import agent_credential_id
from .models import GitRepository


def agent_scope_id(vm_name: str, principal_id: str) -> str:
    import hashlib

    vm = str(vm_name or '').strip()
    if not vm:
        raise AIVMError('Agent credentials require a VM name.')
    principal = str(principal_id or '').strip()
    digest = hashlib.sha256(f'{vm}\0{principal}'.encode('utf-8')).hexdigest()[:20]
    return f'scope-{digest}'


def agent_credential_root() -> Path:
    """Return the user-owned root containing host-only private key material."""
    return app_data_dir() / 'agent-credentials'


def agent_scope_dir(vm_name: str, principal_id: str) -> Path:
    return agent_credential_root() / agent_scope_id(vm_name, principal_id)


def _entries_dir(vm_name: str, principal_id: str) -> Path:
    return agent_scope_dir(vm_name, principal_id) / 'entries'


def _entry_dir(entry: AgentCredentialEntry) -> Path:
    return _entries_dir(entry.vm_name, entry.principal_id) / entry.id


def agent_repository(entry: AgentCredentialEntry) -> GitRepository:
    return GitRepository(
        host=entry.provider_host,
        owner=entry.owner,
        name=entry.repository,
    )


def private_key_path(entry: AgentCredentialEntry) -> Path:
    return _entry_dir(entry) / 'id_ed25519'


def public_key_path(entry: AgentCredentialEntry) -> Path:
    return _entry_dir(entry) / 'id_ed25519.pub'


def _require_private_dir(path: Path, *, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AIVMError(f'{label} must be a real directory: {path}')
    if info.st_uid != os.getuid():
        raise AIVMError(f'{label} is not owned by the current user: {path}')
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise AIVMError(
            f'{label} permissions are too broad: {path} has mode {mode:04o}; '
            'expected 0700.'
        )


def _ensure_private_dir(path: Path, *, label: str) -> None:
    try:
        _require_private_dir(path, label=label)
        return
    except FileNotFoundError:
        pass
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _require_private_dir(path, label=label)


def _ensure_scope_dirs(vm_name: str, principal_id: str) -> Path:
    root = agent_credential_root()
    scope = agent_scope_dir(vm_name, principal_id)
    entries = _entries_dir(vm_name, principal_id)
    _ensure_private_dir(root, label='Agent-credential data directory')
    _ensure_private_dir(scope, label='Agent-credential scope directory')
    _ensure_private_dir(entries, label='Agent-credential entries directory')
    return scope


def _ensure_entry_dir(entry: AgentCredentialEntry) -> Path:
    _ensure_scope_dirs(entry.vm_name, entry.principal_id)
    directory = _entry_dir(entry)
    if os.path.lexists(directory):
        _require_private_dir(directory, label='Agent-credential entry directory')
    else:
        directory.mkdir(mode=0o700)
        _require_private_dir(directory, label='Agent-credential entry directory')
    return directory


def _require_safe_file(
    path: Path, *, label: str, private: bool = True
) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AIVMError(f'{label} must be a regular file: {path}')
    if info.st_uid != os.getuid():
        raise AIVMError(f'{label} is not owned by the current user: {path}')
    mode = stat.S_IMODE(info.st_mode)
    forbidden = 0o077 if private else 0o022
    if mode & forbidden:
        expected = '0600' if private else 'no group/other write access'
        raise AIVMError(
            f'{label} permissions are too broad: {path} has mode {mode:04o}; '
            f'expected {expected}.'
        )


def _remove_key_tree(entry: AgentCredentialEntry) -> None:
    directory = _entry_dir(entry)
    try:
        _require_private_dir(directory, label='Agent-credential entry directory')
    except FileNotFoundError:
        return
    shutil.rmtree(directory)


def list_agent_credentials(
    store: Store, vm_name: str, principal_id: str
) -> tuple[AgentCredentialEntry, ...]:
    principal = str(principal_id or '').strip()
    return tuple(
        sorted(
            (
                entry
                for entry in store.agent_credentials
                if entry.vm_name == vm_name and entry.principal_id == principal
            ),
            key=lambda entry: entry.id,
        )
    )


def list_agent_credentials_for_vm(
    store: Store, vm_name: str
) -> tuple[AgentCredentialEntry, ...]:
    return tuple(
        sorted(
            (entry for entry in store.agent_credentials if entry.vm_name == vm_name),
            key=lambda entry: (entry.principal_id, entry.id),
        )
    )


def find_agent_credential(
    store: Store,
    vm_name: str,
    principal_id: str,
    *,
    credential_id: str = '',
    repo: GitRepository | None = None,
) -> AgentCredentialEntry | None:
    candidates = list_agent_credentials(store, vm_name, principal_id)
    if credential_id:
        matches = [entry for entry in candidates if entry.id == credential_id]
    elif repo is not None:
        matches = [
            entry
            for entry in candidates
            if entry.provider_host.lower() == repo.host.lower()
            and entry.owner.lower() == repo.owner.lower()
            and entry.repository.lower() == repo.name.lower()
        ]
    else:
        raise ValueError('credential_id or repo is required')
    if len(matches) > 1:
        raise AIVMError('Duplicate host-agent credential records were found.')
    return matches[0] if matches else None



__all__ = [
    'AgentCredentialEntry',
    'agent_credential_id',
    'agent_credential_root',
    'agent_repository',
    'agent_scope_dir',
    'agent_scope_id',
    'find_agent_credential',
    'list_agent_credentials',
    'list_agent_credentials_for_vm',
    'private_key_path',
    'public_key_path',
]
