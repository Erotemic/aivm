"""Credential lifecycle orchestration for VM-scoped repository access."""

from __future__ import annotations

import shutil
import socket
from dataclasses import replace
from pathlib import Path
from typing import TypedDict

from loguru import logger as log

from ..attachments.session import _resolve_ip_for_ssh_ops
from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_store import (
    CredentialEntry,
    Store,
    find_credential,
    find_credentials_for_vm,
    remove_credential,
    save_store,
    upsert_credential,
)
from ..errors import AIVMError
from ..vm.connectivity import get_ip_cached
from . import github
from .guest import (
    read_guest_public_key,
    reconcile_guest_credentials,
    verify_guest_repository,
)
from .keys import (
    credential_id,
    host_credential_dir,
    host_private_key_path,
    host_public_key_path,
    normalized_public_key,
    public_key_fingerprint,
)
from .models import GitRepository, ProviderDeployKey
from .validation import (
    CredentialValidationError,
    validate_credential_identity,
    validate_metadata_text,
)


class CredentialStatus(TypedDict):
    """Observed host, provider, and guest state for one credential."""

    host_ok: bool
    fingerprint_ok: bool
    host_detail: str
    remote: ProviderDeployKey | None
    remote_error: str
    guest: str
    guest_detail: str


def credential_title(vm_name: str, repo: GitRepository, cred_id: str) -> str:
    host = socket.gethostname().split('.')[0]
    title = f'aivm:{host}:{vm_name}:{repo.owner}/{repo.name}:{cred_id}'
    try:
        return validate_metadata_text('provider_key_title', title)
    except CredentialValidationError as ex:
        raise AIVMError(str(ex)) from ex


def entry_repository(entry: CredentialEntry) -> GitRepository:
    try:
        return validate_credential_identity(
            vm_name=entry.vm_name,
            cred_id=entry.id,
            provider_host=entry.provider_host,
            owner=entry.owner,
            repository=entry.repository,
        )
    except CredentialValidationError as ex:
        raise AIVMError(str(ex)) from ex


def _credential_matches_repo(
    entry: CredentialEntry, repo: GitRepository
) -> bool:
    return (
        entry.provider_host.lower() == repo.host.lower()
        and entry.owner.lower() == repo.owner.lower()
        and entry.repository.lower() == repo.name.lower()
    )


def select_credential(
    store: Store,
    *,
    vm_name: str,
    selector: str,
    repo: GitRepository | None = None,
) -> CredentialEntry:
    exact = find_credential(store, vm_name=vm_name, credential_id=selector)
    if exact is not None:
        return exact
    if repo is not None:
        matches = [
            item
            for item in find_credentials_for_vm(store, vm_name)
            if _credential_matches_repo(item, repo)
        ]
        if len(matches) == 1:
            return matches[0]
    raise AIVMError(
        f'Credential not found for VM {vm_name!r}: {selector!r}'
    )


def _require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise AIVMError(
            'Missing host command(s) required for VM credentials: '
            + ', '.join(missing)
        )


def _provider_key_fingerprint(key: ProviderDeployKey) -> str:
    try:
        return public_key_fingerprint(key.key)
    except AIVMError as ex:
        raise AIVMError(
            f'GitHub deploy key {key.key_id or "<unknown>"} has malformed '
            'public-key data; refusing to make an identity decision.'
        ) from ex


def _select_remote_key(
    entry: CredentialEntry,
    keys: list[ProviderDeployKey],
) -> ProviderDeployKey | None:
    """Resolve provider state from immutable recorded identity metadata.

    The host-side public-key file is intentionally not consulted here. It is a
    mutable cache that may be missing or tampered with. Revocation must identify
    the provider key from the stored provider id and cryptographic fingerprint.
    """
    if not entry.key_fingerprint:
        raise AIVMError(
            f'Credential {entry.id} has no recorded key fingerprint; refusing '
            'to identify or revoke a provider key.'
        )

    if entry.provider_key_id:
        by_id = [
            item for item in keys if item.key_id == entry.provider_key_id
        ]
        if len(by_id) > 1:
            raise AIVMError(
                'GitHub returned duplicate deploy-key id '
                f'{entry.provider_key_id!r}.'
            )
        if by_id:
            match = by_id[0]
            actual = _provider_key_fingerprint(match)
            if actual != entry.key_fingerprint:
                raise AIVMError(
                    f'GitHub key id {entry.provider_key_id} no longer matches '
                    'the fingerprint recorded by AIVM; refusing to touch it.'
                )
            return match

    by_fingerprint = [
        item
        for item in keys
        if _provider_key_fingerprint(item) == entry.key_fingerprint
    ]
    if len(by_fingerprint) > 1:
        raise AIVMError(
            f'Multiple GitHub deploy keys match credential {entry.id}. '
            'Refusing to choose one.'
        )
    if by_fingerprint:
        return by_fingerprint[0]

    title_matches = [
        item for item in keys if item.title == entry.provider_key_title
    ]
    if title_matches:
        raise AIVMError(
            f'A GitHub deploy key uses title {entry.provider_key_title!r}, but '
            'its fingerprint does not match AIVM state.'
        )
    return None


def _find_remote_key(
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> ProviderDeployKey | None:
    repo = entry_repository(entry)
    keys = github.list_deploy_keys(repo, manager=manager)
    return _select_remote_key(entry, keys)


def _generate_host_key(
    entry: CredentialEntry, *, manager: CommandManager
) -> CredentialEntry:
    private_path = host_private_key_path(entry.vm_name, entry.id)
    public_path = host_public_key_path(entry.vm_name, entry.id)
    if private_path.exists() and public_path.exists():
        public_text = public_path.read_text(encoding='utf-8')
        actual_fingerprint = public_key_fingerprint(public_text)
        if entry.key_fingerprint and actual_fingerprint != entry.key_fingerprint:
            raise AIVMError(
                f'Host public key for credential {entry.id} does not match the '
                'fingerprint recorded by AIVM. Refusing to adopt changed key '
                'material; revoke or repair it explicitly.'
            )
        return replace(entry, key_fingerprint=actual_fingerprint)
    if private_path.exists() or public_path.exists():
        raise AIVMError(
            f'Credential keypair is incomplete under {private_path.parent}. '
            'Remove the partial directory or revoke the pending credential.'
        )
    directory = private_path.parent
    with manager.step(
        f'Generate scoped deploy key {entry.id}',
        why='Create a unique SSH keypair for one VM and one repository.',
        approval_scope=f'vm-credential-key:{entry.id}',
    ):
        manager.submit(
            ['mkdir', '-p', str(directory)],
            role='modify',
            summary='Create host credential directory',
        )
        manager.submit(
            ['chmod', '700', str(directory)],
            role='modify',
            summary='Protect host credential directory',
        )
        manager.submit(
            [
                'ssh-keygen',
                '-q',
                '-t',
                'ed25519',
                '-N',
                '',
                '-f',
                str(private_path),
                '-C',
                entry.provider_key_title,
            ],
            role='modify',
            summary='Generate repository-scoped SSH keypair',
            detail=f'private={private_path} public={public_path}',
        )
        manager.submit(
            ['chmod', '600', str(private_path)],
            role='modify',
            summary='Protect host deploy-key private key',
        )
        manager.submit(
            ['chmod', '644', str(public_path)],
            role='modify',
            summary='Set host deploy-key public key permissions',
        )
    public_text = public_path.read_text(encoding='utf-8')
    return replace(entry, key_fingerprint=public_key_fingerprint(public_text))


def grant_repository_credential(
    cfg: AgentVMConfig,
    store: Store,
    store_path: Path,
    repo: GitRepository,
    *,
    write: bool,
    manager: CommandManager,
) -> CredentialEntry:
    _require_tools('gh', 'ssh', 'ssh-keygen')
    access = 'write' if write else 'read'
    cred_id = credential_id(cfg.vm.name, repo.canonical)
    existing = find_credential(store, vm_name=cfg.vm.name, credential_id=cred_id)
    if existing is not None and existing.access != access:
        raise AIVMError(
            f'Credential {cred_id} already exists with access={existing.access}. '
            'Revoke it before changing access.'
        )
    entry = existing or CredentialEntry(
        id=cred_id,
        vm_name=cfg.vm.name,
        kind='github-deploy-key',
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access=access,
        provider_key_title=credential_title(cfg.vm.name, repo, cred_id),
        state='pending',
    )
    github.check_auth(repo, manager=manager)
    entry = _generate_host_key(entry, manager=manager)
    upsert_credential(store, entry)
    store.schema_version = max(store.schema_version, 8)
    save_store(
        store,
        store_path,
        reason=(
            f'Record pending repository credential {entry.id} '
            f'for VM {cfg.vm.name}.'
        ),
    )

    remote = _find_remote_key(entry, manager=manager)
    if remote is None:
        remote = github.add_deploy_key(
            repo,
            public_key_path=host_public_key_path(entry.vm_name, entry.id),
            title=entry.provider_key_title,
            write=write,
            manager=manager,
        )
    expected_read_only = not write
    if remote.read_only != expected_read_only:
        raise AIVMError(
            f'GitHub deploy key {remote.key_id} has the wrong access mode. '
            f'Expected {access}; revoke it before retrying.'
        )
    entry = replace(entry, provider_key_id=remote.key_id, state='pending')
    upsert_credential(store, entry)
    save_store(
        store,
        store_path,
        reason=f'Record GitHub deploy-key id for credential {entry.id}.',
    )

    ip = _resolve_ip_for_ssh_ops(
        cfg,
        yes=manager.yes,
        purpose='Install the repository-scoped private key in the VM.',
    )
    private_text = host_private_key_path(entry.vm_name, entry.id).read_text(
        encoding='utf-8'
    )
    guest_entries = [
        item
        for item in find_credentials_for_vm(store, cfg.vm.name)
        if item.state != 'revocation-pending'
    ]
    reconcile_guest_credentials(
        cfg,
        ip,
        credentials=guest_entries,
        private_key=(entry.id, private_text),
        manager=manager,
    )
    verify = verify_guest_repository(cfg, ip, repo, manager=manager)
    if verify.code != 0:
        raise AIVMError(
            'The deploy key was registered and installed, but Git access from '
            f'the VM failed: {(verify.stderr or verify.stdout).strip()}'
        )
    entry = replace(entry, state='active')
    upsert_credential(store, entry)
    save_store(
        store,
        store_path,
        reason=(
            f'Activate repository credential {entry.id} after guest '
            'verification.'
        ),
    )
    return entry


def inspect_credential(
    cfg: AgentVMConfig,
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> CredentialStatus:
    private_path = host_private_key_path(entry.vm_name, entry.id)
    public_path = host_public_key_path(entry.vm_name, entry.id)
    host_ok = private_path.exists() and public_path.exists()
    fingerprint_ok = False
    host_detail = ''
    public_text = ''
    if public_path.exists():
        try:
            public_text = public_path.read_text(encoding='utf-8').strip()
            fingerprint_ok = (
                public_key_fingerprint(public_text) == entry.key_fingerprint
            )
        except (AIVMError, OSError, UnicodeError) as ex:
            public_text = ''
            host_detail = str(ex)
    remote: ProviderDeployKey | None = None
    remote_error = ''
    try:
        github.check_auth(entry_repository(entry), manager=manager)
        remote = _find_remote_key(entry, manager=manager)
    except Exception as ex:
        remote_error = str(ex)
    guest = 'unchecked'
    guest_detail = ''
    ip = get_ip_cached(cfg)
    if ip and host_ok:
        key_result = read_guest_public_key(
            cfg, ip, entry.id, manager=manager
        )
        if key_result.code == 0:
            try:
                guest_key_ok = (
                    normalized_public_key(key_result.stdout)
                    == normalized_public_key(public_text)
                )
            except AIVMError:
                guest_key_ok = False
            access_result = verify_guest_repository(
                cfg, ip, entry_repository(entry), manager=manager
            )
            guest = 'ok' if guest_key_ok and access_result.code == 0 else 'drift'
            guest_detail = (access_result.stderr or '').strip()
        else:
            guest = 'unavailable'
            guest_detail = (key_result.stderr or key_result.stdout).strip()
    return {
        'host_ok': host_ok,
        'fingerprint_ok': fingerprint_ok,
        'host_detail': host_detail,
        'remote': remote,
        'remote_error': remote_error,
        'guest': guest,
        'guest_detail': guest_detail,
    }


def revoke_repository_credential(
    cfg: AgentVMConfig,
    store: Store,
    store_path: Path,
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> None:
    _require_tools('gh')
    repo = entry_repository(entry)
    github.check_auth(repo, manager=manager)
    remote = _find_remote_key(entry, manager=manager)
    if remote is not None:
        if entry.provider_key_id and remote.key_id != entry.provider_key_id:
            log.warning(
                'Stored deploy-key id {} drifted to matching id {}.',
                entry.provider_key_id,
                remote.key_id,
            )
        github.delete_deploy_key(repo, remote.key_id, manager=manager)
        remaining_remote = _find_remote_key(entry, manager=manager)
        if remaining_remote is not None:
            raise AIVMError(
                f'GitHub still reports deploy key {remaining_remote.key_id} '
                'after deletion; refusing local cleanup.'
            )

    entry = replace(entry, state='revocation-pending')
    upsert_credential(store, entry)
    save_store(
        store,
        store_path,
        reason=(
            f'Record provider revocation for credential {entry.id} before '
            'guest cleanup.'
        ),
    )

    ip = _resolve_ip_for_ssh_ops(
        cfg,
        yes=manager.yes,
        purpose='Remove the revoked repository credential from the VM.',
    )
    remaining = [
        item
        for item in find_credentials_for_vm(store, cfg.vm.name)
        if item.id != entry.id and item.state != 'revocation-pending'
    ]
    reconcile_guest_credentials(
        cfg,
        ip,
        credentials=remaining,
        private_key=None,
        remove_credential_id=entry.id,
        manager=manager,
    )
    try:
        shutil.rmtree(host_credential_dir(entry.vm_name, entry.id))
    except FileNotFoundError:
        pass
    remove_credential(store, vm_name=entry.vm_name, credential_id=entry.id)
    save_store(
        store,
        store_path,
        reason=f'Remove revoked repository credential {entry.id}.',
    )
