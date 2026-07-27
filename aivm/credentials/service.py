"""Credential lifecycle orchestration for VM-scoped repository access."""

from __future__ import annotations

import json
import socket
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from loguru import logger as log

from ..attachments.session import _resolve_ip_for_ssh_ops
from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_store import (
    CredentialEntry,
    Store,
    app_data_path,
    find_credential,
    find_credentials_for_vm,
    remove_credential,
    save_store,
    upsert_credential,
)
from ..errors import AIVMError
from ..vm.connectivity import get_ip_cached
from . import github, keys
from .guest import (
    read_guest_public_key,
    reconcile_guest_credentials,
    verify_guest_repository,
)
from .models import GitRepository, ProviderDeployKey
from .schema import (
    CREDENTIAL_ACCESS_WRITE,
    CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    CREDENTIAL_STATE_ABANDON_PENDING,
    CREDENTIAL_STATE_ACTIVE,
    CREDENTIAL_STATE_PENDING,
    CREDENTIAL_STATE_REVOCATION_PENDING,
    CredentialAccess,
    credential_is_guest_usable,
    normalize_credential_access,
)
from .setup import require_credential_tools, require_supported_gh
from .validation import (
    CredentialValidationError,
    credential_id,
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


def _require_tools(*names: str, manager: CommandManager) -> None:
    """Host-tool gate for credential operations; tests patch this seam.

    Presence is not enough for gh: a version predating `gh repo deploy-key`
    would fail later with an opaque "unknown command", so the capability is
    checked here rather than at the point of use.
    """
    require_credential_tools(*names)
    if 'gh' in names:
        require_supported_gh(manager=manager)


def _discard_unstarted_grant(
    store: Store,
    store_path: Path,
    entry: CredentialEntry,
) -> bool:
    """Drop local state for a grant the provider refused outright.

    This is deliberately narrow. AIVM records a pending credential *before*
    calling the provider so a key that does get created can never be
    orphaned, and that invariant must survive here: only a record that has no
    provider key id and never left ``pending`` is discarded, and only after
    the provider has said it created nothing. Guest installation happens
    later in the grant, so such a record owns exactly two artifacts -- the
    host keypair and the store row.

    Returns whether local state was discarded.
    """
    if entry.state != CREDENTIAL_STATE_PENDING or entry.provider_key_id:
        return False
    keys.remove_host_key(entry.vm_name, entry.id)
    remove_credential(store, vm_name=entry.vm_name, credential_id=entry.id)
    save_store(
        store,
        store_path,
        reason=(
            f'Discard credential {entry.id}: the provider refused to create '
            'its deploy key and created nothing.'
        ),
    )
    log.info(
        'Discarded pending credential {} because GitHub created no key.',
        entry.id,
    )
    return True


def _admin_assisted_grant_error(
    entry: CredentialEntry,
    repo: GitRepository,
    ex: github.ProviderPermissionError,
) -> AIVMError:
    """Explain how a repository admin can complete a grant AIVM cannot.

    The keypair already exists on the host, and
    :func:`github.select_recorded_provider_key` adopts a provider key that
    matches the recorded fingerprint. So an admin adding this exact public key
    is enough to let the next `creds add` finish the grant.
    """
    public_path = keys.host_public_key_path(entry.vm_name, entry.id)
    try:
        public_text = public_path.read_text(encoding='utf-8').strip()
    except OSError:
        public_text = ''

    lines = [
        str(ex),
        '',
        f'AIVM kept credential {entry.id} pending, so a repository admin can '
        'add the public key it already generated. Ask an admin to add this '
        f'deploy key to {repo.display} with '
        f'{"write" if entry.access == CREDENTIAL_ACCESS_WRITE else "read-only"}'
        ' access:',
        '',
    ]
    if public_text:
        lines.extend([f'  {public_text}', ''])
    lines.extend(
        [
            f'  (also stored at {public_path})',
            f'  suggested title: {entry.provider_key_title}',
            '',
            'Then rerun `aivm vm creds add` to adopt it. Adoption also reads '
            "the repository's deploy keys, which needs the same admin "
            'permission, so if that is denied too the grant must be run by an '
            'admin. Use `aivm vm creds abandon` to discard the pending '
            'credential instead.',
        ]
    )
    return AIVMError('\n'.join(lines))


def grant_repository_credential(
    cfg: AgentVMConfig,
    store: Store,
    store_path: Path,
    repo: GitRepository,
    *,
    access: CredentialAccess,
    manager: CommandManager,
) -> CredentialEntry:
    _require_tools('gh', 'ssh', 'ssh-keygen', manager=manager)
    # Normalize here too: this is the programmatic entry point, and the CLI
    # Literal is not a hard gate when a caller passes data= directly.
    access = normalize_credential_access(access)
    write = access == CREDENTIAL_ACCESS_WRITE
    cred_id = credential_id(cfg.vm.name, repo.canonical)
    existing = find_credential(store, vm_name=cfg.vm.name, credential_id=cred_id)
    if existing is not None and existing.access != access:
        raise AIVMError(
            f'Credential {cred_id} already exists with access={existing.access}. '
            'Revoke it before changing access.'
        )
    if existing is not None and not credential_is_guest_usable(existing):
        raise AIVMError(
            f'Credential {cred_id} is in state {existing.state!r}. Finish '
            'revocation or abandonment before granting repository access again.'
        )
    entry = existing or CredentialEntry(
        id=cred_id,
        vm_name=cfg.vm.name,
        kind=CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access=access,
        provider_key_title=credential_title(cfg.vm.name, repo, cred_id),
        state=CREDENTIAL_STATE_PENDING,
    )
    github.check_auth(repo, manager=manager)
    entry = keys.generate_host_key(entry, manager=manager)
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

    try:
        remote = github.find_recorded_provider_key(repo, entry, manager=manager)
        if remote is None:
            remote = github.add_deploy_key(
                repo,
                public_key_path=keys.host_public_key_path(
                    entry.vm_name, entry.id
                ),
                title=entry.provider_key_title,
                write=write,
                manager=manager,
            )
    except github.ProviderPermissionError as ex:
        # Keep the pending credential: an admin can add the public key AIVM
        # already generated, and the next run adopts it by fingerprint.
        raise _admin_assisted_grant_error(entry, repo, ex) from ex
    except github.ProviderRejectedError as ex:
        if not _discard_unstarted_grant(store, store_path, entry):
            raise
        raise github.ProviderRejectedError(
            f'{ex} No AIVM credential state was kept for this attempt.'
        ) from ex
    expected_read_only = not write
    if remote.read_only != expected_read_only:
        raise AIVMError(
            f'GitHub deploy key {remote.key_id} has the wrong access mode. '
            f'Expected {access}; revoke it before retrying.'
        )
    entry = replace(
        entry,
        provider_key_id=remote.key_id,
        state=CREDENTIAL_STATE_PENDING,
    )
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
    private_text = keys.host_private_key_path(entry.vm_name, entry.id).read_text(
        encoding='utf-8'
    )
    guest_entries = [
        item
        for item in find_credentials_for_vm(store, cfg.vm.name)
        if credential_is_guest_usable(item)
    ]
    reconcile_guest_credentials(
        cfg,
        ip,
        credentials=guest_entries,
        private_key=(entry.id, private_text),
        manager=manager,
    )
    verify = verify_guest_repository(
        cfg, ip, repo, entry.id, manager=manager
    )
    if verify.code != 0:
        raise AIVMError(
            'The deploy key was registered and installed, but Git access from '
            f'the VM failed: {(verify.stderr or verify.stdout).strip()}'
        )
    entry = replace(entry, state=CREDENTIAL_STATE_ACTIVE)
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
    host_ok = False
    fingerprint_ok = False
    host_detail = ''
    public_text = ''
    try:
        public_text, fingerprint = keys.inspect_host_keypair(
            entry, manager=manager
        )
        host_ok = True
        fingerprint_ok = fingerprint == entry.key_fingerprint
    except AIVMError as ex:
        host_detail = str(ex)
    remote: ProviderDeployKey | None = None
    remote_error = ''
    try:
        repo = entry_repository(entry)
        github.check_auth(repo, manager=manager)
        remote = github.find_recorded_provider_key(repo, entry, manager=manager)
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
                    keys.normalized_public_key(key_result.stdout)
                    == keys.normalized_public_key(public_text)
                )
            except AIVMError:
                guest_key_ok = False
            access_result = verify_guest_repository(
                cfg,
                ip,
                entry_repository(entry),
                entry.id,
                manager=manager,
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
    _require_tools('gh', manager=manager)
    repo = entry_repository(entry)
    github.check_auth(repo, manager=manager)
    remote = github.find_recorded_provider_key(repo, entry, manager=manager)
    if remote is not None:
        if entry.provider_key_id and remote.key_id != entry.provider_key_id:
            log.warning(
                'Stored deploy-key id {} drifted to matching id {}.',
                entry.provider_key_id,
                remote.key_id,
            )
        github.delete_deploy_key(repo, remote.key_id, manager=manager)
        remaining_remote = github.find_recorded_provider_key(
            repo, entry, manager=manager
        )
        if remaining_remote is not None:
            raise AIVMError(
                f'GitHub still reports deploy key {remaining_remote.key_id} '
                'after deletion; refusing local cleanup.'
            )

    entry = replace(entry, state=CREDENTIAL_STATE_REVOCATION_PENDING)
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
        if item.id != entry.id
        and credential_is_guest_usable(item)
    ]
    reconcile_guest_credentials(
        cfg,
        ip,
        credentials=remaining,
        private_key=None,
        remove_credential_id=entry.id,
        manager=manager,
    )
    keys.remove_host_key(entry.vm_name, entry.id)
    remove_credential(store, vm_name=entry.vm_name, credential_id=entry.id)
    save_store(
        store,
        store_path,
        reason=f'Remove revoked repository credential {entry.id}.',
    )


def _write_abandon_tombstone(
    entry: CredentialEntry,
    *,
    guest_cleanup_verified: bool,
    guest_cleanup_error: str,
) -> Path:
    root = app_data_path('credential-tombstones')
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    now = datetime.now(timezone.utc)
    stamp = now.strftime('%Y%m%dT%H%M%S%fZ')
    path = root / f'{entry.id}-{stamp}.json'
    payload = {
        'schema_version': 1,
        'abandoned_at': now.isoformat(),
        'provider_revocation_verified': False,
        'guest_cleanup_verified': guest_cleanup_verified,
        'guest_cleanup_error': guest_cleanup_error,
        'credential': {
            'id': entry.id,
            'vm_name': entry.vm_name,
            'kind': entry.kind,
            'provider_host': entry.provider_host,
            'owner': entry.owner,
            'repository': entry.repository,
            'access': entry.access,
            'provider_key_id': entry.provider_key_id,
            'provider_key_title': entry.provider_key_title,
            'key_fingerprint': entry.key_fingerprint,
        },
    }
    path.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    path.chmod(0o600)
    return path


def abandon_repository_credential(
    cfg: AgentVMConfig,
    store: Store,
    store_path: Path,
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> Path:
    """Remove local credential state without claiming provider revocation."""
    entry = replace(entry, state=CREDENTIAL_STATE_ABANDON_PENDING)
    upsert_credential(store, entry)
    save_store(
        store,
        store_path,
        reason=(
            f'Record provider-unverified abandonment for credential '
            f'{entry.id} before local cleanup.'
        ),
    )

    guest_cleanup_verified = False
    guest_cleanup_error = ''
    try:
        ip = _resolve_ip_for_ssh_ops(
            cfg,
            yes=manager.yes,
            purpose=(
                'Remove a provider-unverified repository credential from '
                'the VM.'
            ),
        )
        remaining = [
            item
            for item in find_credentials_for_vm(store, cfg.vm.name)
            if item.id != entry.id
            and credential_is_guest_usable(item)
        ]
        reconcile_guest_credentials(
            cfg,
            ip,
            credentials=remaining,
            private_key=None,
            remove_credential_id=entry.id,
            manager=manager,
        )
        guest_cleanup_verified = True
    except AIVMError as ex:
        guest_cleanup_error = str(ex)
        log.warning(
            'Could not verify guest cleanup while abandoning credential {}: {}',
            entry.id,
            guest_cleanup_error,
        )
    keys.remove_host_key(entry.vm_name, entry.id)
    tombstone = _write_abandon_tombstone(
        entry,
        guest_cleanup_verified=guest_cleanup_verified,
        guest_cleanup_error=guest_cleanup_error,
    )
    remove_credential(store, vm_name=entry.vm_name, credential_id=entry.id)
    save_store(
        store,
        store_path,
        reason=(
            f'Remove provider-unverified credential {entry.id}; audit '
            f'tombstone={tombstone}.'
        ),
    )
    return tombstone
