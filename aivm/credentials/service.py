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
from ..commands import CommandError, CommandManager
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
from ..errors import AIVMError, CommandControlError
from ..vm.connectivity import get_ip_cached
from . import keys, providers
from .errors import ProviderAutomationError
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
    CredentialKind,
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

# Provider automation is a convenience, so a forge being uncooperative --
# unauthenticated, unauthorized, policy-bound, down, or ambiguous -- must not
# stop AIVM from preparing a credential and handing the public key to an
# administrator. This names exactly those failures. It deliberately excludes
# AIVMError: that would also cover CommandControlError, turning "the user said
# no" into "the provider was unhelpful" and installing a key nobody approved.
_RECOVERABLE_PROVIDER_FAILURE = (ProviderAutomationError, CommandError)


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


def _install_and_activate(
    cfg: AgentVMConfig,
    store: Store,
    store_path: Path,
    entry: CredentialEntry,
    repo: GitRepository,
    *,
    manager: CommandManager,
) -> CredentialEntry:
    """Install the private key in the VM and activate it once Git works.

    Guest verification is what actually proves a credential functions: it
    resolves the rewritten URL and reaches the repository over SSH. That check
    is identical whether AIVM created the deploy key itself or a repository
    admin added it, which is what lets a provider-unmanaged grant finish here.
    """
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
    verify = verify_guest_repository(cfg, ip, repo, entry.id, manager=manager)
    if verify.code != 0:
        detail = (verify.stderr or verify.stdout).strip()
        if entry.provider_managed:
            raise AIVMError(
                'The deploy key was registered and installed, but Git access '
                f'from the VM failed: {detail}'
            )
        # Expected while nobody has registered the public key yet: the guest
        # copy authenticates nothing until the provider accepts it. Leave the
        # credential installed and pending rather than failing the command.
        log.info(
            'Credential {} is installed but not usable yet; {} has not '
            'accepted the public key.',
            entry.id,
            repo.display,
        )
        return entry
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


def describe_unregistered_credential(
    entry: CredentialEntry, repo: GitRepository
) -> str:
    """Explain the handoff for a credential AIVM could not publish.

    Everything AIVM can do locally is already done: the keypair exists, the
    private half is in the VM, and Git is configured to use it. Only the public
    half still needs to be accepted by the repository provider, which may
    require an administrator or an out-of-band approval process.
    """
    public_path = keys.host_public_key_path(entry.vm_name, entry.id)
    try:
        public_text = public_path.read_text(encoding='utf-8').strip()
    except OSError:
        public_text = ''
    access = 'write' if entry.access == CREDENTIAL_ACCESS_WRITE else 'read-only'
    provider = providers.provider_label(entry.kind)

    lines = [
        '',
        f'ACTION NEEDED: AIVM could not publish this deploy key to '
        f'{repo.host} automatically.',
        '',
        f'  Provider:    {provider}',
        f'  Credential:  {entry.id} (installed in VM {entry.vm_name}, not '
        'active yet)',
        f'  Repository:  {repo.display}',
        f'  Access:      {access}',
        '',
        f'Send this public key to an administrator of {repo.display} and ask '
        f'them to add it as a deploy key with {access} access:',
        '',
    ]
    if public_text:
        lines.extend([f'  {public_text}', ''])
    lines.extend(
        [
            f'  (also stored at {public_path})',
            f'  suggested title: {entry.provider_key_title}',
            '',
            'Nothing else needs to be run. The private half is already in the '
            'VM and Git is configured to use it, so access begins working as '
            'soon as the provider accepts the public half. Until then the '
            'installed key authenticates nothing.',
            '',
            f'Check with: aivm vm creds status {entry.id}',
            f'Undo with:  aivm vm creds abandon {entry.id}',
        ]
    )
    return '\n'.join(lines)


def _record_unpublished_credential(
    store: Store,
    store_path: Path,
    entry: CredentialEntry,
    repo: GitRepository,
    *,
    kind: CredentialKind,
    reason: str,
) -> CredentialEntry:
    """Record that this run could not administer the provider's deploy key.

    A recorded ``provider_key_id`` is evidence that a key really was published
    once, and it is the only handle ``revoke`` has for deleting it. This run
    failing to reach the provider says nothing about whether that key still
    exists, so the id survives: clearing it would strand a live deploy key
    that AIVM would then refuse to revoke, having convinced itself it never
    registered one. Only a verified deletion, or definitive evidence that the
    remote object is gone, may clear it.
    """
    label = providers.provider_label(kind)
    log.warning(
        'Could not administer the deploy key for {} at {}: {}',
        repo.display,
        label,
        reason,
    )
    if entry.provider_key_id:
        log.warning(
            'Credential {} keeps its recorded {} deploy-key id {} and stays '
            'provider-managed: this run could not inspect the provider, which '
            'is not evidence that the key was removed. Run `aivm vm creds '
            'status {}` once access is restored.',
            entry.id,
            label,
            entry.provider_key_id,
            entry.id,
        )
        return entry
    entry = replace(entry, provider_managed=False, provider_key_id='')
    upsert_credential(store, entry)
    save_store(
        store,
        store_path,
        reason=(
            f'Record credential {entry.id} as provider-unmanaged: AIVM '
            'could not publish or administer its deploy key automatically.'
        ),
    )
    return entry


def grant_repository_credential(
    cfg: AgentVMConfig,
    store: Store,
    store_path: Path,
    repo: GitRepository,
    *,
    access: CredentialAccess,
    kind: CredentialKind = CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    manager: CommandManager,
) -> CredentialEntry:
    # Only the tools that create and install the SSH credential are mandatory.
    # Provider publication is a convenience: missing clients, missing tokens,
    # insufficient permissions, organization policy, and provider-side refusal
    # all become an administrator handoff instead of blocking local progress.
    _require_tools('ssh', 'ssh-keygen', manager=manager)
    access = normalize_credential_access(access)
    write = access == CREDENTIAL_ACCESS_WRITE
    cred_id = credential_id(cfg.vm.name, repo.canonical)
    existing = find_credential(store, vm_name=cfg.vm.name, credential_id=cred_id)
    if existing is not None and existing.access != access:
        raise AIVMError(
            f'Credential {cred_id} already exists with access={existing.access}. '
            'Revoke it before changing access.'
        )
    if existing is not None and existing.kind != kind:
        raise AIVMError(
            f'Credential {cred_id} already exists with kind={existing.kind}. '
            'Revoke it before changing providers.'
        )
    if existing is not None and not credential_is_guest_usable(existing):
        raise AIVMError(
            f'Credential {cred_id} is in state {existing.state!r}. Finish '
            'revocation or abandonment before granting repository access again.'
        )
    entry = existing or CredentialEntry(
        id=cred_id,
        vm_name=cfg.vm.name,
        kind=kind,
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access=access,
        provider_key_title=credential_title(cfg.vm.name, repo, cred_id),
        state=CREDENTIAL_STATE_PENDING,
    )
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

    remote: ProviderDeployKey | None = None
    unregistered_reason = providers.automation_unavailable_reason(
        kind, repo, manager=manager
    )

    if not unregistered_reason:
        with manager.attempt(
            f'Look up an existing deploy key on {repo.host}',
            why='A failed lookup still leaves the key ready to hand over.',
            catch=_RECOVERABLE_PROVIDER_FAILURE,
        ) as lookup:
            remote = providers.find_recorded_provider_key(
                kind, repo, entry, manager=manager
            )
        unregistered_reason = lookup.reason

    if not unregistered_reason and remote is None:
        with manager.attempt(
            f'Publish the deploy key to {repo.host}',
            why=(
                'Provider publication is best effort; refusal or bureaucracy '
                'falls back to an administrator handoff.'
            ),
            catch=_RECOVERABLE_PROVIDER_FAILURE,
        ) as publication:
            remote = providers.add_deploy_key(
                kind,
                repo,
                public_key_path=keys.host_public_key_path(entry.vm_name, entry.id),
                title=entry.provider_key_title,
                write=write,
                manager=manager,
            )
        unregistered_reason = publication.reason

    if unregistered_reason:
        entry = _record_unpublished_credential(
            store,
            store_path,
            entry,
            repo,
            kind=kind,
            reason=unregistered_reason,
        )
        return _install_and_activate(
            cfg, store, store_path, entry, repo, manager=manager
        )

    assert remote is not None
    expected_read_only = not write
    if remote.read_only != expected_read_only:
        raise AIVMError(
            f'{providers.provider_label(kind)} deploy key {remote.key_id} '
            'has the wrong access mode. '
            f'Expected {access}; revoke it before retrying.'
        )
    entry = replace(
        entry,
        provider_key_id=remote.key_id,
        state=CREDENTIAL_STATE_PENDING,
        provider_managed=True,
    )
    upsert_credential(store, entry)
    save_store(
        store,
        store_path,
        reason=(
            f'Record {providers.provider_label(kind)} deploy-key id for '
            f'credential {entry.id}.'
        ),
    )

    return _install_and_activate(
        cfg, store, store_path, entry, repo, manager=manager
    )


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
    except CommandControlError:
        raise
    except AIVMError as ex:
        host_detail = str(ex)
    remote: ProviderDeployKey | None = None
    remote_error = ''
    try:
        repo = entry_repository(entry)
        providers.check_auth(entry.kind, repo, manager=manager)
        remote = providers.find_recorded_provider_key(
            entry.kind, repo, entry, manager=manager
        )
    except CommandControlError:
        # Status is a report, not a recovery: an unreachable provider is a
        # line in the output, but a declined prompt is the user's answer.
        raise
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
    if not entry.provider_managed:
        raise AIVMError(
            f'AIVM never registered credential {entry.id} with '
            f'{entry.provider_host}, so it cannot revoke it and will not '
            'claim to have done so. Ask an administrator of '
            f'{entry.provider_host}/{entry.owner}/{entry.repository} to delete '
            f'the deploy key with fingerprint {entry.key_fingerprint}, then '
            f'run `aivm vm creds abandon {entry.id}` to remove the local and '
            'guest copies.'
        )
    _require_tools(*providers.required_tools(entry.kind), manager=manager)
    repo = entry_repository(entry)
    providers.check_auth(entry.kind, repo, manager=manager)
    remote = providers.find_recorded_provider_key(
        entry.kind, repo, entry, manager=manager
    )
    if remote is not None:
        if entry.provider_key_id and remote.key_id != entry.provider_key_id:
            log.warning(
                'Stored deploy-key id {} drifted to matching id {}.',
                entry.provider_key_id,
                remote.key_id,
            )
        providers.delete_deploy_key(
            entry.kind, repo, remote.key_id, manager=manager
        )
        remaining_remote = providers.find_recorded_provider_key(
            entry.kind, repo, entry, manager=manager
        )
        if remaining_remote is not None:
            raise AIVMError(
                f'{providers.provider_label(entry.kind)} still reports deploy '
                f'key {remaining_remote.key_id} '
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
    except CommandControlError:
        # Abandon deletes the host key and the store record next. Doing that
        # after the user declined the guest cleanup would strand the private
        # key in the VM with nothing left recording that it is there.
        raise
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
