"""Operational lifecycle for shared-machine access identities.

The machine store records host-to-guest access identities (internally called
principals).  This module owns the state-changing lifecycle rules so CLI code,
future daemon code, and tests share one fail-closed implementation.
"""

from __future__ import annotations

import getpass
from dataclasses import dataclass, replace
from typing import Literal

from .commands import CommandManager
from .config import AgentVMConfig
from .config_store import (
    PrincipalEntry,
    Store,
    find_principal,
    find_principal_for_host,
    find_principals_for_vm,
    find_vm,
    materialize_vm_cfg,
    remove_principal,
    upsert_principal,
)
from .errors import AIVMError
from .guestctl import BOOTSTRAP_GUEST_USER, GuestAccessRequest
from .machine_store import current_machine_group_gid, machine_resource_locks
from .profile_store import save_user_profile
from .runtime import ssh_base_args
from .scoped_store import (
    StoreScope,
    load_scope_profile,
    load_scope_store,
    save_scope_store,
)

TRUST_MODE = 'trusted-host-users'
AccessAction = Literal['disable', 'remove']


@dataclass(frozen=True)
class AccessOwnershipSummary:
    """Machine records retained for one access identity."""

    attachment_count: int = 0
    credential_count: int = 0

    @property
    def has_owned_records(self) -> bool:
        return bool(self.attachment_count or self.credential_count)


@dataclass(frozen=True)
class AccessMutationReport:
    """Result of disabling or removing one VM access identity."""

    principal: PrincipalEntry
    action: AccessAction
    changed: bool
    ip: str
    ownership: AccessOwnershipSummary


def access_ownership_summary(
    reg: Store, *, vm_name: str, principal_id: str
) -> AccessOwnershipSummary:
    """Count records that prevent lossless identity removal."""
    return AccessOwnershipSummary(
        attachment_count=sum(
            1
            for item in reg.attachments
            if item.vm_name == vm_name
            and item.owner_principal_id == principal_id
        ),
        credential_count=sum(
            1
            for item in reg.credentials
            if item.vm_name == vm_name and item.principal_id == principal_id
        ),
    )


def resolve_access_principal(
    reg: Store,
    *,
    vm_name: str,
    selector: str = '',
    current_host_user: str | None = None,
) -> PrincipalEntry:
    """Resolve an identity by id or host login, defaulting to the caller."""
    selected = str(selector or '').strip()
    current = current_host_user or getpass.getuser()
    if not selected:
        principal = find_principal_for_host(
            reg, vm_name=vm_name, host_user=current
        )
        if principal is None:
            raise AIVMError(
                f'Host user {current!r} has no access identity for managed '
                f'VM {vm_name!r}.'
            )
        return principal

    by_id = find_principal(reg, vm_name=vm_name, principal_id=selected)
    by_host = [
        item
        for item in find_principals_for_vm(reg, vm_name)
        if item.host_user == selected
    ]
    matches: list[PrincipalEntry] = (
        [by_id] if by_id is not None else []
    ) + [
        item for item in by_host if item is not by_id
    ]
    if not matches:
        known = ', '.join(
            f'{item.host_user} ({item.id})'
            for item in find_principals_for_vm(reg, vm_name)
        )
        raise AIVMError(
            f'Unknown access identity {selected!r} for VM {vm_name!r}. '
            f'Known identities: {known or "none"}.'
        )
    if len(matches) > 1:
        ids = ', '.join(sorted(item.id for item in matches))
        raise AIVMError(
            f'Ambiguous access identity selector {selected!r}: {ids}'
        )
    return matches[0]


def _require_target_authority(
    principal: PrincipalEntry,
    *,
    current_host_user: str,
    administrative_override: bool,
) -> None:
    if principal.host_user == current_host_user:
        return
    if administrative_override:
        return
    raise AIVMError(
        f'Access identity {principal.id!r} belongs to host user '
        f'{principal.host_user!r}. Run the command as that user, or use '
        '--admin_override on the mutually trusted host.'
    )


def _require_not_last_access(
    reg: Store,
    principal: PrincipalEntry,
    *,
    allow_last_access: bool,
) -> None:
    if principal.state not in {'active', 'legacy'}:
        return
    remaining = [
        item
        for item in find_principals_for_vm(reg, principal.vm_name)
        if item.id != principal.id and item.state in {'active', 'legacy'}
    ]
    if remaining or allow_last_access:
        return
    raise AIVMError(
        f'{principal.host_user!r} is the last active access identity for '
        f'VM {principal.vm_name!r}. Refusing to remove its guest access '
        'without --allow_last_access. The restricted bootstrap channel can '
        'recover access, but ordinary SSH/code workflows would stop working.'
    )


def _effective_cfg(reg: Store, principal: PrincipalEntry) -> AgentVMConfig:
    cfg = materialize_vm_cfg(reg, principal.vm_name)
    cfg.vm.user = principal.guest_user
    return cfg


def _resolve_ip(cfg: AgentVMConfig, ip_override: str) -> str:
    from .vm.connectivity import get_ip_cached, wait_for_ip

    selected = str(ip_override or '').strip()
    if selected:
        return selected
    cached = get_ip_cached(cfg)
    if cached:
        return cached
    return wait_for_ip(cfg, timeout_s=360, dry_run=False)


def _disable_guest_key(
    scope: StoreScope,
    principal: PrincipalEntry,
    *,
    reg: Store,
    ip_override: str,
) -> str:
    from .enrollment import require_bootstrap_identity

    assert scope.machine_layout is not None
    identity = require_bootstrap_identity(
        principal.vm_name, layout=scope.machine_layout
    )
    cfg = _effective_cfg(reg, principal)
    ip = _resolve_ip(cfg, ip_override)
    request = GuestAccessRequest(
        operation='disable-principal',
        guest_user=principal.guest_user,
        public_key=principal.ssh_public_key,
    )
    mgr = CommandManager.current()
    result = mgr.run(
        [
            'ssh',
            *ssh_base_args(
                str(identity.private_key),
                strict_host_key_checking='accept-new',
                connect_timeout=15,
                batch_mode=True,
                user_known_hosts_file=str(identity.known_hosts),
            ),
            f'{BOOTSTRAP_GUEST_USER}@{ip}',
            'disable-principal',
        ],
        sudo=identity.use_sudo,
        role='modify',
        check=False,
        capture=True,
        input_text=request.to_json() + '\n',
        timeout=60,
        summary=f'Disable guest access for {principal.guest_user}',
        detail=(
            'The forced bootstrap helper removes only the persisted public '
            'key and AIVM sudoers fragment; it retains the guest home.'
        ),
    )
    if result.code != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Could not disable guest access for {principal.host_user!r} '
            f'on {principal.vm_name!r}: {detail}'
        )
    return ip


def _clear_current_profile_selection(
    scope: StoreScope, principal: PrincipalEntry
) -> None:
    if principal.host_user != getpass.getuser():
        return
    profile = load_scope_profile(scope)
    if profile.active_vm != principal.vm_name:
        return
    profile.active_vm = ''
    assert scope.profile_path is not None
    save_user_profile(profile, scope.profile_path)


def mutate_access_identity(
    scope: StoreScope,
    *,
    vm_name: str,
    selector: str = '',
    action: AccessAction,
    administrative_override: bool = False,
    allow_last_access: bool = False,
    ip_override: str = '',
    dry_run: bool = False,
) -> AccessMutationReport:
    """Disable or remove one identity after guest-side revocation succeeds."""
    if action not in {'disable', 'remove'}:
        raise ValueError(f'Unsupported access action: {action!r}')
    if not scope.is_machine or scope.machine_layout is None:
        raise AIVMError(
            'Access identity lifecycle commands require the shared machine store.'
        )
    reg = load_scope_store(scope)
    if find_vm(reg, vm_name) is None:
        raise AIVMError(f'Unknown managed VM: {vm_name!r}')
    current_host_user = getpass.getuser()
    principal = resolve_access_principal(
        reg,
        vm_name=vm_name,
        selector=selector,
        current_host_user=current_host_user,
    )
    _require_target_authority(
        principal,
        current_host_user=current_host_user,
        administrative_override=administrative_override,
    )
    _require_not_last_access(
        reg, principal, allow_last_access=allow_last_access
    )
    ownership = access_ownership_summary(
        reg, vm_name=vm_name, principal_id=principal.id
    )
    if action == 'remove' and ownership.has_owned_records:
        raise AIVMError(
            f'Cannot remove access identity {principal.id!r} while it owns '
            f'{ownership.attachment_count} attachment(s) and '
            f'{ownership.credential_count} credential(s). Detach or '
            'administratively transfer its attachments, and revoke or abandon '
            'its credentials as the owning host user first. Disabling is '
            'allowed because it preserves ownership metadata.'
        )

    if dry_run:
        return AccessMutationReport(
            principal=principal,
            action=action,
            changed=(principal.state != 'disabled' or action == 'remove'),
            ip=str(ip_override or '').strip() or '<vm-ip>',
            ownership=ownership,
        )

    ip = ''
    if principal.state != 'disabled':
        with CommandManager.current().intent(
            f'Disable access identity {principal.host_user} on {vm_name}',
            why=(
                'Remove the identity public key and AIVM sudo policy from the '
                'guest before changing machine metadata.'
            ),
            role='modify',
        ):
            ip = _disable_guest_key(
                scope,
                principal,
                reg=reg,
                ip_override=ip_override,
            )

    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(),
        include_store=True,
        vms=[vm_name],
    ):
        latest = load_scope_store(scope)
        current = find_principal(
            latest, vm_name=vm_name, principal_id=principal.id
        )
        if current is None:
            if action == 'remove':
                return AccessMutationReport(
                    principal=principal,
                    action=action,
                    changed=False,
                    ip=ip,
                    ownership=ownership,
                )
            raise AIVMError(
                f'Access identity {principal.id!r} disappeared while '
                'disabling guest access.'
            )
        if (
            current.host_user != principal.host_user
            or current.guest_user != principal.guest_user
            or current.ssh_public_key != principal.ssh_public_key
        ):
            raise AIVMError(
                f'Access identity {principal.id!r} changed concurrently; '
                'guest access was disabled, but machine metadata was not '
                'modified. Review the identity and retry.'
            )
        latest_ownership = access_ownership_summary(
            latest, vm_name=vm_name, principal_id=principal.id
        )
        if action == 'remove':
            if latest_ownership.has_owned_records:
                raise AIVMError(
                    f'Access identity {principal.id!r} acquired owned records '
                    'during removal; it remains in the machine store in its '
                    'previous state. Resolve those records and retry.'
                )
            remove_principal(
                latest, vm_name=vm_name, principal_id=principal.id
            )
            save_scope_store(
                scope,
                latest,
                reason=(
                    f'Remove disabled access identity {principal.id} from '
                    f'VM {vm_name}.'
                ),
            )
            changed = True
        else:
            disabled = replace(current, state='disabled')
            changed = current.state != 'disabled'
            if changed:
                upsert_principal(latest, disabled)
                save_scope_store(
                    scope,
                    latest,
                    reason=(
                        f'Disable access identity {principal.id} for VM '
                        f'{vm_name}.'
                    ),
                )
            principal = disabled

    _clear_current_profile_selection(scope, principal)
    return AccessMutationReport(
        principal=principal,
        action=action,
        changed=changed,
        ip=ip,
        ownership=ownership,
    )


__all__ = [
    'AccessAction',
    'AccessMutationReport',
    'AccessOwnershipSummary',
    'TRUST_MODE',
    'access_ownership_summary',
    'mutate_access_identity',
    'resolve_access_principal',
]
