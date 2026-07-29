"""Operational lifecycle for shared-machine access identities.

The machine store records host-to-guest access identities (internally called
principals).  This module owns the state-changing lifecycle rules so CLI code,
future daemon code, and tests share one fail-closed implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from .commands import CommandManager
from .config import AgentVMConfig
from .config_store import (
    PrincipalEntry,
    Store,
    find_principal,
    find_principal_for_host_identity,
    find_principals_for_vm,
    find_vm,
    materialize_vm_cfg,
    remove_principal,
    upsert_principal,
)
from .errors import AIVMError
from .guestctl import BOOTSTRAP_GUEST_USER, GuestAccessRequest
from .host_identity import HostIdentity, current_host_identity
from .machine_store import current_machine_group_gid, machine_resource_locks
from .profile_store import save_user_profile
from .runtime import ssh_base_args
from .scoped_store import (
    StoreScope,
    load_scope_profile,
    load_scope_store,
    save_scope_store,
)

TRUST_MODE = 'kernel-identity'
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


@dataclass(frozen=True)
class HostIdentityRepairReport:
    """Result of repairing a renamed local account in the machine store."""

    principal: PrincipalEntry
    previous_host_user: str
    previous_host_gid: int
    changed: bool


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
    current_identity: HostIdentity | None = None,
) -> PrincipalEntry:
    """Resolve an identity by id or host login, defaulting to the caller."""
    selected = str(selector or '').strip()
    identity = current_identity or current_host_identity()
    if not selected:
        principal = find_principal_for_host_identity(
            reg, vm_name=vm_name, identity=identity
        )
        if principal is None:
            raise AIVMError(
                f'Host user {identity.username!r} (uid {identity.uid}) has no '
                f'access identity for managed VM {vm_name!r}.'
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
    ) + [item for item in by_host if item is not by_id]
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
    current_identity: HostIdentity,
    administrative_override: bool,
) -> None:
    if (
        principal.host_user == current_identity.username
        and principal.host_uid == current_identity.uid
    ):
        return
    if administrative_override:
        return
    raise AIVMError(
        f'Access identity {principal.id!r} belongs to host user '
        f'{principal.host_user!r} (uid {principal.host_uid}). Run the command '
        'as that kernel identity, or use --admin_override on the trusted host.'
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
    identity = current_host_identity()
    if (
        principal.host_user != identity.username
        or principal.host_uid != identity.uid
    ):
        return
    profile = load_scope_profile(scope)
    if profile.active_vm != principal.vm_name:
        return
    profile.active_vm = ''
    assert scope.profile_path is not None
    save_user_profile(profile, scope.profile_path)


def repair_current_host_identity(
    scope: StoreScope,
    *,
    vm_name: str,
    dry_run: bool = False,
) -> HostIdentityRepairReport:
    """Repair a passwd account rename while preserving the stable identity id.

    Only a principal already carrying the caller's kernel UID is eligible. A
    same-name/different-UID record is treated as account recreation or UID reuse
    and is never repaired automatically.
    """
    if not scope.is_machine or scope.machine_layout is None:
        raise AIVMError(
            'Host identity repair requires the shared machine store.'
        )
    identity = current_host_identity()

    def resolve(reg: Store) -> tuple[PrincipalEntry, PrincipalEntry]:
        if find_vm(reg, vm_name) is None:
            raise AIVMError(f'Unknown managed VM: {vm_name!r}')
        principals = find_principals_for_vm(reg, vm_name)
        uid_matches = [
            item for item in principals if item.host_uid == identity.uid
        ]
        if len(uid_matches) > 1:
            ids = ', '.join(sorted(item.id for item in uid_matches))
            raise AIVMError(
                f'Multiple access identities use invoking uid {identity.uid} '
                f'on VM {vm_name!r}: {ids}. Repair the store manually.'
            )
        if not uid_matches:
            name_matches = [
                item for item in principals if item.host_user == identity.username
            ]
            if name_matches:
                recorded = ', '.join(
                    f'uid {item.host_uid} ({item.id})' for item in name_matches
                )
                raise AIVMError(
                    f'Host user {identity.username!r} is now uid {identity.uid}, '
                    f'but the store records {recorded}. This is account '
                    'recreation or UID reuse, not a rename; refusing automatic '
                    'repair.'
                )
            raise AIVMError(
                f'No access identity on VM {vm_name!r} carries invoking uid '
                f'{identity.uid}; there is no account rename to repair.'
            )
        existing = uid_matches[0]
        conflicts = [
            item
            for item in principals
            if item.id != existing.id
            and item.host_user == identity.username
        ]
        if conflicts:
            ids = ', '.join(sorted(item.id for item in conflicts))
            raise AIVMError(
                f'Cannot rename access identity {existing.id!r} to '
                f'{identity.username!r}; that host login is already recorded '
                f'by {ids}.'
            )
        repaired = replace(
            existing,
            host_user=identity.username,
            host_gid=identity.gid,
        )
        return existing, repaired

    if dry_run:
        previous, repaired = resolve(load_scope_store(scope))
        return HostIdentityRepairReport(
            principal=repaired,
            previous_host_user=previous.host_user,
            previous_host_gid=previous.host_gid,
            changed=(repaired != previous),
        )

    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(),
        include_store=True,
        vms=[vm_name],
    ):
        reg = load_scope_store(scope)
        previous, repaired = resolve(reg)
        changed = repaired != previous
        if changed:
            upsert_principal(reg, repaired)
            save_scope_store(
                scope,
                reg,
                reason=(
                    f'Repair host account rename for access identity '
                    f'{repaired.id} on VM {vm_name}: '
                    f'{previous.host_user} -> {repaired.host_user}.'
                ),
            )
    return HostIdentityRepairReport(
        principal=repaired,
        previous_host_user=previous.host_user,
        previous_host_gid=previous.host_gid,
        changed=changed,
    )



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
    """Convergently disable or remove one identity under authoritative locks.

    The store and VM locks remain held through guest revocation. This avoids a
    second durable transition state while still making concurrent last-access
    checks and ownership checks authoritative. Guest revocation is idempotent,
    so a crash after revocation but before persistence is repaired by retrying.
    """
    if action not in {'disable', 'remove'}:
        raise ValueError(f'Unsupported access action: {action!r}')
    if not scope.is_machine or scope.machine_layout is None:
        raise AIVMError(
            'Access identity lifecycle commands require the shared machine store.'
        )
    identity = current_host_identity()

    def validate(reg: Store) -> tuple[PrincipalEntry, AccessOwnershipSummary]:
        if find_vm(reg, vm_name) is None:
            raise AIVMError(f'Unknown managed VM: {vm_name!r}')
        principal = resolve_access_principal(
            reg,
            vm_name=vm_name,
            selector=selector,
            current_identity=identity,
        )
        _require_target_authority(
            principal,
            current_identity=identity,
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
                'administratively transfer its attachments, and revoke or '
                'abandon its credentials first. Disabling is allowed because '
                'it preserves ownership metadata.'
            )
        return principal, ownership

    if dry_run:
        principal, ownership = validate(load_scope_store(scope))
        return AccessMutationReport(
            principal=principal,
            action=action,
            changed=(principal.state != 'disabled' or action == 'remove'),
            ip=str(ip_override or '').strip() or '<vm-ip>',
            ownership=ownership,
        )

    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(),
        include_store=True,
        vms=[vm_name],
    ):
        latest = load_scope_store(scope)
        principal, ownership = validate(latest)
        with CommandManager.current().intent(
            f'Disable access identity {principal.host_user} on {vm_name}',
            why=(
                'Idempotently remove the recorded public key and AIVM sudo '
                'policy from the guest before finalizing machine metadata.'
            ),
            role='modify',
        ):
            ip = _disable_guest_key(
                scope, principal, reg=latest, ip_override=ip_override
            )

        # Clear caller-local selection before the final machine-store write.
        # A crash here leaves authoritative identity metadata intact and a
        # retry can repeat the idempotent guest revocation. There is no
        # post-commit profile side effect that could become unresumable.
        _clear_current_profile_selection(scope, principal)

        if action == 'remove':
            changed = remove_principal(
                latest, vm_name=vm_name, principal_id=principal.id
            )
            if changed:
                save_scope_store(
                    scope,
                    latest,
                    reason=(
                        f'Remove verified-disabled access identity '
                        f'{principal.id} from VM {vm_name}.'
                    ),
                )
        else:
            disabled = replace(principal, state='disabled')
            changed = principal.state != 'disabled'
            if changed:
                upsert_principal(latest, disabled)
                save_scope_store(
                    scope,
                    latest,
                    reason=(
                        f'Disable access identity {principal.id} for VM '
                        f'{vm_name} after verified guest revocation.'
                    ),
                )
            principal = disabled

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
    'HostIdentityRepairReport',
    'TRUST_MODE',
    'access_ownership_summary',
    'mutate_access_identity',
    'repair_current_host_identity',
    'resolve_access_principal',
]
