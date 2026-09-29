"""Host-side guest principal enrollment and bootstrap-key management."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path

from loguru import logger as log

from .commands import CommandManager
from .config import AgentVMConfig
from .config_store import (
    PrincipalEntry,
    Store,
    find_principal_for_host_identity,
    find_principals_for_vm,
    find_vm,
    materialize_vm_cfg,
    upsert_principal,
)
from .errors import AIVMError, MissingSSHIdentityError
from .guestctl import BOOTSTRAP_GUEST_USER, GuestEnrollmentRequest
from .host_identity import current_host_identity
from .machine_store import (
    MachineStoreLayout,
    current_machine_group_gid,
    machine_resource_locks,
    machine_store_layout,
)
from .profile_store import UserProfileStore
from .runtime import require_ssh_identity, ssh_base_args
from .scoped_store import (
    StoreScope,
    load_scope_profile,
    load_scope_store,
    save_scope_store,
    stable_principal_id,
)
from .ssh_keys import same_ssh_public_key
from .vm.connectivity import get_ip_cached, wait_for_ip


@dataclass(frozen=True)
class BootstrapIdentity:
    """Machine-scoped SSH identity used only for forced enrollment."""

    directory: Path
    private_key: Path
    public_key_path: Path
    known_hosts: Path
    public_key: str
    use_sudo: bool


@dataclass(frozen=True)
class EnrollmentReport:
    """Result of reconciling one host principal against one guest."""

    principal: PrincipalEntry
    ip: str
    changed: bool


def _storage_stem(vm_name: str) -> str:
    clean = re.sub(r'[^A-Za-z0-9_.-]+', '_', vm_name.strip()).strip('._')
    clean = clean[:48] or 'vm'
    digest = hashlib.sha256(vm_name.encode('utf-8')).hexdigest()[:12]
    return f'{clean}-{digest}'


def bootstrap_identity_paths(
    vm_name: str,
    *,
    layout: MachineStoreLayout | None = None,
) -> BootstrapIdentity:
    """Return deterministic bootstrap identity paths without creating them."""
    layout = layout or machine_store_layout()
    directory = layout.bootstrap_dir / _storage_stem(vm_name)
    private = directory / 'id_ed25519'
    public = directory / 'id_ed25519.pub'
    known_hosts = directory / 'known_hosts'
    public_text = ''
    try:
        public_text = public.read_text(encoding='utf-8').strip()
    except OSError:
        pass
    # Root owns this keypair only where the store is shared: there it is a
    # machine credential sitting in a directory every trusted-group member can
    # reach, so group members must be able to read the public half and not the
    # private one. A personal store has exactly one principal -- its owner --
    # so root ownership would buy nothing and cost plenty: a sudo prompt on an
    # otherwise unprivileged flow, and root-owned files inside the user's own
    # home that they then cannot read, back up, or delete without escalating.
    use_sudo = layout.shared
    return BootstrapIdentity(
        directory=directory,
        private_key=private,
        public_key_path=public,
        known_hosts=known_hosts,
        public_key=public_text,
        use_sudo=use_sudo,
    )


def ensure_bootstrap_identity(
    vm_name: str,
    *,
    layout: MachineStoreLayout | None = None,
    dry_run: bool = False,
) -> BootstrapIdentity:
    """Create the root-owned machine bootstrap identity once and reuse it."""
    layout = layout or machine_store_layout()
    identity = bootstrap_identity_paths(vm_name, layout=layout)
    have_private = identity.private_key.is_file()
    have_public = identity.public_key_path.is_file()
    if have_private != have_public:
        raise AIVMError(
            f'Incomplete bootstrap SSH identity for VM {vm_name!r}: '
            f'{identity.directory}'
        )
    if have_private and have_public:
        public_key = identity.public_key_path.read_text(
            encoding='utf-8'
        ).strip()
        return replace(identity, public_key=public_key)
    if dry_run:
        return replace(
            identity,
            public_key='ssh-ed25519 AAAA-AIVM-DRY-RUN aivm-bootstrap',
        )

    gid = current_machine_group_gid(layout)
    owner = 'root' if identity.use_sudo else str(os.getuid())
    group = str(gid)
    mgr = CommandManager.current()
    with mgr.intent(
        f'Create enrollment bootstrap identity for {vm_name}',
        why=(
            'Later trusted host users need a machine-owned key that can invoke '
            'only the guest enrollment helper.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Generate restricted bootstrap SSH keypair',
            why=(
                'Create one stable keypair under machine state; its guest key '
                'is forced to a non-interactive enrollment command.'
            ),
            approval_scope=f'vm-bootstrap-key:{vm_name}',
        ):
            mgr.submit(
                ['mkdir', '-p', str(identity.directory)],
                sudo=identity.use_sudo,
                role='modify',
                summary='Create VM bootstrap identity directory',
            )
            if identity.use_sudo:
                mgr.submit(
                    ['chown', f'{owner}:{group}', str(identity.directory)],
                    sudo=True,
                    role='modify',
                    summary='Set VM bootstrap directory ownership',
                )
            mgr.submit(
                ['chmod', '0750', str(identity.directory)],
                sudo=identity.use_sudo,
                role='modify',
                summary='Restrict VM bootstrap identity directory',
            )
            mgr.submit(
                [
                    'ssh-keygen',
                    '-q',
                    '-t',
                    'ed25519',
                    '-f',
                    str(identity.private_key),
                    '-N',
                    '',
                    '-C',
                    f'aivm-bootstrap@{vm_name}',
                ],
                sudo=identity.use_sudo,
                role='modify',
                summary='Generate VM enrollment bootstrap keypair',
            )
            mgr.submit(
                ['chmod', '0600', str(identity.private_key)],
                sudo=identity.use_sudo,
                role='modify',
                summary='Protect VM bootstrap private key',
            )
            mgr.submit(
                ['chmod', '0644', str(identity.public_key_path)],
                sudo=identity.use_sudo,
                role='modify',
                summary='Make VM bootstrap public key readable',
            )
    public_key = identity.public_key_path.read_text(encoding='utf-8').strip()
    return replace(identity, public_key=public_key)


def require_bootstrap_identity(
    vm_name: str,
    *,
    layout: MachineStoreLayout | None = None,
) -> BootstrapIdentity:
    """Load an existing bootstrap identity or explain the migration boundary."""
    identity = bootstrap_identity_paths(vm_name, layout=layout)
    if (
        not identity.private_key.is_file()
        or not identity.public_key_path.is_file()
    ):
        raise AIVMError(
            f'Managed VM {vm_name!r} has no enrollment bootstrap identity. '
            'It predates automatic enrollment or was only partially created. '
            'Use the forthcoming existing-installation migration before '
            'enrolling another user.'
        )
    return replace(
        identity,
        public_key=identity.public_key_path.read_text(encoding='utf-8').strip(),
    )


def normalized_guest_username(host_user: str) -> str:
    """Map a host login such as ``edward.wang`` to a stable guest username."""
    base = re.sub(r'[^a-z0-9_-]+', '-', host_user.strip().lower()).strip('-_')
    if not base:
        base = 'user'
    if not re.match(r'^[a-z_]', base):
        base = f'user-{base}'
    suffix = '-agent'
    max_base = 32 - len(suffix)
    if len(base) > max_base:
        digest = hashlib.sha256(host_user.encode('utf-8')).hexdigest()[:6]
        base = f'{base[: max_base - 7]}-{digest}'
    return f'{base}{suffix}'


def _read_profile_public_key(profile: UserProfileStore) -> str:
    path = Path(profile.ssh_pubkey_path).expanduser()
    if not profile.ssh_pubkey_path or not path.is_file():
        raise MissingSSHIdentityError(
            'The user profile has no readable AIVM SSH public key. '
            'Run `aivm config init` to create one before enrollment.'
        )
    key = path.read_text(encoding='utf-8').strip()
    if not key:
        raise MissingSSHIdentityError(f'Empty SSH public key: {path}')
    return key


def _effective_cfg_for_principal(
    reg: Store,
    vm_name: str,
    *,
    profile: UserProfileStore,
    principal: PrincipalEntry,
) -> AgentVMConfig:
    cfg = materialize_vm_cfg(reg, vm_name)
    cfg.vm.user = principal.guest_user
    cfg.paths.ssh_identity_file = profile.ssh_identity_file
    cfg.paths.ssh_pubkey_path = profile.ssh_pubkey_path
    cfg.paths.state_dir = profile.state_dir
    cfg.verbosity = int(profile.behavior.verbose)
    return cfg


def _granted_state(existing: PrincipalEntry | None) -> str:
    """Return the access grant a persisted principal already holds, if any.

    ``PrincipalEntry.state`` records the last *known grant*, not the outcome
    of the last reconcile attempt, and only an affirmative revocation may
    lower it.  A failed attempt is never that evidence: the enrollment
    transport reports one status for an unreachable guest and for a rejected
    key alike, so the guest key is usually still installed and only the proof
    is missing.  Downgrading on a failed attempt would retire the identity
    from the last-access accounting in
    :func:`aivm.access_control._require_not_last_access`, which counts only
    ``active``/``legacy`` identities, and would lock its owner out of
    :func:`aivm.scoped_store.resolve_machine_context` until some later attempt
    happened to succeed.  Callers therefore persist ``_granted_state(existing)
    or <attempt outcome>``, so only an identity that never held a grant
    records the failure.
    """
    if existing is not None and existing.state in {'active', 'legacy'}:
        return existing.state
    return ''


def _save_principal_state(
    scope: StoreScope,
    principal: PrincipalEntry,
    *,
    reason: str,
) -> PrincipalEntry:
    assert scope.machine_layout is not None
    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(scope.machine_layout),
        include_store=True,
        vms=[principal.vm_name],
    ):
        reg = load_scope_store(scope)
        upsert_principal(reg, principal)
        save_scope_store(scope, reg, reason=reason)
    return principal


def _resolve_enrollment_ip(cfg: AgentVMConfig, ip_override: str = '') -> str:
    if ip_override.strip():
        return ip_override.strip()
    cached = get_ip_cached(cfg)
    if cached:
        return cached
    return wait_for_ip(cfg, timeout_s=360, dry_run=False)


def reconcile_current_principal(
    scope: StoreScope,
    *,
    vm_name: str,
    guest_user: str = '',
    ip_override: str = '',
    dry_run: bool = False,
    enable_disabled: bool = False,
) -> EnrollmentReport:
    """Enroll or repair the caller through one serialized transaction."""
    if not scope.is_machine or scope.machine_layout is None:
        raise AIVMError(
            'Principal enrollment requires the shared machine store.'
        )
    if dry_run:
        return _reconcile_current_principal_impl(
            scope,
            vm_name=vm_name,
            guest_user=guest_user,
            ip_override=ip_override,
            dry_run=True,
            enable_disabled=enable_disabled,
        )
    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(scope.machine_layout),
        include_store=True,
        vms=[vm_name],
    ):
        return _reconcile_current_principal_impl(
            scope,
            vm_name=vm_name,
            guest_user=guest_user,
            ip_override=ip_override,
            dry_run=False,
            enable_disabled=enable_disabled,
        )


def _reconcile_current_principal_impl(
    scope: StoreScope,
    *,
    vm_name: str,
    guest_user: str = '',
    ip_override: str = '',
    dry_run: bool = False,
    enable_disabled: bool = False,
) -> EnrollmentReport:
    """Implement enrollment while the caller holds the VM/store locks."""
    if not scope.is_machine or scope.machine_layout is None:
        raise AIVMError(
            'Principal enrollment requires the shared machine store.'
        )
    reg = load_scope_store(scope)
    if find_vm(reg, vm_name) is None:
        raise AIVMError(f'Unknown managed VM: {vm_name!r}')
    profile = load_scope_profile(scope)
    host_identity = current_host_identity()
    host_user = host_identity.username
    host_uid = host_identity.uid
    host_gid = host_identity.gid
    existing = find_principal_for_host_identity(
        reg, vm_name=vm_name, identity=host_identity
    )
    if (
        existing is not None
        and existing.state == 'disabled'
        and not enable_disabled
    ):
        raise AIVMError(
            f'Access identity {existing.id!r} is disabled. Retry with '
            '`aivm vm access reconcile --enable` as the owning host user to '
            'restore its personal key and sudo policy.'
        )
    requested_guest = guest_user.strip()
    selected_guest = (
        requested_guest
        or (existing.guest_user if existing is not None else '')
        or normalized_guest_username(host_user)
    )
    public_key = _read_profile_public_key(profile)
    if existing is not None:
        if requested_guest and requested_guest != existing.guest_user:
            raise AIVMError(
                f'Access identity {existing.id!r} already uses guest account '
                f'{existing.guest_user!r}. Guest-account rotation is not '
                'supported by reconcile; disable the identity and use a '
                'dedicated future rotation operation instead.'
            )
        if not same_ssh_public_key(public_key, existing.ssh_public_key):
            raise AIVMError(
                f'Access identity {existing.id!r} already has different SSH '
                'key material. Key rotation is not supported by reconcile; '
                'the old guest key must remain represented until an explicit '
                'rotation operation can install, revoke, and verify both sides.'
            )
        # A comment-only edit is not a rotation. Keep the persisted line so a
        # later disable removes exactly the originally enrolled representation.
        public_key = existing.ssh_public_key
    conflicts = [
        item
        for item in find_principals_for_vm(reg, vm_name)
        if item.id != (existing.id if existing is not None else '')
        and item.guest_user == selected_guest
        and item.state not in {'removed'}
    ]
    if conflicts:
        owners = ', '.join(
            f'{item.host_user!r} ({item.id})' for item in conflicts
        )
        raise AIVMError(
            f'Guest account {selected_guest!r} is already assigned to {owners}. '
            'Each access identity must use a unique guest account because its '
            'authorized_keys and sudo policy are reconciled as one unit.'
        )
    principal = PrincipalEntry(
        # Reuse the matched record's id: the lookup is by host identity, and
        # writing a recomputed id for an existing principal would append a
        # duplicate record instead of updating it.
        id=(
            existing.id
            if existing is not None
            else stable_principal_id(vm_name, host_user)
        ),
        vm_name=vm_name,
        host_user=host_user,
        host_uid=host_uid,
        host_gid=host_gid,
        guest_user=selected_guest,
        ssh_public_key=public_key,
        state='pending',
    )
    cfg = _effective_cfg_for_principal(
        reg,
        vm_name,
        profile=profile,
        principal=principal,
    )
    if dry_run:
        identity = bootstrap_identity_paths(
            vm_name, layout=scope.machine_layout
        )
        ip = ip_override.strip() or get_ip_cached(cfg) or '<vm-ip>'
        log.info(
            'DRYRUN: would enroll host user {} as {} through bootstrap key '
            '{} at {}',
            host_user,
            selected_guest,
            identity.private_key,
            ip,
        )
        return EnrollmentReport(principal=principal, ip=ip, changed=True)

    already_granted = bool(_granted_state(existing))
    if not already_granted:
        # Record a brand-new enrollment as pending before any transport. An
        # already-granted identity is only being re-verified: writing
        # 'pending' here would durably downgrade it before the user has
        # approved anything, so a declined prompt would leave the identity
        # (and last-access accounting) weakened.
        _save_principal_state(
            scope,
            principal,
            reason=f'Record pending enrollment for {host_user} on VM {vm_name}.',
        )
    identity = require_bootstrap_identity(vm_name, layout=scope.machine_layout)
    ip = _resolve_enrollment_ip(cfg, ip_override)
    request = GuestEnrollmentRequest(
        guest_user=principal.guest_user,
        uid=principal.host_uid,
        gid=principal.host_gid,
        public_key=principal.ssh_public_key,
        allow_sudo=True,
        groups=('docker',),
    )
    bootstrap_cmd = [
        'ssh',
        *ssh_base_args(
            str(identity.private_key),
            strict_host_key_checking='accept-new',
            connect_timeout=15,
            batch_mode=True,
            user_known_hosts_file=str(identity.known_hosts),
        ),
        f'{BOOTSTRAP_GUEST_USER}@{ip}',
        'enroll-principal',
    ]
    mgr = CommandManager.current()
    with mgr.intent(
        f'Enroll {host_user} on VM {vm_name}',
        why=(
            'Use the machine bootstrap key to invoke only the restricted '
            'guest account enrollment helper, then verify the personal key.'
        ),
        role='modify',
    ):
        result = mgr.run(
            bootstrap_cmd,
            sudo=identity.use_sudo,
            role='modify',
            check=False,
            capture=True,
            input_text=request.to_json() + '\n',
            timeout=60,
            summary=f'Enroll guest principal {principal.guest_user}',
            detail='The bootstrap SSH key is forced to aivm-guestctl --forced.',
        )
    if result.code != 0:
        # A failed helper invocation revokes nothing, so an identity that
        # already holds a grant keeps it; 255 additionally distinguishes an
        # unreachable VM (retry later) from a guest-side refusal.
        state = _granted_state(existing) or (
            'pending' if result.code == 255 else 'error'
        )
        failed = replace(principal, state=state)
        _save_principal_state(
            scope,
            failed,
            reason=(
                f'Record enrollment state {state} for {host_user} on VM '
                f'{vm_name} after the guest enrollment helper failed.'
            ),
        )
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Guest enrollment failed for {host_user!r} on {vm_name!r}: '
            f'{detail}'
        )

    ident = require_ssh_identity(profile.ssh_identity_file)
    verify = mgr.run(
        [
            'ssh',
            *ssh_base_args(
                ident,
                strict_host_key_checking='accept-new',
                connect_timeout=10,
                batch_mode=True,
            ),
            f'{principal.guest_user}@{ip}',
            'true',
        ],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        timeout=30,
        summary=f'Verify personal SSH access for {principal.guest_user}',
    )
    if verify.code != 0:
        # The helper reported success, so the personal key is installed and
        # an unproven probe is not evidence that it is gone. An identity that
        # already holds a grant keeps it; a brand-new one stays unproven.
        state = _granted_state(existing) or 'error'
        failed = replace(principal, state=state)
        _save_principal_state(
            scope,
            failed,
            reason=(
                f'Record enrollment state {state} for {host_user} on VM '
                f'{vm_name} after failed personal-key verification.'
            ),
        )
        detail = (verify.stderr or verify.stdout or '').strip()
        raise AIVMError(
            f'Enrollment helper completed, but personal SSH verification '
            f'failed for {principal.guest_user!r}: {detail}'
        )

    active = replace(principal, state='active')
    _save_principal_state(
        scope,
        active,
        reason=f'Activate enrolled principal {host_user} on VM {vm_name}.',
    )
    return EnrollmentReport(
        principal=active,
        ip=ip,
        changed=existing != active,
    )
