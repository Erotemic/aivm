"""Administrator-side zero-touch enrollment of a second host user.

A root-installed, stdlib-only helper performs the user-specific filesystem
and SSH operations *after dropping to the target user's uid*. The owning
administrator's AIVM process never reads that user's private key. The usual
restricted guest bootstrap transport still provisions the guest account.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
from dataclasses import dataclass, replace
from importlib import resources
from pathlib import Path

from .commands import CommandManager
from .config_store import (
    PrincipalEntry,
    find_principal_for_host,
    find_principals_for_vm,
    find_vm,
    materialize_vm_cfg,
    upsert_principal,
)
from .enrollment import (
    _resolve_enrollment_ip,
    normalized_guest_username,
    prepare_other_principal,
)
from .errors import AIVMError
from .host_identity import current_host_identity
from .machine_store import (
    current_machine_group_gid,
    machine_resource_locks,
)
from .profile_store import UserProfileStore, render_user_profile
from .scoped_store import (
    StoreScope,
    load_scope_store,
    save_scope_store,
    stable_principal_id,
)
from .ssh_keys import same_ssh_public_key
from .vm.connectivity import get_ip_cached

# Only root may install/modify the helper. Never execute a helper from a user
# checkout or from the administrator's virtualenv with sudo.
ONBOARD_HELPER = Path('/usr/local/libexec/aivm/onboard-user')


@dataclass(frozen=True)
class OnboardReport:
    principal: PrincipalEntry
    ip: str
    profile_path: Path
    changed: bool


def _target_account(user: str) -> pwd.struct_passwd:
    if not user.strip() or user.startswith('-'):
        raise AIVMError('Select the host account to onboard.')
    try:
        target = pwd.getpwnam(user)
    except KeyError as ex:
        raise AIVMError(f'Host account {user!r} does not exist.') from ex
    if target.pw_uid == 0 or target.pw_gid == 0:
        raise AIVMError('Cannot onboard root or root-group host accounts.')
    if target.pw_name != user:
        raise AIVMError('Host login must match its canonical passwd account name.')
    actor = current_host_identity()
    if target.pw_uid == actor.uid:
        raise AIVMError('Use `aivm config init` for your own host account.')
    # Group ownership is part of the existing trusted-shared-host model. Do
    # not silently grant broad libvirt authority during VM onboarding.
    membership = set(os.getgrouplist(target.pw_name, target.pw_gid))
    required_gid = current_machine_group_gid()
    if required_gid not in membership:
        group = grp.getgrgid(required_gid).gr_name
        raise AIVMError(
            f'Host user {user!r} is not a member of shared AIVM group '
            f'{group!r}. First run `aivm host permissions grant {user} '
            '--admin_override`, then onboard.'
        )
    return target


def _profile_for(account: pwd.struct_passwd, vm_name: str, guest_user: str) -> tuple[Path, UserProfileStore]:
    home = Path(account.pw_dir)
    key = home / '.ssh' / 'id_aivm_ed25519'
    profile = home / '.config' / 'aivm' / 'profile.toml'
    return profile, UserProfileStore(
        active_vm=vm_name,
        ssh_identity_file=str(key),
        ssh_pubkey_path=str(key) + '.pub',
        state_dir='~/.cache/aivm',
        default_guest_user=guest_user,
    )


def _preflight_principal(reg: object, vm_name: str, account: pwd.struct_passwd, guest_user: str) -> PrincipalEntry | None:
    existing = find_principal_for_host(
        reg, vm_name=vm_name, host_user=account.pw_name
    )
    if existing is not None:
        if (existing.host_uid, existing.host_gid) != (account.pw_uid, account.pw_gid):
            raise AIVMError(
                'Host account UID/GID changed since the existing access '
                'identity was registered; use the identity repair workflow.'
            )
        if existing.guest_user != guest_user:
            raise AIVMError(
                f'Existing identity {existing.id} uses guest '
                f'{existing.guest_user!r}; onboarding cannot rotate guest users.'
            )
        if existing.state in {'removed', 'disabled'}:
            raise AIVMError(
                f'Existing access identity is {existing.state}; onboarding '
                'cannot reactivate or restore it.'
            )
    for item in find_principals_for_vm(reg, vm_name):
        if existing is not None and item.id == existing.id:
            continue
        if item.state == 'removed':
            continue
        if item.guest_user == guest_user:
            raise AIVMError(
                f'Guest account {guest_user!r} is already assigned to '
                f'{item.host_user!r} ({item.id}).'
            )
        if item.host_uid == account.pw_uid:
            raise AIVMError(
                f'Host UID {account.pw_uid} is already represented by '
                f'{item.host_user!r}; repair the account identity instead.'
            )
    return existing


def _install_helper() -> None:
    mgr = CommandManager.current()
    helper_src = Path(str(resources.files('aivm').joinpath('privileged_onboard_user.py')))
    if not helper_src.is_file():
        raise AIVMError(f'Bundled onboard helper missing: {helper_src}')
    if ONBOARD_HELPER.is_symlink() or ONBOARD_HELPER.parent.is_symlink():
        raise AIVMError('Refusing a symlinked privileged onboard helper path.')
    with mgr.intent(
        'Install the privileged AIVM onboarding helper',
        why=(
            'A stable root-owned helper drops to the target uid for profile '
            'creation, SSH key generation, and guest verification.'
        ),
        role='modify',
    ):
        mgr.run(
            ['install', '-d', '-o', 'root', '-g', 'root', '-m', '0755',
             str(ONBOARD_HELPER.parent)],
            sudo=True, role='modify',
            summary='Create root-owned AIVM helper directory',
        )
        mgr.run(
            ['install', '-o', 'root', '-g', 'root', '-m', '0755',
             str(helper_src), str(ONBOARD_HELPER)],
            sudo=True, role='modify',
            summary='Install reviewed AIVM user-onboarding helper',
        )


def _run_helper(action: str, *, account: pwd.struct_passwd, vm_name: str,
                guest_user: str, profile_text: str = '', ip: str = '') -> dict[str, object]:
    cmd = [
        str(ONBOARD_HELPER), action, '--user', account.pw_name,
        '--vm', vm_name, '--guest', guest_user,
    ]
    if ip:
        cmd += ['--ip', ip]
    result = CommandManager.current().run(
        cmd, sudo=True, role=('modify' if action == 'prepare' else 'read'),
        input_text=profile_text, check=False, capture=True, timeout=90,
        summary=(
            'Create user-owned AIVM profile and SSH identity'
            if action == 'prepare'
            else 'Verify VM SSH connection as the target host identity'
        ),
    )
    if result.code:
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Host user {action} step failed for {account.pw_name}: {detail}'
        )
    try:
        parsed = json.loads(result.stdout.strip())
    except (ValueError, TypeError) as ex:
        raise AIVMError(
            f'Onboarding helper returned invalid {action} report.'
        ) from ex
    if not isinstance(parsed, dict):
        raise AIVMError('Onboarding helper must return a JSON object.')
    return parsed


def onboard_other_principal(
    scope: StoreScope,
    *,
    vm_name: str,
    host_user: str,
    guest_user: str = '',
    ip_override: str = '',
    dry_run: bool = False,
) -> OnboardReport:
    """Create a second user's profile, guest account, and verified VM access.

    Requires administrator sudo for the root-owned helper and the existing
    restricted bootstrap channel. Does not require sudo-as-target permissions
    or any command executed by the new user.
    """
    if not scope.is_machine or scope.machine_layout is None or not scope.machine_layout.shared:
        raise AIVMError('Administrator onboarding requires the shared machine store.')
    account = _target_account(host_user)
    reg = load_scope_store(scope)
    if find_vm(reg, vm_name) is None:
        raise AIVMError(f'Unknown managed VM: {vm_name!r}')
    initial = find_principal_for_host(reg, vm_name=vm_name, host_user=host_user)
    selected_guest = (
        guest_user.strip()
        or (initial.guest_user if initial is not None else '')
        or normalized_guest_username(host_user)
    )
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', selected_guest):
        raise AIVMError('Guest login must be a valid Linux username (at most 32 characters).')
    existing = _preflight_principal(reg, vm_name, account, selected_guest)
    profile_path, profile = _profile_for(account, vm_name, selected_guest)
    principal = existing or PrincipalEntry(
        id=stable_principal_id(vm_name, host_user),
        vm_name=vm_name,
        host_user=host_user,
        host_uid=account.pw_uid,
        host_gid=account.pw_gid,
        guest_user=selected_guest,
        state='pending',
    )
    cfg = materialize_vm_cfg(reg, vm_name)
    ip_preview = ip_override.strip() or get_ip_cached(cfg) or '<vm-ip>'
    if dry_run:
        return OnboardReport(
            principal=replace(principal, state='active'), ip=ip_preview,
            profile_path=profile_path, changed=False,
        )

    _install_helper()
    # Serialize the *filesystem provisioning* with the machine registration.
    # Otherwise two administrators could both see a missing key and run
    # ssh-keygen concurrently for the same host account.
    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(scope.machine_layout),
        include_store=True, vms=[vm_name],
    ):
        reg = load_scope_store(scope)
        current = _preflight_principal(reg, vm_name, account, selected_guest)
        prepared_user = _run_helper(
            'prepare', account=account, vm_name=vm_name,
            guest_user=selected_guest, profile_text=render_user_profile(profile),
        )
        public_key = str(prepared_user.get('public_key', '')).strip()
        if not public_key.startswith('ssh-ed25519 '):
            raise AIVMError(
                'Onboarding helper did not return an Ed25519 public key.'
            )
        if current is not None and not same_ssh_public_key(
            current.ssh_public_key, public_key
        ):
            raise AIVMError(
                'Existing registered SSH key differs from the provisioned '
                'user key. Refusing silent key rotation.'
            )
        pending = replace(
            current or principal,
            ssh_public_key=(
                current.ssh_public_key if current is not None else public_key
            ),
            state=(
                current.state
                if current is not None and current.state in {'active', 'legacy'}
                else 'pending'
            ),
        )
        # The pending record is durable before the guest bootstrap call.
        # prepare_other_principal acquires its own VM/store lock, so release
        # this one before invoking it rather than nesting the lock.
        upsert_principal(reg, pending)
        save_scope_store(
            scope, reg,
            reason=f'Administrator provisioned host SSH identity for {host_user}.',
        )

    prepare_other_principal(
        scope, vm_name=vm_name, selector=pending.id,
        ip_override=ip_override,
    )
    ip = _resolve_enrollment_ip(cfg, ip_override)
    verified = _run_helper(
        'verify', account=account, vm_name=vm_name,
        guest_user=selected_guest, ip=ip,
    )
    if verified.get('verified') is not True or not same_ssh_public_key(
        public_key, str(verified.get('public_key', ''))
    ):
        raise AIVMError('Owner-identity SSH verification did not prove the registered key.')
    with machine_resource_locks(
        scope.machine_layout,
        group_gid=current_machine_group_gid(scope.machine_layout),
        include_store=True, vms=[vm_name],
    ):
        reg = load_scope_store(scope)
        current = _preflight_principal(reg, vm_name, account, selected_guest)
        if current is None or not same_ssh_public_key(current.ssh_public_key, public_key):
            raise AIVMError('Identity changed while verifying access; not activating.')
        active = replace(current, state='active')
        if active != current:
            upsert_principal(reg, active)
            save_scope_store(scope, reg, reason=(
                f'Activate {host_user} after SSH proof as uid {account.pw_uid}.'
            ))
    return OnboardReport(
        principal=active, ip=ip, profile_path=profile_path,
        changed=existing != active,
    )
