"""Shared-machine access identity commands."""

from __future__ import annotations

from typing import Any

import kwconf

from ..access_control import (
    TRUST_MODE,
    AccessAction,
    access_ownership_summary,
    mutate_access_identity,
    repair_current_host_identity,
)
from ..commands import CommandManager
from ..config_store import find_principals_for_vm
from ..enrollment import reconcile_current_principal
from ..errors import AIVMError
from ..host_identity import current_host_identity
from ..scoped_store import load_scope_store, resolve_store_scope
from ..services import resolve_vm_name
from ._common import _BaseCommand


class VMAccessListCLI(_BaseCommand):
    """List host access identities enrolled for a managed VM."""

    vm: str = kwconf.Value('', help='Optional VM name override.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        vm_name, path = resolve_vm_name(
            config_opt=args.config,
            vm_opt=str(args.vm or ''),
            host_src=None,
        )
        scope = resolve_store_scope(str(path))
        if not scope.is_machine:
            raise AIVMError(
                'Access identity commands require the shared machine store.'
            )
        reg = load_scope_store(scope)
        current = current_host_identity()
        identities = find_principals_for_vm(reg, vm_name)
        print(f'VM access identities: {vm_name}')
        print(f'Trust mode: {TRUST_MODE}')
        if not identities:
            print('  (none)')
        for identity in identities:
            marker = (
                '*'
                if identity.host_user == current.username
                and identity.host_uid == current.uid
                else ' '
            )
            owned = access_ownership_summary(
                reg, vm_name=vm_name, principal_id=identity.id
            )
            print(
                f'{marker} {identity.host_user} -> {identity.guest_user} '
                f'| state={identity.state} | uid={identity.host_uid} '
                f'gid={identity.host_gid} | attachments={owned.attachment_count} '
                f'credentials={owned.credential_count} | id={identity.id}'
            )
        print(f'Machine store: {path}')
        return 0


class VMAccessReconcileCLI(_BaseCommand):
    """Create, repair, or explicitly re-enable the caller's access identity."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    guest_user: str = kwconf.Value(
        '',
        help=(
            'Guest username override. By default AIVM reuses the persisted '
            'name or derives <host-user>-agent.'
        ),
    )
    ip: str = kwconf.Value(
        '',
        help='Optional VM IP override; normally resolved from libvirt state.',
    )
    enable: bool = kwconf.Flag(
        False,
        help=(
            'Explicitly restore a disabled identity owned by the current host '
            'user. Without this flag disabled identities remain disabled.'
        ),
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Describe enrollment without changing machine or guest state.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        vm_name, path = resolve_vm_name(
            config_opt=args.config,
            vm_opt=str(args.vm or ''),
            host_src=None,
        )
        scope = resolve_store_scope(str(path))
        report = reconcile_current_principal(
            scope,
            vm_name=vm_name,
            guest_user=str(args.guest_user or ''),
            ip_override=str(args.ip or ''),
            dry_run=bool(args.dry_run),
            enable_disabled=bool(args.enable),
        )
        prefix = 'Would enroll' if args.dry_run else 'Enrolled'
        print(
            f'{prefix} {report.principal.host_user} as '
            f'{report.principal.guest_user} on {vm_name} at {report.ip} '
            f'(state={report.principal.state}).'
        )
        return 0


class VMAccessRepairHostIdentityCLI(_BaseCommand):
    """Repair a host account rename while preserving the access identity id."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Describe the repair without changing the machine store.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        vm_name, path = resolve_vm_name(
            config_opt=args.config,
            vm_opt=str(args.vm or ''),
            host_src=None,
        )
        scope = resolve_store_scope(str(path))
        report = repair_current_host_identity(
            scope, vm_name=vm_name, dry_run=bool(args.dry_run)
        )
        prefix = 'Would repair' if args.dry_run else 'Repaired'
        if report.changed:
            print(
                f'{prefix} access identity {report.principal.id}: '
                f'{report.previous_host_user} -> '
                f'{report.principal.host_user} (uid={report.principal.host_uid}).'
            )
        else:
            print(
                f'Access identity {report.principal.id} already matches '
                f'{report.principal.host_user} (uid={report.principal.host_uid}).'
            )
        return 0


class _VMAccessMutationCLI(_BaseCommand):
    """Shared options for disable/remove commands."""

    identity: str = kwconf.Value(
        '',
        position=1,
        nargs='?',
        help=(
            'Access identity id or host login. Defaults to the current host '
            'user.'
        ),
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    ip: str = kwconf.Value(
        '', help='Optional VM IP override for the restricted guest operation.'
    )
    admin_override: bool = kwconf.Flag(
        False,
        help=(
            'Allow a trusted host administrator to target another host '
            "user's identity. This does not grant access to that user's secrets."
        ),
    )
    allow_last_access: bool = kwconf.Flag(
        False,
        help=(
            'Permit disabling the last active identity. Ordinary SSH/code '
            'access will be unavailable until bootstrap reconciliation.'
        ),
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Describe the operation without changing guest or host state.',
    )

    @classmethod
    def _run_action(
        cls, *, action: AccessAction, argv: bool, kwargs: dict[str, Any]
    ) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        vm_name, path = resolve_vm_name(
            config_opt=args.config,
            vm_opt=str(args.vm or ''),
            host_src=None,
        )
        scope = resolve_store_scope(str(path))
        purpose = (
            f'{action.title()} access identity '
            f'{str(args.identity or current_host_identity().username)!r} on shared VM '
            f'{vm_name}. This is a machine-wide access-control change.'
        )
        mgr = CommandManager.current()
        if args.dry_run:
            report = mutate_access_identity(
                scope,
                vm_name=vm_name,
                selector=str(args.identity or ''),
                action=action,
                administrative_override=bool(args.admin_override),
                allow_last_access=bool(args.allow_last_access),
                ip_override=str(args.ip or ''),
                dry_run=True,
            )
        else:
            with mgr.approved_action(purpose=purpose):
                report = mutate_access_identity(
                    scope,
                    vm_name=vm_name,
                    selector=str(args.identity or ''),
                    action=action,
                    administrative_override=bool(args.admin_override),
                    allow_last_access=bool(args.allow_last_access),
                    ip_override=str(args.ip or ''),
                    dry_run=False,
                )
        if action == 'remove':
            prefix = 'Would remove' if args.dry_run else 'Removed'
        else:
            prefix = 'Would disable' if args.dry_run else 'Disabled'
        print(
            f'{prefix} access identity {report.principal.host_user} -> '
            f'{report.principal.guest_user} ({report.principal.id}) on '
            f'{vm_name}.'
        )
        if report.ownership.has_owned_records:
            print(
                'Owned records retained: '
                f'{report.ownership.attachment_count} attachment(s), '
                f'{report.ownership.credential_count} credential(s).'
            )
        if action == 'remove':
            print('Guest home retained; no guest files were deleted.')
        return 0


class VMAccessDisableCLI(_VMAccessMutationCLI):
    """Disable guest login and sudo while retaining ownership metadata."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        return cls._run_action(action='disable', argv=argv, kwargs=kwargs)


class VMAccessRemoveCLI(_VMAccessMutationCLI):
    """Remove a disabled identity after all owned records are resolved."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        return cls._run_action(action='remove', argv=argv, kwargs=kwargs)


class VMAccessModalCLI(kwconf.ModalCLI):
    """Manage host-user access to one shared VM."""

    list = VMAccessListCLI
    reconcile = VMAccessReconcileCLI
    repair_host_identity = VMAccessRepairHostIdentityCLI
    disable = VMAccessDisableCLI
    remove = VMAccessRemoveCLI


__all__ = [
    'VMAccessDisableCLI',
    'VMAccessListCLI',
    'VMAccessModalCLI',
    'VMAccessReconcileCLI',
    'VMAccessRepairHostIdentityCLI',
    'VMAccessRemoveCLI',
]
