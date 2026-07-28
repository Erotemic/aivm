"""Shared-machine principal access commands."""

from __future__ import annotations

import getpass
from typing import Any

import kwconf

from ..config_store import find_principals_for_vm
from ..enrollment import reconcile_current_principal
from ..errors import AIVMError
from ..scoped_store import load_scope_store, resolve_store_scope
from ..services import resolve_vm_name
from ._common import _BaseCommand


class VMAccessListCLI(_BaseCommand):
    """List host principals enrolled for a managed VM."""

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
                'Principal access commands require the shared machine store.'
            )
        reg = load_scope_store(scope)
        current = getpass.getuser()
        principals = find_principals_for_vm(reg, vm_name)
        print(f'VM principals: {vm_name}')
        if not principals:
            print('  (none)')
        for principal in principals:
            marker = '*' if principal.host_user == current else ' '
            print(
                f'{marker} {principal.host_user} -> {principal.guest_user} '
                f'| state={principal.state} | uid={principal.host_uid} '
                f'gid={principal.host_gid} | id={principal.id}'
            )
        print(f'Machine store: {path}')
        return 0


class VMAccessReconcileCLI(_BaseCommand):
    """Create or repair the current host user's guest principal."""

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
    dry_run: bool = kwconf.Flag(
        False,
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
        )
        prefix = 'Would enroll' if args.dry_run else 'Enrolled'
        print(
            f'{prefix} {report.principal.host_user} as '
            f'{report.principal.guest_user} on {vm_name} at {report.ip} '
            f'(state={report.principal.state}).'
        )
        return 0


class VMAccessModalCLI(kwconf.ModalCLI):
    """Manage host-user access to one shared VM."""

    list = VMAccessListCLI
    reconcile = VMAccessReconcileCLI


__all__ = [
    'VMAccessListCLI',
    'VMAccessModalCLI',
    'VMAccessReconcileCLI',
]
