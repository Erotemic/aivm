"""CLI commands that inspect and establish sudoless operation.

``aivm host sudoless check`` reports whether this host satisfies every
requirement for running aivm without sudo. ``aivm host sudoless setup``
establishes those requirements, using sudo at most once (to add the user
to the libvirt group) and then persists the sudoless configuration.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Any

import kwconf

from ..commands import CommandManager
from ..config import AgentVMConfig, PathsConfig
from ..config_store import load_store, save_store
from ..privilege import (
    LIBVIRT_GROUP,
    LIBVIRT_QEMU_USER,
    libvirt_unprivileged_ok,
    qemu_traversal_blockers,
    user_can_write_path,
    user_in_libvirt_group,
)
from ..services import cfg_path
from ..status import status_line
from ..util import expand, which
from ._common import _BaseCommand


def _effective_default_base_dir(config_opt: str | None) -> Path:
    """Return the base_dir new VMs would get from the config store."""
    try:
        path = cfg_path(config_opt)
        if path.exists():
            reg = load_store(path)
            if reg.defaults is not None and reg.defaults.paths.base_dir:
                return Path(expand(reg.defaults.paths.base_dir))
    except Exception:
        pass
    return Path(expand(PathsConfig().base_dir))


def _firewall_enabled_anywhere(config_opt: str | None) -> bool:
    """Return True when any stored config still enables the nft firewall."""
    try:
        path = cfg_path(config_opt)
        if not path.exists():
            return AgentVMConfig().firewall.enabled
        reg = load_store(path)
        if reg.defaults is not None and reg.defaults.firewall.enabled:
            return True
        if reg.defaults is None and not reg.vms:
            return AgentVMConfig().firewall.enabled
        return any(rec.cfg.firewall.enabled for rec in reg.vms)
    except Exception:
        return True


class SudolessCheckCLI(_BaseCommand):
    """Report whether this host can run aivm without sudo."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        lines: list[str] = ['🔐 Sudoless readiness']
        ok_overall = True

        in_group = user_in_libvirt_group()
        lines.append(
            status_line(
                in_group,
                f'{LIBVIRT_GROUP} group membership',
                'grants unprivileged qemu:///system access'
                if in_group
                else f'run `sudo usermod -aG {LIBVIRT_GROUP} {getpass.getuser()}` '
                'or `aivm host sudoless setup`',
            )
        )
        ok_overall &= in_group

        live_access = libvirt_unprivileged_ok()
        live_detail = 'virsh reaches qemu:///system without sudo'
        if not live_access:
            live_detail = (
                'unprivileged virsh cannot reach qemu:///system'
                + (
                    ' (group added but not active in this session; log out/in '
                    f'or use `newgrp {LIBVIRT_GROUP}`)'
                    if in_group
                    else ''
                )
            )
        lines.append(
            status_line(live_access, 'live libvirt access', live_detail)
        )
        ok_overall &= live_access

        base_dir = _effective_default_base_dir(args.config)
        writable = user_can_write_path(base_dir)
        lines.append(
            status_line(
                writable,
                'VM storage writable',
                f'{base_dir}'
                if writable
                else f'{base_dir} needs sudo; pick a user-owned dir via '
                '`aivm host sudoless setup --base_dir ...`',
            )
        )
        ok_overall &= writable

        blockers = qemu_traversal_blockers(base_dir)
        if blockers is None:
            lines.append(
                status_line(
                    None,
                    f'{LIBVIRT_QEMU_USER} traversal',
                    'undetermined (libvirt not fully installed?)',
                )
            )
        else:
            lines.append(
                status_line(
                    not blockers,
                    f'{LIBVIRT_QEMU_USER} traversal',
                    f'qemu can reach {base_dir}'
                    if not blockers
                    else 'blocked by: '
                    + ', '.join(str(b) for b in blockers)
                    + ' (setup grants ACLs on dirs you own)',
                )
            )
            ok_overall &= not blockers

        setfacl_ok = which('setfacl') is not None
        lines.append(
            status_line(
                setfacl_ok,
                'setfacl available',
                'used to grant qemu traversal without loosening permissions'
                if setfacl_ok
                else 'install the `acl` package',
            )
        )
        ok_overall &= setfacl_ok

        fw_enabled = _firewall_enabled_anywhere(args.config)
        lines.append(
            status_line(
                None if not fw_enabled else False,
                'firewall compatibility',
                'firewall disabled; nothing needs root'
                if not fw_enabled
                else 'firewall.enabled needs root nftables access; sudoless '
                'runs will skip firewall reconciliation',
            )
        )

        mgr = CommandManager.current()
        lines.append(
            status_line(
                True if mgr.privilege_mode != 'sudo' else None,
                'privilege mode',
                f'behavior.privilege_mode = {mgr.privilege_mode!r}',
            )
        )

        print('\n'.join(lines))
        if ok_overall:
            print('✅ Host is ready for sudoless operation.')
            return 0
        print('❌ Host is not fully ready; run `aivm host sudoless setup`.')
        return 2


class SudolessSetupCLI(_BaseCommand):
    """Prepare this host for sudoless aivm operation.

    Uses sudo at most once (libvirt group membership); everything else is
    unprivileged: creating a user-owned VM storage directory, granting
    libvirt-qemu traversal via POSIX ACLs, and persisting the sudoless
    configuration.
    """

    base_dir: str = kwconf.Value(
        '',
        help=(
            'User-owned VM storage directory to configure (default: keep '
            'the current default when writable, else ~/.local/share/aivm).'
        ),
    )
    mode: str = kwconf.Value(
        'sudoless',
        help=(
            "privilege_mode to persist: 'sudoless' (never sudo) or 'auto' "
            '(sudoless where possible, sudo fallback).'
        ),
    )
    keep_firewall: bool = kwconf.Flag(
        False,
        help=(
            'Keep firewall.enabled in the default config even though '
            'sudoless runs cannot manage nftables.'
        ),
    )
    dry_run: bool = kwconf.Flag(False, help='Print actions without running.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.mode not in {'sudoless', 'auto'}:
            print("--mode must be 'sudoless' or 'auto'")
            return 2
        mgr = CommandManager.current()
        if mgr.privilege_mode == 'sudoless':
            # Setup is the transition tool: it may need one privileged
            # command (usermod), so it runs with sudo fallback enabled even
            # when the config already says sudoless.
            print(
                'ℹ️ Sudoless setup may use sudo once (libvirt group '
                'membership); everything else runs unprivileged.'
            )
            mgr = CommandManager(
                yes=bool(args.yes),
                yes_sudo=bool(args.yes_sudo),
                auto_approve_readonly_sudo=mgr.auto_approve_readonly_sudo,
                privilege_mode='auto',
            )
            CommandManager.activate(mgr)

        group_added = False
        if not user_in_libvirt_group():
            # Under `sudo aivm ...`, the account that needs libvirt access
            # is the invoking user, not root.
            user = os.environ.get('SUDO_USER') or getpass.getuser()
            if args.dry_run:
                print(f'DRYRUN: sudo usermod -aG {LIBVIRT_GROUP} {user}')
            else:
                with mgr.intent(
                    'Enable unprivileged libvirt access',
                    why=(
                        'Membership in the libvirt group lets virsh reach '
                        'qemu:///system without sudo (polkit rule shipped '
                        'with libvirt).'
                    ),
                    role='modify',
                ):
                    with mgr.step(
                        'Add user to libvirt group',
                        why=(
                            'This is the one privileged step of sudoless '
                            'setup; everything else runs unprivileged.'
                        ),
                        approval_scope='sudoless-setup-group',
                    ):
                        mgr.submit(
                            ['usermod', '-aG', LIBVIRT_GROUP, user],
                            sudo=True,
                            role='modify',
                            check=True,
                            capture=True,
                            summary=f'Add {user} to the {LIBVIRT_GROUP} group',
                        )
                group_added = True

        base_dir = (
            Path(expand(args.base_dir))
            if args.base_dir
            else _effective_default_base_dir(args.config)
        )
        if not args.base_dir and not user_can_write_path(base_dir):
            base_dir = Path(expand('~/.local/share/aivm'))
            print(
                f'Default VM storage is not user-writable; using {base_dir} '
                'for sudoless operation.'
            )
        if not user_can_write_path(base_dir):
            print(
                f'❌ {base_dir} is not writable by you; pass a user-owned '
                'directory via --base_dir.'
            )
            return 2

        if args.dry_run:
            print(f'DRYRUN: mkdir -p {base_dir}; grant {LIBVIRT_QEMU_USER} ACLs')
        else:
            with mgr.intent(
                'Prepare sudoless VM storage',
                why=(
                    'VM images and cloud-init artifacts live in a '
                    'user-owned tree so no file operation needs sudo.'
                ),
                role='modify',
            ):
                with mgr.step(
                    'Create user-owned VM storage and grant qemu traversal',
                    why=(
                        'QEMU runs as libvirt-qemu and needs execute (search) '
                        'access on every ancestor of the image tree; targeted '
                        'ACLs grant that without changing ownership.'
                    ),
                    approval_scope=f'sudoless-setup-storage:{base_dir}',
                ):
                    mgr.submit(
                        ['mkdir', '-p', str(base_dir)],
                        sudo=False,
                        role='modify',
                        check=True,
                        capture=True,
                        summary='Create VM storage directory',
                        detail=f'target={base_dir}',
                    )
                    mgr.submit(
                        ['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(base_dir)],
                        sudo=False,
                        role='modify',
                        check=True,
                        capture=True,
                        summary=f'Allow {LIBVIRT_QEMU_USER} to traverse {base_dir}',
                    )
            blockers = qemu_traversal_blockers(base_dir) or []
            own_blockers = [b for b in blockers if user_can_write_path(b)]
            foreign = [b for b in blockers if not user_can_write_path(b)]
            for b in own_blockers:
                mgr.run(
                    ['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(b)],
                    sudo=False,
                    role='modify',
                    check=True,
                    capture=True,
                    summary=f'Allow {LIBVIRT_QEMU_USER} to traverse {b}',
                )
            if foreign:
                print(
                    '⚠️ These directories still block libvirt-qemu and are '
                    'not owned by you:'
                )
                for b in foreign:
                    print(f'  sudo setfacl -m u:{LIBVIRT_QEMU_USER}:x {b}')

        # Persist config: privilege mode, default base_dir, firewall policy.
        store = cfg_path(args.config)
        reg = load_store(store)
        reg.behavior.privilege_mode = args.mode
        if reg.defaults is None:
            reg.defaults = AgentVMConfig()
        reg.defaults.paths.base_dir = str(base_dir)
        firewall_note = ''
        if reg.defaults.firewall.enabled and not args.keep_firewall:
            reg.defaults.firewall.enabled = False
            firewall_note = (
                'Disabled firewall.enabled in default config: nftables '
                'management needs root. NOTE this loosens guest network '
                'confinement for NEW VMs; pass --keep_firewall to keep it '
                '(sudoless runs will then skip firewall reconciliation).'
            )
        if args.dry_run:
            print(f'DRYRUN: would persist privilege_mode={args.mode!r}, ')
            print(f'DRYRUN: default base_dir={base_dir}')
            if firewall_note:
                print(f'DRYRUN: {firewall_note}')
            return 0
        save_store(
            reg,
            store,
            reason=(
                f'Persist sudoless setup: privilege_mode={args.mode}, '
                f'default base_dir={base_dir}.'
            ),
        )
        print(f'Persisted behavior.privilege_mode = {args.mode!r}')
        print(f'Persisted default paths.base_dir = {base_dir}')
        if firewall_note:
            print(f'⚠️ {firewall_note}')
        for rec in reg.vms:
            vm_base = Path(expand(rec.cfg.paths.base_dir))
            if not user_can_write_path(vm_base):
                print(
                    f'⚠️ Existing VM {rec.name!r} stores images under '
                    f'{vm_base}, which still needs sudo; recreate it or '
                    'move its storage for fully sudoless operation.'
                )
        if group_added:
            print(
                f'👉 Group membership added. Log out and back in (or run '
                f'`newgrp {LIBVIRT_GROUP}`) so it takes effect, then run '
                '`aivm host sudoless check`.'
            )
        else:
            print('Run `aivm host sudoless check` to verify readiness.')
        return 0


class SudolessModalCLI(kwconf.ModalCLI):
    """Inspect or establish sudoless (never-sudo) operation for this host."""

    check = SudolessCheckCLI
    setup = SudolessSetupCLI
