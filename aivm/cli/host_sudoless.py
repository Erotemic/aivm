"""CLI commands that inspect and establish sudoless operation.

"Sudoless" here names a property of the *host*, not a mode aivm runs in: a
host is sudoless-ready when aivm never needs to escalate to do its ordinary
work. ``aivm host sudoless check`` reports whether this host is there yet.
``aivm host sudoless setup`` establishes the host-side prerequisites --
libvirt group membership (its one privileged step) and a user-owned VM
storage tree with libvirt-qemu traversal ACLs.

Setup does not change your config. Establishing a capability and choosing a
policy are different acts: ``behavior.privilege_mode`` and
``firewall.enabled`` stay yours to set. Once the host work is done, the
default ``privilege_mode='auto'`` stops invoking sudo for libvirt and image
operations on its own -- no mode flip required, and the firewall keeps
working. ``--persist`` opts in to the one config value the host work
genuinely depends on (``defaults.paths.base_dir``, which the ACLs are
granted on), and writes nothing else.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Any

import kwconf

from ..commands import CommandManager
from ..config import AgentVMConfig, BehaviorConfig, PathsConfig
from ..config_store import load_store, save_store
from ..modes import PrivilegeMode
from ..privilege import (
    LIBVIRT_GROUP,
    LIBVIRT_QEMU_USER,
    libvirt_unprivileged_ok,
    normalize_privilege_mode,
    qemu_traversal_blockers,
    user_can_write_path,
    user_in_libvirt_group,
)
from ..services import cfg_path
from ..status import status_line
from ..util import expand, which
from ._common import _BaseCommand

#: Where setup puts VM storage when the configured base_dir needs root.
USER_BASE_DIR = '~/.local/share/aivm'


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


def _print_base_dir_toml(base_dir: Path) -> None:
    """Print the exact config lines that point VM storage at ``base_dir``."""
    print()
    print('    [defaults.paths]')
    print(f'    base_dir = "{base_dir}"')
    print()


def _configured_privilege_mode(config_opt: str | None) -> PrivilegeMode:
    """Return the persisted privilege mode, not the one this run is using.

    Setup temporarily activates an ``auto`` manager so it can run ``usermod``
    even under a sudoless config, so the live manager is not the answer to
    "what did the user choose?".
    """
    try:
        path = cfg_path(config_opt)
        if path.exists():
            return normalize_privilege_mode(load_store(path).behavior.privilege_mode)
    except Exception:
        pass
    return normalize_privilege_mode(BehaviorConfig().privilege_mode)


def _print_policy_report(config_opt: str | None, *, group_added: bool) -> None:
    """Report the privilege policy setup deliberately did not change."""
    mode = _configured_privilege_mode(config_opt)
    if mode == PrivilegeMode.SUDOLESS:
        print("behavior.privilege_mode = 'sudoless': aivm refuses rather than")
        print('  escalates. It cannot manage the nftables firewall, and cannot')
        print('  establish a *new* persistent/shared-root attachment, because')
        print('  `mount --bind` has no unprivileged implementation.')
        if _firewall_enabled_anywhere(config_opt):
            print(
                '⚠️ firewall.enabled is true, which sudoless mode cannot honor. '
                'Disable the firewall or choose a mode that may escalate.'
            )
    elif mode == PrivilegeMode.SUDO:
        print("behavior.privilege_mode = 'sudo': aivm escalates for every")
        print('  privileged-capable operation, so the host work above buys you')
        print("  nothing until you switch to 'auto'.")
    else:
        print(f"behavior.privilege_mode = '{mode}', unchanged and correct:")
        print('  once the libvirt group is active, aivm stops invoking sudo for')
        print('  libvirt and image operations on its own. Sudo remains only for')
        print('  the nftables firewall, apt-get, and establishing a new host')
        print('  bind mount.')
    if group_added:
        print(
            f'👉 Group membership added. Log out and back in (or run `newgrp '
            f'{LIBVIRT_GROUP}`) so it takes effect.'
        )
    print('Run `aivm host sudoless check` to verify readiness.')


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
                else 'firewall.enabled requires root nftables access, which '
                'has no unprivileged equivalent; disable it to run fully '
                'without sudo',
            )
        )

        mode = _configured_privilege_mode(args.config)
        lines.append(
            status_line(
                True if mode != PrivilegeMode.SUDO else None,
                'privilege mode',
                f'behavior.privilege_mode = {str(mode)!r}',
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
    unprivileged: creating a user-owned VM storage directory and granting
    libvirt-qemu traversal via POSIX ACLs. Your config is not modified
    unless you pass ``--persist``, and even then only
    ``defaults.paths.base_dir`` is written.
    """

    base_dir: str = kwconf.Value(
        '',
        help=(
            'User-owned VM storage directory to prepare (default: the '
            f'directory your config already resolves to, else {USER_BASE_DIR}).'
        ),
    )
    persist: bool = kwconf.Flag(
        False,
        help=(
            'Write the prepared directory to defaults.paths.base_dir. '
            'Nothing else is ever written: privilege_mode and '
            'firewall.enabled stay yours to set.'
        ),
    )
    dry_run: bool = kwconf.Flag(False, help='Print actions without running.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
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

        # The ACLs below are granted on one specific directory, so they are
        # worthless unless aivm goes on to use it. Prefer the directory the
        # config already resolves to: when that is user-owned the host work
        # lands where aivm already looks and no config change is implied.
        resolved_default = _effective_default_base_dir(args.config)
        base_dir = (
            Path(expand(args.base_dir)) if args.base_dir else resolved_default
        )
        if not args.base_dir and not user_can_write_path(base_dir):
            base_dir = Path(expand(USER_BASE_DIR))
            print(
                f'{resolved_default} is not user-writable, so preparing '
                f'{base_dir} instead.'
            )
        if not user_can_write_path(base_dir):
            print(
                f'❌ {base_dir} is not writable by you; pass a user-owned '
                'directory via --base_dir.'
            )
            return 2
        config_gap = base_dir != resolved_default

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

        store = cfg_path(args.config)
        has_defaults = store.exists() and load_store(store).defaults is not None
        if config_gap and args.persist and not has_defaults:
            # Creating a [defaults] section to hold one path would materialize
            # every other default alongside it, pinning values the user never
            # chose -- including a hostname-derived vm.name. Decline.
            print()
            print(
                f'❌ Cannot persist: {store} has no [defaults] section, and '
                'creating one would pin every other default value. Run '
                '`aivm config init` first, or add this yourself:'
            )
            _print_base_dir_toml(base_dir)
            return 2
        if config_gap and args.persist:
            if args.dry_run:
                print(f'DRYRUN: would persist default base_dir={base_dir}')
            else:
                reg = load_store(store)
                assert reg.defaults is not None  # guarded by has_defaults
                reg.defaults.paths.base_dir = str(base_dir)
                save_store(
                    reg,
                    store,
                    reason=f'Persist sudoless setup: base_dir={base_dir}.',
                )
                print(f'Persisted default paths.base_dir = {base_dir}')
        elif config_gap:
            print()
            print(
                f'Nothing in your config changed. aivm still resolves VM '
                f'storage to {resolved_default}, so the ACLs just granted on '
                f'{base_dir} will go unused until you point it there. Add to '
                f'{store}:'
            )
            _print_base_dir_toml(base_dir)
            if has_defaults:
                print('Or re-run with --persist to write exactly that line.')
        else:
            print(
                f'Nothing in your config needs to change; VM storage already '
                f'resolves to {base_dir}.'
            )

        print()
        _print_policy_report(args.config, group_added=group_added)
        existing_vms = load_store(store).vms if store.exists() else []
        for rec in existing_vms:
            vm_base = Path(expand(rec.cfg.paths.base_dir))
            if not user_can_write_path(vm_base):
                print(
                    f'⚠️ Existing VM {rec.name!r} stores images under '
                    f'{vm_base}, which still needs sudo; recreate it or '
                    'move its storage for fully sudoless operation.'
                )
        return 0


class SudolessModalCLI(kwconf.ModalCLI):
    """Inspect or establish sudoless (never-sudo) operation for this host."""

    check = SudolessCheckCLI
    setup = SudolessSetupCLI
