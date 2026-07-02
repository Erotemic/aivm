"""CLI commands that inspect and establish rootless (session-runtime) operation.

``aivm host rootless check`` reports whether this host satisfies every
requirement for running truly rootless VMs on the per-user
``qemu:///session`` daemon. ``aivm host rootless setup`` establishes those
requirements, using sudo at most once (to add the user to the ``kvm``
group when ``/dev/kvm`` is not accessible) and then persists the session
runtime configuration.

This is one privilege step below ``aivm host sudoless``: sudoless still
talks to the root system libvirt daemon (libvirt group membership is
root-equivalent), while the session runtime needs no root daemon at all.
"""

from __future__ import annotations

import getpass
import os
import subprocess
from pathlib import Path
from typing import Any

import kwconf

from ..commands import CommandManager
from ..config import (
    SESSION_DEFAULT_BASE_DIR,
    AgentVMConfig,
)
from ..config_store import load_store, save_store
from ..host import SESSION_ONLY_CMDS
from ..privilege import user_can_write_path
from ..runtime import SESSION_LIBVIRT_URI
from ..services import cfg_path
from ..status import status_line
from ..util import expand, which
from ._common import _BaseCommand

KVM_DEVICE = Path('/dev/kvm')
KVM_GROUP = 'kvm'

#: Host commands the session runtime needs beyond the standard required set.
_ROOTLESS_REQUIRED_CMDS = (
    'virsh',
    'virt-install',
    'qemu-img',
    'cloud-localds',
    *SESSION_ONLY_CMDS,
)


def _kvm_accessible() -> bool:
    """Return True when the invoking user can open /dev/kvm."""
    return os.access(KVM_DEVICE, os.R_OK | os.W_OK)


def _session_libvirt_ok() -> bool:
    """Return True when the per-user libvirt daemon is reachable.

    Uses a plain subprocess (not the CommandManager) because this is a
    pure local capability probe with no privilege or approval dimension:
    qemu:///session auto-spawns a user daemon on first contact.
    """
    if which('virsh') is None:
        return False
    probe = subprocess.run(
        ['virsh', '-c', SESSION_LIBVIRT_URI, 'version'],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return probe.returncode == 0


def _effective_session_base_dir(config_opt: str | None) -> Path:
    """Return the base_dir a new session VM would get from the store."""
    try:
        path = cfg_path(config_opt)
        if path.exists():
            reg = load_store(path)
            if reg.defaults is not None and reg.defaults.paths.base_dir:
                candidate = Path(expand(reg.defaults.paths.base_dir))
                # The system-mode default is root-owned; session falls back
                # to the user tree the same way apply_session_runtime_defaults
                # does.
                from ..config import PathsConfig

                if candidate != Path(expand(PathsConfig().base_dir)):
                    return candidate
    except Exception:
        pass
    return Path(expand(SESSION_DEFAULT_BASE_DIR))


class RootlessCheckCLI(_BaseCommand):
    """Report whether this host can run fully rootless session VMs."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        lines: list[str] = ['🪶 Rootless (session runtime) readiness']
        ok_overall = True

        kvm_ok = _kvm_accessible()
        if kvm_ok:
            kvm_detail = 'user can open the KVM device'
        elif not KVM_DEVICE.exists():
            from ..detect import running_under_wsl

            kvm_detail = '/dev/kvm does not exist'
            if running_under_wsl():
                kvm_detail += (
                    ' (WSL2: enable `nestedVirtualization=true` under '
                    '[wsl2] in %UserProfile%\\.wslconfig, then '
                    '`wsl --shutdown`; WSL1 cannot run KVM)'
                )
            else:
                kvm_detail += (
                    ' (enable VT-x/AMD-V in firmware; check the kvm '
                    'kernel module)'
                )
        else:
            kvm_detail = (
                f'run `sudo usermod -aG {KVM_GROUP} {getpass.getuser()}` '
                'or `aivm host rootless setup`, then log out/in'
            )
        lines.append(status_line(kvm_ok, '/dev/kvm access', kvm_detail))
        ok_overall &= kvm_ok

        session_ok = _session_libvirt_ok()
        lines.append(
            status_line(
                session_ok,
                'session libvirt',
                f'virsh reaches {SESSION_LIBVIRT_URI}'
                if session_ok
                else f'`virsh -c {SESSION_LIBVIRT_URI} version` failed; '
                'install libvirt client/daemon packages',
            )
        )
        ok_overall &= session_ok

        for cmd in _ROOTLESS_REQUIRED_CMDS:
            present = which(cmd) is not None
            hint = 'required for session VMs'
            if cmd == 'passt':
                hint = (
                    'provides user-mode networking with SSH port forwards'
                    if present
                    else 'install the `passt` package'
                )
            elif not present:
                hint = 'install it (see `aivm host install_deps`)'
            lines.append(status_line(present, f'{cmd} available', hint))
            ok_overall &= present

        base_dir = _effective_session_base_dir(args.config)
        writable = user_can_write_path(base_dir)
        lines.append(
            status_line(
                writable,
                'VM storage writable',
                f'{base_dir}'
                if writable
                else f'{base_dir} is not user-writable; pick a user-owned '
                'dir via `aivm host rootless setup --base_dir ...`',
            )
        )
        ok_overall &= writable

        reg_path = cfg_path(args.config)
        runtime_mode = 'system'
        if reg_path.exists():
            reg = load_store(reg_path)
            if reg.defaults is not None:
                runtime_mode = str(reg.defaults.runtime.mode or 'system')
        lines.append(
            status_line(
                True if runtime_mode == 'session' else None,
                'default runtime mode',
                f'defaults.runtime.mode = {runtime_mode!r}'
                + (
                    ''
                    if runtime_mode == 'session'
                    else ' (run `aivm host rootless setup` to switch new '
                    'VMs to the session runtime)'
                ),
            )
        )

        print('\n'.join(lines))
        if ok_overall:
            print('✅ Host is ready for rootless session VMs.')
            return 0
        print('❌ Host is not fully ready; run `aivm host rootless setup`.')
        return 2


class RootlessSetupCLI(_BaseCommand):
    """Prepare this host for rootless session-runtime aivm operation.

    Uses sudo at most once (kvm group membership when /dev/kvm is not yet
    accessible); everything else is unprivileged: creating a user-owned VM
    storage directory and persisting the session runtime configuration.
    """

    base_dir: str = kwconf.Value(
        '',
        help=(
            'User-owned VM storage directory to configure '
            f'(default: {SESSION_DEFAULT_BASE_DIR}).'
        ),
    )
    dry_run: bool = kwconf.Flag(False, help='Print actions without running.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        mgr = CommandManager.current()
        if mgr.privilege_mode == 'sudoless':
            # Setup is the transition tool: it may need one privileged
            # command (usermod for kvm access), so it runs with sudo
            # fallback enabled even when the config already says sudoless.
            print(
                'ℹ️ Rootless setup may use sudo once (kvm group '
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
        if not _kvm_accessible():
            user = os.environ.get('SUDO_USER') or getpass.getuser()
            if args.dry_run:
                print(f'DRYRUN: sudo usermod -aG {KVM_GROUP} {user}')
            else:
                with mgr.intent(
                    'Enable unprivileged KVM access',
                    why=(
                        'Membership in the kvm group lets session-mode '
                        'qemu use hardware virtualization via /dev/kvm.'
                    ),
                    role='modify',
                ):
                    with mgr.step(
                        'Add user to kvm group',
                        why=(
                            'This is the one privileged step of rootless '
                            'setup; everything else runs unprivileged.'
                        ),
                        approval_scope='rootless-setup-group',
                    ):
                        mgr.submit(
                            ['usermod', '-aG', KVM_GROUP, user],
                            sudo=True,
                            role='modify',
                            check=True,
                            capture=True,
                            summary=f'Add {user} to the {KVM_GROUP} group',
                        )
                group_added = True

        base_dir = (
            Path(expand(args.base_dir))
            if args.base_dir
            else _effective_session_base_dir(args.config)
        )
        if not user_can_write_path(base_dir):
            print(
                f'❌ {base_dir} is not writable by you; pass a user-owned '
                'directory via --base_dir.'
            )
            return 2
        if args.dry_run:
            print(f'DRYRUN: mkdir -p {base_dir}')
        else:
            with mgr.intent(
                'Prepare rootless VM storage',
                why=(
                    'Session VM images and cloud-init artifacts live in a '
                    'user-owned tree; qemu runs as you, so plain '
                    'directories suffice.'
                ),
                role='modify',
            ):
                mgr.run(
                    ['mkdir', '-p', str(base_dir)],
                    sudo=False,
                    role='modify',
                    check=True,
                    capture=True,
                    summary='Create VM storage directory',
                )

        missing = [c for c in _ROOTLESS_REQUIRED_CMDS if which(c) is None]
        if missing:
            print(
                '⚠️ Missing host packages for the session runtime: '
                + ', '.join(missing)
            )
            print(
                '   Install them (e.g. `sudo apt install passt` for passt) '
                'and re-run `aivm host rootless check`.'
            )

        # Persist config: session runtime, never-sudo privilege mode,
        # user-owned storage, firewall off (not applicable in session).
        store = cfg_path(args.config)
        reg = load_store(store)
        reg.behavior.privilege_mode = 'sudoless'
        if reg.defaults is None:
            reg.defaults = AgentVMConfig()
        reg.defaults.runtime.mode = 'session'
        reg.defaults.paths.base_dir = str(base_dir)
        firewall_note = ''
        if reg.defaults.firewall.enabled:
            reg.defaults.firewall.enabled = False
            firewall_note = (
                'Disabled firewall.enabled in default config: the nftables '
                'firewall only applies to system-runtime managed networks.'
            )
        if args.dry_run:
            print("DRYRUN: would persist defaults.runtime.mode = 'session',")
            print("DRYRUN: behavior.privilege_mode = 'sudoless',")
            print(f'DRYRUN: default base_dir = {base_dir}')
            if firewall_note:
                print(f'DRYRUN: {firewall_note}')
            return 0
        save_store(
            reg,
            store,
            reason=(
                'Persist rootless setup: runtime.mode=session, '
                f'privilege_mode=sudoless, default base_dir={base_dir}.'
            ),
        )
        print("Persisted defaults.runtime.mode = 'session'")
        print("Persisted behavior.privilege_mode = 'sudoless'")
        print(f'Persisted default paths.base_dir = {base_dir}')
        if firewall_note:
            print(f'⚠️ {firewall_note}')
        for rec in reg.vms:
            mode = str(rec.cfg.runtime.mode or 'system').strip().lower()
            if mode != 'session':
                print(
                    f'⚠️ Existing VM {rec.name!r} uses runtime.mode='
                    f'{mode!r} and is not affected; session mode applies '
                    'to newly created VMs.'
                )
        if group_added:
            print(
                '👉 Group membership added. Log out and back in (or run '
                f'`newgrp {KVM_GROUP}`) so it takes effect, then run '
                '`aivm host rootless check`.'
            )
        else:
            print('Run `aivm host rootless check` to verify readiness.')
        return 0


class RootlessModalCLI(kwconf.ModalCLI):
    """Inspect or establish rootless session-runtime operation for this host."""

    check = RootlessCheckCLI
    setup = RootlessSetupCLI
