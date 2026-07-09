"""VM virtiofs fd guard CLI commands.

Manages the guest-side guard documented in ``docs/source/virtiofs.rst``:
a systemd timer inside the guest that (a) keeps ``updatedb`` from sweeping
virtiofs shares (the nightly walk that saturates host virtiofsd fd limits)
and (b) flushes guest dentry/inode caches when the fuse inode count crosses
a watermark, releasing host-side virtiofsd file descriptors before EMFILE.

New VMs get the guard automatically via cloud-init when
``virtiofs.fd_guard`` is enabled (the default), and ``aivm vm update``
reconciles existing running VMs against that config. This command is the
direct manual path: inspect, install/refresh, or remove the guard over SSH
without a full update pass.
"""

from __future__ import annotations

import shlex
from typing import Any

import kwconf
from loguru import logger as log

from ..attachments.session import _resolve_ip_for_ssh_ops
from ..commands import CommandManager, shell_join
from ..errors import AIVMError
from ..fdguard import (
    fdguard_install_script,
    fdguard_status_script,
    fdguard_uninstall_script,
)
from ..runtime import require_ssh_identity, ssh_base_args
from ..services import load_cfg
from ._common import _BaseCommand

_ACTIONS = ('status', 'install', 'uninstall')


class VMFdGuardCLI(_BaseCommand):
    """Manage the guest-side virtiofs fd guard (watermark cache flusher)."""

    vm: str = kwconf.Value(
        '',
        help='VM name override.',
    )
    action: str = kwconf.Value(
        'status',
        parser=str,
        help=(
            'One of: status (show guard/timer state and current fuse inode '
            'count), install (install or update the guard, enable its '
            'timer, and run it once), uninstall (disable the timer and '
            'remove guard files).'
        ),
    )
    threshold: int = kwconf.Value(
        0,
        parser=int,
        help=(
            'Override virtiofs.fd_guard_threshold for install: flush guest '
            'dentry/inode caches when the fuse inode count exceeds this. '
            '0 uses the configured value.'
        ),
    )
    interval_sec: int = kwconf.Value(
        0,
        parser=int,
        help=(
            'Override virtiofs.fd_guard_interval_sec for install: seconds '
            'between guard checks. 0 uses the configured value.'
        ),
    )
    timeout: int = kwconf.Value(
        60,
        parser=int,
        help='SSH command timeout in seconds.',
    )
    dry_run: bool = kwconf.Flag(
        False,
        help='Print the guest command without running it.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        action = str(args.action or '').strip().lower()
        if action not in _ACTIONS:
            raise AIVMError(
                f'invalid action {action!r}; expected one of {", ".join(_ACTIONS)}'
            )

        cfg = load_cfg(args.config, vm_opt=str(args.vm or ''))
        vm_name = cfg.vm.name
        threshold = int(args.threshold or 0) or int(
            cfg.virtiofs.fd_guard_threshold
        )
        interval_sec = int(args.interval_sec or 0) or int(
            cfg.virtiofs.fd_guard_interval_sec
        )
        if action == 'install':
            try:
                script = fdguard_install_script(
                    threshold=threshold, interval_sec=interval_sec
                )
            except ValueError as ex:
                raise AIVMError(str(ex)) from ex
        elif action == 'uninstall':
            script = fdguard_uninstall_script()
        else:
            script = fdguard_status_script()

        # Quote the guest script so the remote login shell hands it to
        # `sh -c` as one argument and `set -eu` failure semantics hold.
        remote_command = f'sh -c {shlex.quote(script)}'
        if args.dry_run:
            print(f'DRYRUN: would run fdguard {action} for VM {vm_name}')
            print('Guest script:')
            print(script)
            print('SSH shape:')
            print(f'ssh <ssh-options> {cfg.vm.user}@<vm-ip> {remote_command}')
            return 0

        intent_why = {
            'status': 'Inspect the guest-side virtiofs fd guard state.',
            'install': (
                'Install the guest-side virtiofs fd guard so the guest '
                'sheds cached virtiofs inodes before host virtiofsd '
                'exhausts its file-descriptor limit (EMFILE).'
            ),
            'uninstall': 'Remove the guest-side virtiofs fd guard.',
        }[action]
        mgr = CommandManager.current()
        with mgr.intent(
            f'Virtiofs fd guard {action} for {vm_name}',
            why=intent_why,
            role='read' if action == 'status' else 'modify',
        ):
            ip = _resolve_ip_for_ssh_ops(
                cfg,
                yes=bool(args.yes),
                purpose='Resolve VM networking before managing the fd guard.',
            )
            ident = require_ssh_identity(cfg.paths.ssh_identity_file)
            cmd = [
                'ssh',
                *ssh_base_args(
                    ident,
                    strict_host_key_checking='accept-new',
                    connect_timeout=10,
                    batch_mode=True,
                ),
                f'{cfg.vm.user}@{ip}',
                remote_command,
            ]
            log.debug('Running fdguard {} command: {}', action, shell_join(cmd))
            res = mgr.run(
                cmd,
                sudo=False,
                check=False,
                capture=True,
                timeout=int(args.timeout or 60),
                summary=f'Virtiofs fd guard {action} in VM {vm_name}',
                detail=(
                    'Manages the aivm-virtiofs-guard systemd timer inside '
                    'the guest via sudo -n.'
                ),
            )

        if res.stdout:
            print(res.stdout, end='' if res.stdout.endswith('\n') else '\n')
        if res.stderr:
            print(res.stderr, end='' if res.stderr.endswith('\n') else '\n')
        if res.code != 0:
            print(
                f'Virtiofs fd guard {action} failed for {vm_name} (exit code '
                f'{res.code}). The guest user may lack passwordless sudo, or '
                'SSH may be unavailable.'
            )
            return int(res.code) if res.code else 1
        if action == 'install':
            print(
                f'Installed virtiofs fd guard in {vm_name} '
                f'(threshold={threshold}, interval={interval_sec}s). '
                'Host-side periodic `aivm vm flush_caches` jobs are no '
                'longer needed for this VM.'
            )
        return 0


__all__ = [
    'VMFdGuardCLI',
]
