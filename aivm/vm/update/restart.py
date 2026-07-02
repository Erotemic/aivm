"""Restart handling for VM update operations."""

from __future__ import annotations

import sys

from ...commands import CommandManager
from ...privilege import virsh_needs_sudo
from ...config import AgentVMConfig
from ...runtime import virsh_cmd
from .models import RestartKind


def _maybe_restart_vm_after_update(
    cfg: AgentVMConfig,
    *,
    kind: RestartKind,
    restart_policy: str,
    dry_run: bool,
    yes: bool,
) -> None:
    """Restart the VM if needed, picking the right command for the drift kind.

    ``kind`` comes from ``_apply_vm_update``. For NONE this is a no-op.
    SOFT does a guest-OS reboot (``virsh reboot``). HARD does a full
    power cycle via the existing ``restart_vm`` helper, which handles
    the ACPI shutdown, polling for ``shut off``, and ``virsh start``
    (including pmsuspended corner cases).
    """
    if kind == RestartKind.NONE:
        return

    label = {
        RestartKind.SOFT: 'guest reboot',
        RestartKind.HARD: 'full power cycle (shutdown + start)',
    }[kind]

    should_restart = False
    if restart_policy == 'always':
        should_restart = True
    elif restart_policy == 'never':
        should_restart = False
    elif yes:
        should_restart = True
    elif sys.stdin.isatty():
        ans = (
            input(
                f'A {label} is needed for the applied changes to take '
                f'effect now. Restart VM now? [y/N]: '
            )
            .strip()
            .lower()
        )
        should_restart = ans in {'y', 'yes'}

    if not should_restart:
        print(
            f'Updates saved, but VM {cfg.vm.name} needs a {label} for them '
            f'to take effect.'
        )
        return

    if kind == RestartKind.SOFT:
        cmd = virsh_cmd('reboot', cfg.vm.name)
        if dry_run:
            print(f'DRYRUN: {" ".join(cmd)}')
        else:
            CommandManager.current().run(
                cmd, sudo=virsh_needs_sudo(), check=True, capture=True
            )
            print(f'Rebooted VM {cfg.vm.name}.')
        return

    # HARD: shutdown + start. Local import keeps this module decoupled from
    # the full lifecycle import chain at module load.
    from ..lifecycle import restart_vm

    if dry_run:
        print(
            f'DRYRUN: virsh shutdown {cfg.vm.name} (wait for off) && virsh '
            f'start {cfg.vm.name}'
        )
        return
    restart_vm(cfg, dry_run=False)
    print(f'Power-cycled VM {cfg.vm.name}.')
