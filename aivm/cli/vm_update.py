"""VM update CLI command implementation."""

from __future__ import annotations

from typing import Any

import scriptconfig as scfg

from ..commands import CommandManager
from ..vm.update_ops import (
    RestartKind,
    _apply_vm_update,
    _maybe_restart_vm_after_update,
    _print_vm_update_plan,
    _vm_update_drift,
)
from ._common import _BaseCommand, _load_cfg_with_path


class VMUpdateCLI(_BaseCommand):
    """Reconcile VM config drift against live libvirt settings."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    restart: Any = scfg.Value(
        'auto',
        help='Restart policy when changes require reboot to take effect: auto, always, never.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        restart_policy = str(args.restart or 'auto').strip().lower()
        if restart_policy not in {'auto', 'always', 'never'}:
            raise RuntimeError('--restart must be one of: auto, always, never')
        cfg, _ = _load_cfg_with_path(args.config, vm_opt=args.vm)
        drift, vm_running = _vm_update_drift(cfg, yes=bool(args.yes))
        if drift.notes:
            print('Detected diagnostics (not auto-applied):')
            for note in drift.notes:
                print(f'  - {note}')
        if not drift.has_changes():
            print(f'VM {cfg.vm.name} is already in sync with config.')
            return 0
        _print_vm_update_plan(cfg, drift)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Update VM {cfg.vm.name}',
            why='Apply editable libvirt hardware changes so the VM matches config.',
            role='modify',
        ):
            changed, restart_kind = _apply_vm_update(
                cfg, drift, dry_run=bool(args.dry_run)
            )
        if changed and restart_kind != RestartKind.NONE and vm_running:
            _maybe_restart_vm_after_update(
                cfg,
                kind=restart_kind,
                restart_policy=restart_policy,
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
                rollback_virtiofs_binary=drift.virtiofs_binary,
            )
        elif changed:
            print('Update complete.')
        return 0
