"""VM update CLI command implementation.

Owns both the scriptconfig CLI and the business logic — scriptconfig is
the programmatic entry point too, so no separate Request/Result layer
in a sibling ``ops/`` module is needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import scriptconfig as scfg

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..vm.update import (
    RestartKind,
    _apply_vm_update,
    _maybe_restart_vm_after_update,
    _print_vm_update_plan,
    _vm_update_drift,
)
from ._common import _BaseCommand, _load_cfg_with_path


@dataclass(frozen=True)
class VMUpdateRequest:
    """Inputs for the VM update operation after CLI parsing."""

    cfg: AgentVMConfig
    restart_policy: str = 'auto'
    dry_run: bool = False
    yes: bool = False


def normalize_restart_policy(value: object) -> str:
    """Normalize and validate a VM update restart policy."""
    restart_policy = str(value or 'auto').strip().lower()
    if restart_policy not in {'auto', 'always', 'never'}:
        raise RuntimeError('--restart must be one of: auto, always, never')
    return restart_policy


def run_vm_update(request: VMUpdateRequest) -> int:
    """Reconcile VM config drift against live libvirt settings."""
    cfg = request.cfg
    drift, vm_running = _vm_update_drift(cfg, yes=bool(request.yes))
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
            cfg, drift, dry_run=bool(request.dry_run)
        )
    if changed and restart_kind != RestartKind.NONE and vm_running:
        _maybe_restart_vm_after_update(
            cfg,
            kind=restart_kind,
            restart_policy=request.restart_policy,
            dry_run=bool(request.dry_run),
            yes=bool(request.yes),
        )
    elif changed:
        print('Update complete.')
    return 0


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
        restart_policy = normalize_restart_policy(args.restart)
        cfg, _ = _load_cfg_with_path(args.config, vm_opt=args.vm)
        return run_vm_update(
            VMUpdateRequest(
                cfg=cfg,
                restart_policy=restart_policy,
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        )
