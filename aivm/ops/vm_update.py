"""High-level VM update operation used by the CLI."""

from __future__ import annotations

from dataclasses import dataclass

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..vm.update_ops import (
    RestartKind,
    _apply_vm_update,
    _maybe_restart_vm_after_update,
    _print_vm_update_plan,
    _vm_update_drift,
)


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
