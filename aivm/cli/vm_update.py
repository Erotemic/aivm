"""VM update CLI command implementation.

Owns both the kwconf CLI and the business logic — kwconf is
the programmatic entry point too, so no separate Request/Result layer
in a sibling ``ops/`` module is needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import kwconf

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..errors import AIVMError
from ..operational_scope import announce_vm_machine_impact
from ..services import load_cfg_with_path
from ..vm.tpm import TpmChoice
from ..vm.update import (
    RestartKind,
    _apply_vm_update,
    _maybe_restart_vm_after_update,
    _print_vm_update_plan,
    _vm_update_drift,
)
from ..vm.update.render import _preview_vm_update
from ._common import _BaseCommand


@dataclass(frozen=True)
class VMUpdateRequest:
    """Inputs for the VM update operation after CLI parsing."""

    cfg: AgentVMConfig
    restart_policy: str = 'auto'
    dry_run: bool = False
    yes: bool = False
    store_path: Path | None = None


def normalize_restart_policy(value: object) -> str:
    """Normalize and validate a VM update restart policy."""
    restart_policy = str(value or 'auto').strip().lower()
    if restart_policy not in {'auto', 'always', 'never'}:
        raise AIVMError('--restart must be one of: auto, always, never')
    return restart_policy


def run_vm_update(request: VMUpdateRequest) -> int:
    """Reconcile VM config drift against live host/libvirt state."""
    cfg = request.cfg
    if request.dry_run:
        # A dry run executes no probes, so it cannot compute live drift.
        _preview_vm_update(cfg)
        return 0
    drift, vm_running = _vm_update_drift(cfg, yes=request.yes)
    if drift.notes:
        print('Detected diagnostics (not auto-applied):')
        for note in drift.notes:
            print(f'  - {note}')
    if not drift.has_changes():
        print(f'VM {cfg.vm.name} is already in sync with config.')
        return 0
    if request.store_path is not None:
        announce_vm_machine_impact(
            request.store_path, cfg.vm.name, action='update configuration'
        )
    _print_vm_update_plan(cfg, drift)
    mgr = CommandManager.current()
    with mgr.intent(
        f'Update VM {cfg.vm.name}',
        why=(
            'Apply editable host and libvirt changes so the VM environment '
            'matches config.'
        ),
        role='modify',
    ):
        changed, restart_kind = _apply_vm_update(
            cfg, drift, dry_run=request.dry_run
        )
    if changed and restart_kind != RestartKind.NONE and vm_running:
        _maybe_restart_vm_after_update(
            cfg,
            kind=restart_kind,
            restart_policy=request.restart_policy,
            dry_run=request.dry_run,
            yes=request.yes,
        )
    elif changed:
        print('Update complete.')
    return 0


class VMUpdateCLI(_BaseCommand):
    """Reconcile VM config drift against live host/libvirt state."""

    vm: str = kwconf.Value('', help='Optional VM name override.')

    tpm: TpmChoice | None = kwconf.Value(
        None,
        help=('Reconcile the virtual TPM: emulator adds a software TPM 2.0 to '
              'a shut-off VM and persists the choice; an explicit none is '
              'rejected because TPM removal is not yet implemented.'),
    )
    restart: Literal['auto', 'always', 'never'] = kwconf.Value(
        'auto',
        help='Restart policy when changes require reboot to take effect: auto, always, never.',
    )
    dry_run: bool = kwconf.Flag(
        False, short_alias=['n'], help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.tpm == 'none':
            # The shared value set includes 'none', but this command only
            # adds: removal would have to delete libvirt's persistent TPM
            # state, which is not implemented. Fail before any store or
            # host access so a rejected request can never mutate or
            # persist anything.
            raise AIVMError(
                'aivm vm update --tpm none is not supported: removing an '
                'emulated TPM (and its persistent state) is not implemented '
                'yet. Omit --tpm to leave the existing device untouched, or '
                'pass --tpm emulator to add one.'
            )
        restart_policy = normalize_restart_policy(args.restart)
        cfg, store_path = load_cfg_with_path(args.config, vm_opt=args.vm)
        if args.tpm:
            cfg.vm.tpm = args.tpm
        result = run_vm_update(
            VMUpdateRequest(
                cfg=cfg,
                restart_policy=restart_policy,
                dry_run=args.dry_run,
                yes=args.yes,
                store_path=store_path,
            )
        )
        if args.tpm and not args.dry_run and result == 0:
            from ..vm.tpm import persist_tpm_choice
            persist_tpm_choice(cfg, store_path)
        return result
