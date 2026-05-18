"""VM update CLI command implementation."""

from __future__ import annotations

from typing import Any

import scriptconfig as scfg

from ..ops.vm_update import (
    VMUpdateRequest,
    normalize_restart_policy,
    run_vm_update,
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
