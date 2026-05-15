"""VM config-file helper CLI command implementations."""

from __future__ import annotations

from typing import Any

import scriptconfig as scfg

from ..store import load_config_document
from ._common import _BaseCommand, _cfg_path
from .config import _edit_path, _resolve_config_edit_target


class VMConfigPathCLI(_BaseCommand):
    """Show the physical config source for a managed VM."""

    vm: Any = scfg.Value('', help='VM name override.', position=1)

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg_path = _cfg_path(args.config)
        loaded = load_config_document(cfg_path)
        vm_name = str(args.vm or '').strip() or loaded.store.active_vm
        if not vm_name:
            raise RuntimeError('No VM specified and active_vm is unset.')
        src = loaded.vm_sources.get(vm_name)
        if src is None:
            rec_names = sorted(v.name for v in loaded.store.vms)
            if vm_name not in rec_names:
                raise RuntimeError(f'VM not found in config: {vm_name}')
            # Monolithic configs may not have per-source VM metadata when the
            # file was missing and defaulted.  Fall back to the root path.
            src = cfg_path
        print(src)
        return 0


class VMEditCLI(_BaseCommand):
    """Edit the active or named VM config fragment in $EDITOR."""

    vm: Any = scfg.Value('', help='VM name override.', position=1)
    editor: Any = scfg.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )
    visual: Any = scfg.Value(
        '',
        help='If true, then prefer $VISUAL over $EDITOR.',
        isflag=True,
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _resolve_config_edit_target(
            config_opt=args.config,
            target='vm',
            name=str(args.vm or ''),
        )
        _edit_path(path, args)
        return 0
