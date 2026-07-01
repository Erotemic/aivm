"""``aivm config edit`` — open a config fragment in $EDITOR."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any

import kwconf

from ...commands import CommandManager
from ...config_store import (
    find_vm,
    load_config_document,
    load_store,
    save_store,
)
from ...util import which
from .._common import _BaseCommand, _cfg_path
from .paths import _role_source, _vm_config_source


class ConfigEditCLI(_BaseCommand):
    """Edit a config fragment in $EDITOR.

    Targets:
      global/root/base/config  -> config.toml
      defaults                 -> defaults.toml when formatted
      networks                 -> networks.toml when formatted
      vm [NAME]                -> the named VM fragment, defaulting to active_vm
      NAME                     -> shorthand for `vm NAME` when NAME is a VM
    """

    target: Any = kwconf.Value(
        'global',
        help='Edit target: global, defaults, networks, vm, active-vm, or VM name.',
        position=1,
    )
    name: Any = kwconf.Value(
        '',
        help='Optional name for targets that need one, e.g. `vm aivm-2404`.',
        position=2,
    )
    editor: Any = kwconf.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )
    visual: Any = kwconf.Flag(
        False,
        help='If true, then prefer $VISUAL over $EDITOR.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _resolve_config_edit_target(
            config_opt=args.config,
            target=str(args.target or 'global'),
            name=str(args.name or ''),
        )
        if path == _cfg_path(args.config) and not path.exists():
            reg = load_store(path)
            save_store(reg, path)
        _edit_path(path, args)
        return 0


def _editor_command(args: Any) -> list[str]:
    """Return the editor command prefix selected by CLI args/environment."""
    order = ['VISUAL', 'EDITOR'] if args.visual else ['EDITOR', 'VISUAL']
    candidates = [
        str(args.editor or '').strip(),
        *(os.environ.get(key, '') for key in order),
    ]
    editor_cmd = next((x for x in candidates if x), '')
    if not editor_cmd:
        editor_cmd = which('nano') or which('vi') or ''
    if not editor_cmd:
        raise RuntimeError('No editor found. Set $EDITOR or pass --editor.')
    return shlex.split(editor_cmd)


def _edit_path(path: Path, args: Any) -> None:
    """Open a config path in the selected editor."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text('', encoding='utf-8')
    parts = _editor_command(args) + [str(path)]
    CommandManager.current().run(
        parts, sudo=False, check=True, capture=False
    )


def _resolve_config_edit_target(
    *, config_opt: str, target: str, name: str = ''
) -> Path:
    """Resolve a user-facing config edit target to a physical file."""
    root = _cfg_path(config_opt)
    loaded = load_config_document(root)
    cfg_dir = root.parent
    target_norm = (target or 'global').strip().lower().replace('_', '-')
    name = str(name or '').strip()

    if target_norm in {'global', 'root', 'base', 'config', ''}:
        return root

    if target_norm in {'defaults', 'default'}:
        src = _role_source(loaded, 'defaults')
        if src is not None:
            return src
        return cfg_dir / 'defaults.toml' if loaded.layout == 'split' else root

    if target_norm in {'networks', 'network', 'net'}:
        src = _role_source(loaded, 'networks')
        if src is not None:
            return src
        return cfg_dir / 'networks.toml' if loaded.layout == 'split' else root

    if target_norm in {'vm', 'vms', 'active-vm', 'active'}:
        vm_name = name or loaded.store.active_vm
    else:
        # Convenience: `aivm config edit aivm-2404` means that VM if it exists.
        vm_name = target

    if not vm_name:
        raise RuntimeError('No VM specified and active_vm is unset.')
    if find_vm(loaded.store, vm_name) is None:
        raise RuntimeError(f'VM not found in config: {vm_name}')
    return _vm_config_source(root, loaded, vm_name)
