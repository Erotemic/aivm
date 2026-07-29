"""``aivm config edit`` — open a config fragment in $EDITOR."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import kwconf

from ...config_store import load_config_document, require_vm
from ...errors import AIVMError
from ...profile_store import UserProfileStore, save_user_profile
from ...scoped_store import (
    load_scope_profile,
    load_scope_store,
    resolve_store_scope,
    save_scope_store,
)
from .._common import _BaseCommand
from .editor import edit_path, select_editor_command
from .paths import _role_source, _vm_config_source


class ConfigEditCLI(_BaseCommand):
    """Edit a config fragment in $EDITOR.

    Targets:
      global/root/base/config  -> config.toml
      profile                  -> the caller's private profile.toml
      defaults                 -> defaults.toml when formatted
      networks                 -> networks.toml when formatted
      vm [NAME]                -> the named VM fragment, defaulting to active_vm
      NAME                     -> shorthand for `vm NAME` when NAME is a VM
    """

    target: str = kwconf.Value(
        'global',
        help=(
            'Edit target: global, profile, defaults, networks, vm, '
            'active-vm, or VM name.'
        ),
        position=1,
    )
    name: str = kwconf.Value(
        '',
        help=(
            'Optional name for targets that need one, e.g. '
            '`vm aivm-2404-workstation`.'
        ),
        position=2,
    )
    editor: str = kwconf.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )
    visual: bool = kwconf.Flag(
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
        scope = resolve_store_scope(args.config)
        if scope.profile_path is not None and path == scope.profile_path:
            if not path.exists():
                save_user_profile(UserProfileStore(), path)
        elif path == scope.store_path and not path.exists():
            reg = load_scope_store(scope)
            save_scope_store(
                scope,
                reg,
                reason='Create config document before editing.',
            )
        _edit_path(path, args)
        return 0


def _editor_command(args: Any) -> list[str]:
    """Return the editor command prefix selected by CLI args/environment."""
    command = select_editor_command(
        editor=str(args.editor or ''),
        prefer_visual=bool(args.visual),
        fallbacks=('nano', 'vi'),
        required=True,
    )
    assert command is not None
    return command


def _edit_path(path: Path, args: Any) -> None:
    """Open a config path in the selected editor."""
    edit_path(path, _editor_command(args))


def _resolve_config_edit_target(
    *, config_opt: str | None, target: str, name: str = ''
) -> Path:
    """Resolve a user-facing config edit target to a physical file."""
    scope = resolve_store_scope(config_opt)
    root = scope.store_path
    loaded = load_config_document(root)
    profile = load_scope_profile(scope) if scope.is_machine else None
    cfg_dir = root.parent
    target_norm = (target or 'global').strip().lower().replace('_', '-')
    name = str(name or '').strip()

    if target_norm in {'global', 'root', 'base', 'config', ''}:
        return root

    if target_norm in {'profile', 'user', 'preferences'}:
        if scope.profile_path is None:
            raise AIVMError(
                'Legacy stores do not have a separate user profile.'
            )
        return scope.profile_path

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
        active_vm = (
            profile.active_vm if profile is not None else loaded.store.active_vm
        )
        vm_name = name or active_vm
    else:
        # Convenience: a bare managed VM name selects its fragment.
        vm_name = target

    if not vm_name:
        raise AIVMError('No VM specified and active_vm is unset.')
    require_vm(loaded.store, vm_name)
    return _vm_config_source(root, loaded, vm_name)
