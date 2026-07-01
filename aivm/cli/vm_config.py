"""VM config-file helper CLI command implementations."""

from __future__ import annotations

from typing import Any

import kwconf

from ._common import _BaseCommand
from .config.edit import _edit_path, _resolve_config_edit_target


class VMEditCLI(_BaseCommand):
    """Edit the active or named VM config fragment in $EDITOR."""

    vm: Any = kwconf.Value('', help='VM name override.', position=1)
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
            target='vm',
            name=str(args.vm or ''),
        )
        _edit_path(path, args)
        return 0
