"""``aivm config show`` and ``aivm config format``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import kwconf

from ...config import dump_toml
from ...config_store import (
    format_existing_config,
    load_config_document,
    save_store,
)
from .._common import _BaseCommand, _cfg_path, _load_cfg_with_path


class ConfigShowCLI(_BaseCommand):
    """Show AIVM config content.

    By default this prints the canonical source document.  For split layouts,
    that source document is the deterministic concatenation of config.toml,
    defaults.toml, networks.toml, and sorted vms/*.toml fragments.
    """

    vm = kwconf.Value(
        '',
        help='Optional VM name override for --resolved output.',
        position=1,
    )
    resolved = kwconf.Flag(
        False,
        help='Show effective VM config after defaults/network resolution.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        vm_name = str(args.vm or '').strip()
        if bool(args.resolved) or vm_name:
            cfg, cfg_path = _load_cfg_with_path(
                args.config, vm_opt=vm_name, host_src=Path.cwd()
            )
            toml_text = '\n'.join(
                [
                    f'# Store: {cfg_path}',
                    f'# VM: {cfg.vm.name}',
                    dump_toml(cfg),
                ]
            )
        else:
            loaded = load_config_document(path)
            if loaded.sources:
                toml_text = loaded.source_text
            else:
                store = loaded.store
                save_store(store, path)
                loaded = load_config_document(path)
                toml_text = loaded.source_text or path.read_text(
                    encoding='utf-8'
                )
        import ubelt as ub

        text = ub.highlight_code(toml_text, lexer_name='toml')
        print(text, end='')
        return 0


class ConfigFormatCLI(_BaseCommand):
    """Format config into the canonical split-file layout."""

    dry_run = kwconf.Flag(
        False,
        help='Show the files that would be written without modifying them.',
    )
    force = kwconf.Flag(
        False,
        help='Rewrite existing formatted fragments from the loaded logical document.',
    )
    no_backup = kwconf.Flag(
        False,
        help='Do not make a config.toml.bak backup before rewriting config.toml.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        targets = format_existing_config(
            path,
            backup=not bool(args.no_backup),
            dry_run=bool(args.dry_run),
            force=bool(args.force),
        )
        if args.dry_run:
            print('Would write formatted config paths:')
        else:
            print('Wrote formatted config paths:')
        for fpath in targets:
            print(f'  {fpath}')
        if not args.dry_run:
            print('Validate with: aivm config paths && aivm config show')
        return 0
