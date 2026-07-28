"""Read-only planning commands for released-store migration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import kwconf

from ...config_store.paths import store_path as legacy_store_path
from ...errors import AIVMError
from ...migration import (
    build_migration_plan,
    default_legacy_source,
    parse_legacy_source_spec,
)
from .._common import _BaseCommand


class ConfigMigratePlanCLI(_BaseCommand):
    """Plan migration of released per-user stores without changing state."""

    sources: list[str] = kwconf.Value(
        [],
        position=1,
        nargs='*',
        help=(
            'Released stores as [HOST_USER=]PATH. With no source, plan the '
            'current user store (or --config path).'
        ),
    )
    output: Literal['text', 'json'] = kwconf.Value(
        'text',
        help='Report format: text or json.',
    )
    no_runtime: bool = kwconf.Flag(
        False,
        help='Skip read-only libvirt domain/network inventory.',
    )
    sudo: bool = kwconf.Flag(
        False,
        help='Use sudo for the read-only libvirt inventory.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        raw_sources = list(args.sources or [])
        if raw_sources and args.config:
            raise AIVMError(
                'Use positional [HOST_USER=]PATH sources or --config, not both.'
            )
        if raw_sources:
            try:
                sources = [
                    parse_legacy_source_spec(item) for item in raw_sources
                ]
            except ValueError as ex:
                raise AIVMError(str(ex)) from ex
        else:
            selected = Path(args.config) if args.config else legacy_store_path()
            sources = [default_legacy_source(selected)]
        plan = build_migration_plan(
            sources,
            check_runtime=not bool(args.no_runtime),
            runtime_sudo=bool(args.sudo),
        )
        if args.output == 'json':
            print(plan.render_json(), end='')
        else:
            print(plan.render_text(), end='')
        return 2 if plan.blocked else 0


class ConfigMigrateModalCLI(kwconf.ModalCLI):
    """Released-installation migration commands."""

    plan = ConfigMigratePlanCLI


__all__ = ['ConfigMigrateModalCLI', 'ConfigMigratePlanCLI']
