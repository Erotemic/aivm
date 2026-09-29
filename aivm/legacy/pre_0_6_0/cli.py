"""Planning and execution commands for released-store migration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import kwconf

from ...cli._common import _BaseCommand
from ...commands import CommandManager
from ...errors import AIVMError
from ...machine_store import machine_store_layout
from .migration import (
    LegacyStoreSource,
    build_migration_plan,
    default_legacy_source,
    parse_legacy_source_spec,
)
from .migration_apply import (
    MigrationExecutionError,
    apply_migration,
    latest_migration_id,
    list_migration_ids,
    load_migration_journal,
    resume_migration,
    rollback_migration,
    verify_applied_migration,
)
from .paths import store_path as legacy_store_path


def _resolve_sources(
    raw_sources: list[str], config_opt: str | None
) -> list[LegacyStoreSource]:
    if raw_sources and config_opt:
        raise AIVMError(
            'Use positional [HOST_USER=]PATH sources or --config, not both.'
        )
    if raw_sources:
        try:
            return [parse_legacy_source_spec(item) for item in raw_sources]
        except ValueError as ex:
            raise AIVMError(str(ex)) from ex
    selected = Path(config_opt) if config_opt else legacy_store_path()
    return [default_legacy_source(selected)]


def _selected_migration_id(raw: str) -> str:
    return str(raw or '').strip() or latest_migration_id()


class _MigrationSourcesCLI(_BaseCommand):
    """Shared source and report options for plan/apply commands."""

    __special_options__ = False

    sources: list[str] = kwconf.Value(
        [],
        position=1,
        nargs='*',
        help=(
            'Released stores as [HOST_USER=]PATH. With no source, use the '
            'current user store (or --config path).'
        ),
    )
    output: Literal['text', 'json'] = kwconf.Value(
        'text',
        help='Report format: text or json.',
    )


class ConfigMigratePlanCLI(_MigrationSourcesCLI):
    """Plan migration of released per-user stores without changing state."""

    no_runtime: bool = kwconf.Flag(
        False,
        help='Skip read-only libvirt domain/network inventory.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        sources = _resolve_sources(list(args.sources or []), args.config)
        plan = build_migration_plan(
            sources,
            check_runtime=not args.no_runtime,
        )
        if args.output == 'json':
            print(plan.render_json(), end='')
        else:
            print(plan.render_text(), end='')
        return 2 if plan.blocked else 0


class ConfigMigrateApplyCLI(_MigrationSourcesCLI):
    """Back up, apply, verify, or resume one reviewed migration plan."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        sources = _resolve_sources(list(args.sources or []), args.config)
        plan = build_migration_plan(
            sources,
            check_runtime=True,
        )
        if plan.blocked:
            print(
                plan.render_json()
                if args.output == 'json'
                else plan.render_text(),
                end='',
            )
            return 2
        purpose = (
            'Migrate released AIVM stores into the shared machine store. '
            'This creates verified backups, writes machine/profile state, '
            'copies credential and persistent data, and installs the restricted '
            'guest enrollment helper. Legacy inputs remain retained for rollback.'
        )
        try:
            with CommandManager.current().approved_action(
                purpose=purpose,
                yes=args.yes,
            ):
                result = apply_migration(plan)
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(
                json.dumps(result.journal.to_dict(), indent=2, sort_keys=True)
            )
        else:
            prefix = 'Resumed' if result.resumed else 'Completed'
            print(f'{prefix} migration {result.journal.migration_id}.')
            print(result.journal.render_text(), end='')
        return 0


class _MigrationJournalCLI(_BaseCommand):
    """Shared selection and output options for journal operations."""

    __special_options__ = False

    migration: str = kwconf.Value(
        '',
        position=1,
        help='Migration id. Defaults to the newest local journal.',
    )
    output: Literal['text', 'json'] = kwconf.Value(
        'text',
        help='Report format: text or json.',
    )


class ConfigMigrateStatusCLI(_MigrationJournalCLI):
    """Show durable migration phase and verification state."""

    all: bool = kwconf.Flag(
        False,
        help='List every migration journal instead of only the selected/latest one.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.all:
            ids = list_migration_ids()
            if args.output == 'json':
                print(json.dumps({'migrations': ids}, indent=2, sort_keys=True))
            else:
                for item in ids:
                    print(item)
            return 0
        migration_id = _selected_migration_id(args.migration)
        result = load_migration_journal(migration_id)
        if args.output == 'json':
            print(
                json.dumps(result.journal.to_dict(), indent=2, sort_keys=True)
            )
        else:
            print(result.journal.render_text(), end='')
        return 0


class ConfigMigrateResumeCLI(_MigrationJournalCLI):
    """Resume a failed/interrupted migration from its durable journal."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        migration_id = _selected_migration_id(args.migration)
        layout = machine_store_layout()
        try:
            with CommandManager.current().approved_action(
                purpose=f'Resume migration {migration_id} from its next incomplete phase.',
                yes=args.yes,
            ):
                result = resume_migration(
                    migration_id,
                    layout=layout,
                    check_runtime=True,
                )
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(
                json.dumps(result.journal.to_dict(), indent=2, sort_keys=True)
            )
        else:
            print(result.journal.render_text(), end='')
        return 0


class ConfigMigrateVerifyCLI(_MigrationJournalCLI):
    """Re-run source, store, profile, data-copy, libvirt, and SSH checks."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        migration_id = _selected_migration_id(args.migration)
        try:
            result = verify_applied_migration(migration_id)
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(
                json.dumps(result.journal.to_dict(), indent=2, sort_keys=True)
            )
        else:
            print(result.journal.render_text(), end='')
        return 0


class ConfigMigrateRollbackCLI(_MigrationJournalCLI):
    """Restore all backed-up paths from one migration journal."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        migration_id = _selected_migration_id(args.migration)
        try:
            with CommandManager.current().approved_action(
                purpose=(
                    f'Roll back migration {migration_id}. Migrated machine/profile '
                    'files and copied state will be replaced by their verified backups.'
                ),
                yes=args.yes,
            ):
                result = rollback_migration(migration_id)
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(
                json.dumps(result.journal.to_dict(), indent=2, sort_keys=True)
            )
        else:
            print(result.journal.render_text(), end='')
        return 0


class ConfigMigrateModalCLI(kwconf.ModalCLI):
    """Released-installation migration commands."""

    plan = ConfigMigratePlanCLI
    apply = ConfigMigrateApplyCLI
    resume = ConfigMigrateResumeCLI
    status = ConfigMigrateStatusCLI
    verify = ConfigMigrateVerifyCLI
    rollback = ConfigMigrateRollbackCLI


__all__ = [
    'ConfigMigrateApplyCLI',
    'ConfigMigrateModalCLI',
    'ConfigMigratePlanCLI',
    'ConfigMigrateResumeCLI',
    'ConfigMigrateRollbackCLI',
    'ConfigMigrateStatusCLI',
    'ConfigMigrateVerifyCLI',
]
