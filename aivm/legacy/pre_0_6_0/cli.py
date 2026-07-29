"""Planning and execution commands for released-store migration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import kwconf

from ...commands import CommandManager
from .paths import store_path as legacy_store_path
from ...errors import AIVMError
from ...machine_store import MachineStoreLayout, machine_store_layout
from .migration import (
    LegacyStoreSource,
    MigrationPlan,
    build_migration_plan,
    default_legacy_source,
    parse_legacy_source_spec,
)
from .migration_apply import (
    MigrationExecutionError,
    RuntimeVerifier,
    apply_migration,
    latest_migration_id,
    list_migration_ids,
    load_migration_journal,
    rebuild_plan_from_journal,
    rollback_migration,
    verify_applied_migration,
    verify_migration_runtime,
)
from ...cli._common import _BaseCommand


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


def _runtime_verifier(*, sudo: bool) -> RuntimeVerifier:
    def verify(
        plan: MigrationPlan, layout: MachineStoreLayout
    ) -> dict[str, object]:
        return verify_migration_runtime(plan, layout, runtime_sudo=sudo)

    return verify


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
    sudo: bool = kwconf.Flag(
        False,
        help='Use sudo for read-only libvirt inventory and verification.',
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
            check_runtime=not bool(args.no_runtime),
            runtime_sudo=bool(args.sudo),
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
            runtime_sudo=bool(args.sudo),
        )
        if plan.blocked:
            print(plan.render_json() if args.output == 'json' else plan.render_text(), end='')
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
                yes=bool(args.yes),
            ):
                result = apply_migration(
                    plan,
                    runtime_verifier=_runtime_verifier(sudo=bool(args.sudo)),
                )
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(json.dumps(result.journal.to_dict(), indent=2, sort_keys=True))
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
            print(json.dumps(result.journal.to_dict(), indent=2, sort_keys=True))
        else:
            print(result.journal.render_text(), end='')
        return 0


class ConfigMigrateResumeCLI(_MigrationJournalCLI):
    """Resume a failed/interrupted migration from its durable journal."""

    sudo: bool = kwconf.Flag(
        False,
        help='Use sudo for read-only libvirt inventory and verification.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        migration_id = _selected_migration_id(args.migration)
        layout = machine_store_layout()
        loaded = load_migration_journal(migration_id, layout=layout)
        plan = rebuild_plan_from_journal(
            loaded.journal,
            layout=layout,
            check_runtime=True,
            runtime_sudo=bool(args.sudo),
        )
        try:
            with CommandManager.current().approved_action(
                purpose=f'Resume migration {migration_id} from its next incomplete phase.',
                yes=bool(args.yes),
            ):
                result = apply_migration(
                    plan,
                    layout=layout,
                    runtime_verifier=_runtime_verifier(sudo=bool(args.sudo)),
                )
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(json.dumps(result.journal.to_dict(), indent=2, sort_keys=True))
        else:
            print(result.journal.render_text(), end='')
        return 0


class ConfigMigrateVerifyCLI(_MigrationJournalCLI):
    """Re-run source, store, profile, data-copy, libvirt, and SSH checks."""

    sudo: bool = kwconf.Flag(
        False,
        help='Use sudo for read-only libvirt verification.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        migration_id = _selected_migration_id(args.migration)
        try:
            result = verify_applied_migration(
                migration_id,
                runtime_verifier=_runtime_verifier(sudo=bool(args.sudo)),
            )
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(json.dumps(result.journal.to_dict(), indent=2, sort_keys=True))
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
                yes=bool(args.yes),
            ):
                result = rollback_migration(migration_id)
        except MigrationExecutionError as ex:
            raise AIVMError(str(ex)) from ex
        if args.output == 'json':
            print(json.dumps(result.journal.to_dict(), indent=2, sort_keys=True))
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
