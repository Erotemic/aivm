"""Static and runtime checks for the pre-0.6 compatibility quarantine."""

from __future__ import annotations

from pathlib import Path

from aivm.attachments.ownership import attachment_owner_for_context
from aivm.cli.config.lint import _lint_store_text
from aivm.config_store import Store, load_config_document, parse_store_toml
from aivm.config_store.render import render_store_toml
from aivm.legacy.pre_0_6_0 import compatibility_surface
from aivm.legacy.pre_0_6_0.context import (
    resolve_pre_0_6_0_vm_context,
)
from aivm.legacy.pre_0_6_0.migration import MigrationPlan
from aivm.legacy.pre_0_6_0.migration_apply import MigrationJournal
from aivm.scoped_store import resolve_store_scope

ROOT = Path(__file__).resolve().parents[3]
SUPPORT_TAG = 'pre_0_6_0'


def test_bulk_compatibility_lives_under_versioned_package() -> None:
    for obj in (MigrationPlan, MigrationJournal, resolve_pre_0_6_0_vm_context):
        module = str(obj.__module__)
        assert module.startswith('aivm.legacy.pre_0_6_0.')

    # Overlay application cannot delete old paths, so they remain as tiny
    # failure stubs rather than silently retaining duplicate implementations.
    for relative in ('aivm/migration.py', 'aivm/migration_apply.py'):
        lines = (ROOT / relative).read_text(encoding='utf-8').splitlines()
        assert len(lines) < 20
        assert 'aivm.legacy.pre_0_6_0' in '\n'.join(lines)


def test_mixed_surfaces_are_semantically_marked() -> None:
    marked = (
        Store,
        parse_store_toml,
        render_store_toml,
        load_config_document,
        resolve_store_scope,
        attachment_owner_for_context,
        _lint_store_text,
    )
    for obj in marked:
        assert getattr(obj, '__aivm_legacy_support__', None) == SUPPORT_TAG


def test_marker_preserves_identity_and_records_support_boundary() -> None:
    def sample() -> str:
        return 'ok'

    decorated = compatibility_surface(sample)
    assert decorated is sample
    assert decorated() == 'ok'
    assert getattr(decorated, '__aivm_legacy_support__', None) == SUPPORT_TAG


def test_no_unversioned_migration_or_context_imports_remain() -> None:
    forbidden = (
        'from aivm.migration',
        'from aivm.migration_apply',
        'import aivm.migration',
        'import aivm.migration_apply',
        'resolve_legacy_vm_context',
    )
    offenders: list[str] = []
    for path in (ROOT / 'aivm').rglob('*.py'):
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith('aivm/legacy/pre_0_6_0/'):
            continue
        text = path.read_text(encoding='utf-8')
        for token in forbidden:
            if token in text:
                offenders.append(f'{relative}: {token}')
    assert offenders == []


def test_pre_0_6_0_tests_live_under_versioned_folder() -> None:
    legacy_root = ROOT / 'tests' / 'legacy' / 'pre_0_6_0'
    offenders: list[str] = []
    for path in (ROOT / 'tests').rglob('test_*.py'):
        if path.is_relative_to(legacy_root):
            continue
        source = path.read_text(encoding='utf-8')
        if 'aivm.legacy.pre_0_6_0' in source:
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_released_fixtures_live_with_removable_legacy_tests() -> None:
    fixture_root = ROOT / 'tests' / 'legacy' / 'pre_0_6_0' / 'data'
    assert (fixture_root / 'released_v0_5').is_dir()
    assert not (ROOT / 'tests' / 'data' / 'released_v0_5').exists()


def test_canonical_runtime_does_not_construct_legacy_contexts() -> None:
    """Only the store-loading bridge may adapt a released aggregate config."""
    allowed = {'aivm/services.py'}
    offenders: list[str] = []
    for path in (ROOT / 'aivm').rglob('*.py'):
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith('aivm/legacy/pre_0_6_0/'):
            continue
        text = path.read_text(encoding='utf-8')
        if (
            'resolve_pre_0_6_0_vm_context' in text
            or 'legacy.pre_0_6_0.context' in text
        ) and relative not in allowed:
            offenders.append(relative)
    assert offenders == []
