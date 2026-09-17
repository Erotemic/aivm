"""Frozen released-store fixtures for the 0.6 scope migration."""

from __future__ import annotations

from pathlib import Path

from aivm.config_store import load_store, save_store

FIXTURE_ROOT = Path(__file__).parent / 'data' / 'released_v0_5'


def _copy_fixture_layout(tmp_path: Path, layout: str) -> Path:
    source = FIXTURE_ROOT / layout
    target = tmp_path / layout
    for source_file in source.rglob('*'):
        if not source_file.is_file():
            continue
        relative = source_file.relative_to(source)
        target_file = target / relative
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(source_file.read_bytes())
    return target / 'config.toml'


def test_released_monolithic_and_split_fixtures_are_equivalent(
    tmp_path: Path,
) -> None:
    monolithic_path = _copy_fixture_layout(tmp_path, 'monolithic')
    split_path = _copy_fixture_layout(tmp_path, 'split')

    monolithic = load_store(monolithic_path)
    split = load_store(split_path)

    assert monolithic.schema_version == 8
    assert split.schema_version == 8
    assert monolithic == split
    assert monolithic.active_vm == 'aivm-2404-fixture-host'
    assert monolithic.vms[0].cfg.vm.user == 'alice-agent'
    assert monolithic.attachments[0].guest_dst == (
        '/home/alice-agent/code/project'
    )


def test_released_fixture_roundtrip_does_not_require_real_user_state(
    tmp_path: Path,
) -> None:
    source = _copy_fixture_layout(tmp_path, 'monolithic')
    loaded = load_store(source)
    target = tmp_path / 'roundtrip' / 'config.toml'

    save_store(loaded, target)
    reloaded = load_store(target)

    assert reloaded == loaded
    assert target.is_file()
