"""Explicit recovery behavior for persistent source identity pins."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.attachments.persistent.identity import (
    _refresh_in_store,
    refresh_persistent_source_identities,
)
from aivm.config_store import AttachmentEntry, Store, load_store, save_store
from aivm.fs_identity import FilesystemIdentity, directory_identity
from tests.helpers import make_cfg, write_store


def _stale_persistent_record(source: Path, *, vm_name: str) -> AttachmentEntry:
    source.mkdir(parents=True)
    identity = directory_identity(source)
    return AttachmentEntry(
        host_path=str(source.resolve()),
        vm_name=vm_name,
        mode='persistent',
        guest_dst='/workspace/source',
        tag='hostcode-source',
        source_dev=identity.dev + 1,
        source_ino=identity.ino,
    )


def test_trust_current_paths_refreshes_identity_at_saved_path(
    tmp_path: Path,
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'test-vm'})
    cfg_path = write_store(tmp_path / 'config.toml', cfg)
    source = tmp_path / 'source'
    reg = load_store(cfg_path)
    reg.attachments.append(
        _stale_persistent_record(source, vm_name=cfg.vm.name)
    )
    save_store(reg, cfg_path)

    report = refresh_persistent_source_identities(
        cfg,
        cfg_path,
        current_principal_id='',
        administrative_override=False,
        dry_run=False,
    )

    assert report.refreshed == (str(source.resolve()),)
    refreshed = load_store(cfg_path).attachments[0]
    identity = directory_identity(source)
    assert (refreshed.source_dev, refreshed.source_ino) == (
        identity.dev,
        identity.ino,
    )


def test_trust_current_paths_dry_run_does_not_mutate_store(
    tmp_path: Path,
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'test-vm'})
    cfg_path = write_store(tmp_path / 'config.toml', cfg)
    source = tmp_path / 'source'
    stale = _stale_persistent_record(source, vm_name=cfg.vm.name)
    reg = load_store(cfg_path)
    reg.attachments.append(stale)
    save_store(reg, cfg_path)

    report = refresh_persistent_source_identities(
        cfg,
        cfg_path,
        current_principal_id='',
        administrative_override=False,
        dry_run=True,
    )

    assert report.refreshed == (str(source.resolve()),)
    after = load_store(cfg_path).attachments[0]
    assert (after.source_dev, after.source_ino) == (
        stale.source_dev,
        stale.source_ino,
    )


def test_trust_current_paths_skips_missing_source_and_refreshes_others(
    tmp_path: Path,
) -> None:
    cfg = make_cfg(tmp_path, **{'vm.name': 'test-vm'})
    cfg_path = write_store(tmp_path / 'config.toml', cfg)
    good = tmp_path / 'good'
    missing = tmp_path / 'missing'
    reg = load_store(cfg_path)
    reg.attachments.extend(
        [
            _stale_persistent_record(good, vm_name=cfg.vm.name),
            AttachmentEntry(
                host_path=str(missing.resolve()),
                vm_name=cfg.vm.name,
                mode='persistent',
                guest_dst='/workspace/missing',
                tag='hostcode-missing',
                source_dev=1,
                source_ino=1,
            ),
        ]
    )
    save_store(reg, cfg_path)

    report = refresh_persistent_source_identities(
        cfg,
        cfg_path,
        current_principal_id='',
        administrative_override=False,
        dry_run=False,
    )

    assert report.refreshed == (str(good.resolve()),)
    assert report.unavailable and report.unavailable[0][0] == str(
        missing.resolve()
    )


def test_admin_refresh_can_use_privileged_descriptor_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / 'private-source'
    source.mkdir()
    reg = Store()
    reg.attachments.append(
        AttachmentEntry(
            host_path=str(source.resolve()),
            vm_name='test-vm',
            mode='persistent',
            guest_dst='/workspace/private-source',
            tag='hostcode-private-source',
            owner_principal_id='principal-other',
            source_dev=1,
            source_ino=2,
        )
    )
    monkeypatch.setattr(
        'aivm.attachments.persistent.identity.directory_identity',
        lambda _path: (_ for _ in ()).throw(PermissionError('private home')),
    )
    probed: list[Path] = []

    def privileged_probe(path: Path) -> FilesystemIdentity:
        probed.append(path)
        return FilesystemIdentity(dev=9, ino=10)

    report = _refresh_in_store(
        reg,
        vm_name='test-vm',
        current_principal_id='principal-current',
        administrative_override=True,
        privileged_probe=privileged_probe,
    )

    assert probed == [source.resolve()]
    assert report.refreshed == (str(source.resolve()),)
    assert (reg.attachments[0].source_dev, reg.attachments[0].source_ino) == (
        9,
        10,
    )
