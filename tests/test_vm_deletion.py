"""Durable VM-deletion journal and recovery tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import (
    Store,
    find_vm,
    load_store,
    save_store,
    upsert_attachment,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.errors import AIVMError
from aivm.profile_store import UserProfileStore, load_user_profile, save_user_profile
from aivm.scoped_store import resolve_store_scope
from aivm.vm.deletion import _journal_path, delete_managed_vm
from aivm.vm.domain import DomainRemovalReport


def _machine_vm(tmp_path: Path):
    scope = resolve_store_scope(None)
    assert scope.is_machine
    cfg = AgentVMConfig()
    cfg.vm.name = 'delete-me'
    cfg.paths.base_dir = str(tmp_path / 'libvirt')
    cfg.paths.state_dir = str(tmp_path / 'user-state')
    reg = Store(store_kind='machine', schema_version=11)
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    source = tmp_path / 'source'
    source.mkdir()
    upsert_attachment(
        reg,
        host_path=source,
        vm_name=cfg.vm.name,
        mode='persistent',
        guest_dst='/workspace/source',
        tag='source',
    )
    save_store(reg, scope.store_path)
    assert scope.profile_path is not None
    save_user_profile(
        UserProfileStore(active_vm=cfg.vm.name), scope.profile_path
    )
    return scope, cfg, scope.store_path


def _stub_external_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    cfg: AgentVMConfig,
    calls: list[str],
) -> dict[str, bool]:
    disk = Path(cfg.paths.base_dir) / cfg.vm.name / 'images' / f'{cfg.vm.name}.qcow2'
    domain_state = {'defined': True}
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined',
        lambda name: domain_state['defined'],
    )
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_file_storage_paths', lambda name: (disk,)
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts',
        lambda *a, **k: calls.append('attachments'),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion.discard_released_credential_material',
        lambda *a, **k: calls.append('credentials'),
    )
    def remove_domain(*args: object, **kwargs: object) -> DomainRemovalReport:
        calls.append('domain')
        domain_state['defined'] = False
        return DomainRemovalReport((disk,), ())

    monkeypatch.setattr(
        'aivm.vm.deletion._destroy_and_undefine_vm', remove_domain
    )
    monkeypatch.setattr('aivm.vm.deletion._path_exists', lambda path: False)
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_owned_trees',
        lambda *a, **k: calls.append('trees'),
    )
    return domain_state


def test_vm_deletion_journal_finishes_store_last(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)

    journal = delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert journal is not None and journal.status == 'complete'
    assert calls == ['attachments', 'credentials', 'domain', 'trees']
    assert find_vm(load_store(cfg_path), cfg.vm.name) is None
    assert scope.profile_path is not None
    assert load_user_profile(scope.profile_path).active_vm == ''
    persisted = _journal_path(scope, cfg).read_text(encoding='utf-8')
    assert '"status": "complete"' in persisted
    assert '"store-finalized"' in persisted


def test_vm_deletion_retry_skips_completed_external_phases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    domain_state = _stub_external_cleanup(monkeypatch, cfg, calls)
    failures = 1

    def fail_domain(*args: object, **kwargs: object) -> DomainRemovalReport:
        nonlocal failures
        calls.append('domain')
        if failures:
            failures -= 1
            raise RuntimeError('simulated domain interruption')
        disk = Path(cfg.paths.base_dir) / cfg.vm.name / 'images' / f'{cfg.vm.name}.qcow2'
        domain_state['defined'] = False
        return DomainRemovalReport((disk,), ())

    monkeypatch.setattr(
        'aivm.vm.deletion._destroy_and_undefine_vm', fail_domain
    )
    with pytest.raises(RuntimeError, match='domain interruption'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None
    journal_text = _journal_path(scope, cfg).read_text(encoding='utf-8')
    assert '"attachments-cleaned"' in journal_text
    assert '"credentials-cleaned"' in journal_text
    assert 'simulated domain interruption' in journal_text

    journal = delete_managed_vm(scope, cfg, cfg_path, dry_run=False)
    assert journal is not None and journal.status == 'complete'
    assert calls.count('attachments') == 1
    assert calls.count('credentials') == 1
    assert calls.count('domain') == 2
    assert calls.count('trees') == 1


def test_vm_deletion_retains_journal_for_external_storage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    domain_state = _stub_external_cleanup(monkeypatch, cfg, calls)
    external = tmp_path / 'outside' / 'disk.qcow2'
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_file_storage_paths', lambda name: (external,)
    )
    with pytest.raises(AIVMError, match='outside its AIVM-managed tree'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert domain_state['defined'] is True
    assert calls == []
    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None
    journal_text = _journal_path(scope, cfg).read_text(encoding='utf-8')
    assert str(external) in journal_text
    assert 'outside its AIVM-managed tree' in journal_text
    assert 'Refusing deletion before changing' in journal_text


def test_vm_deletion_retries_final_store_save_without_repeating_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    from aivm.vm import deletion as module

    real_save = module.save_store
    failures = 1

    def fail_final(reg: Store, path: Path, *, reason: str = '') -> None:
        nonlocal failures
        if 'Finalize journaled deletion' in reason and failures:
            failures -= 1
            raise OSError('simulated final store save failure')
        real_save(reg, path, reason=reason)

    monkeypatch.setattr(module, 'save_store', fail_final)
    with pytest.raises(OSError, match='final store save failure'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    journal = delete_managed_vm(scope, cfg, cfg_path, dry_run=False)
    assert journal is not None and journal.status == 'complete'
    assert calls == ['attachments', 'credentials', 'domain', 'trees']
    assert find_vm(load_store(cfg_path), cfg.vm.name) is None


def test_vm_deletion_recovers_crash_after_final_store_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A missing VM plus a complete cleanup journal closes the final-write window."""
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    from aivm.vm import deletion as module

    real_persist = module._persist_phase

    def crash_after_store_write(
        path: Path,
        journal: object,
        journal_scope: object,
        phase: str,
    ) -> None:
        if phase == 'store-finalized':
            raise OSError('simulated crash after final store write')
        real_persist(path, journal, journal_scope, phase)

    monkeypatch.setattr(module, '_persist_phase', crash_after_store_write)
    with pytest.raises(OSError, match='after final store write'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert find_vm(load_store(cfg_path), cfg.vm.name) is None
    journal = module.complete_missing_vm_deletion(
        scope, cfg_path, cfg.vm.name
    )
    assert journal is not None
    assert journal.status == 'complete'
    assert journal.completed('store-finalized')
    assert calls == ['attachments', 'credentials', 'domain', 'trees']


def test_vm_delete_cli_recovers_missing_record_from_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An explicit delete command resumes bookkeeping without VM materialization."""
    from aivm.cli.vm_lifecycle import VMDeleteCLI
    from aivm.vm import deletion as module

    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    real_persist = module._persist_phase

    def crash_after_store_write(
        path: Path,
        journal: object,
        journal_scope: object,
        phase: str,
    ) -> None:
        if phase == 'store-finalized':
            raise OSError('simulated crash after final store write')
        real_persist(path, journal, journal_scope, phase)

    monkeypatch.setattr(module, '_persist_phase', crash_after_store_write)
    with pytest.raises(OSError, match='after final store write'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    rc = VMDeleteCLI.main(
        argv=False,
        config=str(cfg_path),
        vm=cfg.vm.name,
        yes=True,
    )
    assert rc == 0
    journal = module._load_journal(_journal_path(scope, cfg))
    assert journal is not None and journal.status == 'complete'
