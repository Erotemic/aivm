"""Durable VM-deletion journal and recovery tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.commands import CommandManager, CommandResult
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
from aivm.profile_store import (
    UserProfileStore,
    load_user_profile,
    save_user_profile,
)
from aivm.scoped_store import StoreScope, resolve_store_scope
from aivm.vm.deletion import (
    VMDeletionJournal,
    _assert_no_mounts_below,
    _cleanup_owned_trees,
    _journal_path,
    _load_journal,
    _new_journal,
    _save_journal,
    delete_managed_vm,
    require_vm_creation_not_blocked,
)
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
    disk = (
        Path(cfg.paths.base_dir)
        / cfg.vm.name
        / 'images'
        / f'{cfg.vm.name}.qcow2'
    )
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
        disk = (
            Path(cfg.paths.base_dir)
            / cfg.vm.name
            / 'images'
            / f'{cfg.vm.name}.qcow2'
        )
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


def test_vm_tree_cleanup_fails_closed_when_findmnt_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    vm_base = tmp_path / 'vm-base'
    machine_state = tmp_path / 'machine-state'
    bootstrap = tmp_path / 'bootstrap'
    for path in (vm_base, machine_state, bootstrap):
        path.mkdir()
        (path / 'keep.txt').write_text('keep\n', encoding='utf-8')
    commands: list[list[str]] = []

    def fake_run(
        self: CommandManager,
        cmd: list[str],
        **kwargs: object,
    ) -> CommandResult:
        del self, kwargs
        commands.append(list(cmd))
        if cmd and cmd[0] == 'findmnt':
            return CommandResult(2, '', 'findmnt inspection failed')
        if cmd[:3] == ['env', 'LC_ALL=C', 'stat']:
            return CommandResult(0, '', '')
        raise AssertionError(f'unexpected destructive command: {cmd!r}')

    monkeypatch.setattr(CommandManager, 'run', fake_run)
    journal = VMDeletionJournal(
        schema_version=1,
        vm_name='vm-findmnt-failure',
        config_path=str(tmp_path / 'config.toml'),
        storage_paths=[],
        vm_base_dir=str(vm_base),
        machine_state_dir=str(machine_state),
        bootstrap_dir=str(bootstrap),
    )

    with pytest.raises(AIVMError, match='Could not verify'):
        _cleanup_owned_trees(journal)

    assert all(cmd[0] != 'bash' for cmd in commands)
    for path in (vm_base, machine_state, bootstrap):
        assert (path / 'keep.txt').read_text(encoding='utf-8') == 'keep\n'


def test_vm_tree_cleanup_allows_confirmed_absent_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        self: CommandManager,
        cmd: list[str],
        **kwargs: object,
    ) -> CommandResult:
        del self, kwargs
        commands.append(list(cmd))
        if cmd and cmd[0] == 'findmnt':
            return CommandResult(1, '', '')
        if cmd[:3] == ['env', 'LC_ALL=C', 'stat']:
            return CommandResult(
                1,
                '',
                "stat: cannot statx '/missing': No such file or directory",
            )
        raise AssertionError(f'unexpected destructive command: {cmd!r}')

    monkeypatch.setattr(CommandManager, 'run', fake_run)
    _assert_no_mounts_below(tmp_path / 'missing')

    # The absent root is a no-op; no removal command is submitted.
    assert all(cmd[0] != 'bash' for cmd in commands)


def test_vm_tree_cleanup_detects_nested_mount(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / 'vm-base'
    nested = root / 'persistent-root' / 'tok-project'
    commands: list[list[str]] = []

    def fake_run(
        self: CommandManager,
        cmd: list[str],
        **kwargs: object,
    ) -> CommandResult:
        del self, kwargs
        commands.append(list(cmd))
        if cmd and cmd[0] == 'findmnt':
            # ``findmnt -R --list`` output: one absolute target per line,
            # including mounts elsewhere on the same filesystem.
            return CommandResult(0, f'/\n/boot\n{nested}\n', '')
        raise AssertionError(f'unexpected command: {cmd!r}')

    monkeypatch.setattr(CommandManager, 'run', fake_run)

    with pytest.raises(AIVMError, match='mounts remain beneath'):
        _assert_no_mounts_below(root)

    # The enumeration must ask for list output; the default tree rendering
    # prefixes targets with box-drawing glyphs the filter cannot match.
    findmnt_cmds = [cmd for cmd in commands if cmd[0] == 'findmnt']
    assert findmnt_cmds and all('--list' in cmd for cmd in findmnt_cmds)


def test_vm_tree_cleanup_fails_closed_on_tree_rendered_findmnt_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / 'vm-base'
    nested = root / 'persistent-root' / 'tok-project'

    def fake_run(
        self: CommandManager,
        cmd: list[str],
        **kwargs: object,
    ) -> CommandResult:
        del self, kwargs
        if cmd and cmd[0] == 'findmnt':
            # Tree-mode rendering (the historical inert-guard bug): the
            # nested mount is present but prefixed with box-drawing glyphs.
            return CommandResult(0, f'/\n├─/boot\n└─{nested}\n', '')
        raise AssertionError(f'unexpected command: {cmd!r}')

    monkeypatch.setattr(CommandManager, 'run', fake_run)

    with pytest.raises(AIVMError, match='Unrecognized findmnt output'):
        _assert_no_mounts_below(root)


def test_vm_tree_cleanup_does_not_confuse_missing_stat_with_missing_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fake_run(
        self: CommandManager,
        cmd: list[str],
        **kwargs: object,
    ) -> CommandResult:
        del self, kwargs
        if cmd and cmd[0] == 'findmnt':
            return CommandResult(127, '', 'findmnt: command not found')
        if cmd[:3] == ['env', 'LC_ALL=C', 'stat']:
            return CommandResult(
                127,
                '',
                "env: 'stat': No such file or directory",
            )
        raise AssertionError(f'unexpected command: {cmd!r}')

    monkeypatch.setattr(CommandManager, 'run', fake_run)

    with pytest.raises(AIVMError, match='Could not inspect deletion root'):
        _assert_no_mounts_below(tmp_path / 'vm-root')


def test_vm_deletion_resume_refuses_changed_domain_storage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    journal = _new_journal(scope, cfg, cfg_path)
    journal.mark('attachments-cleaned')
    journal.mark('credentials-cleaned')
    _save_journal(_journal_path(scope, cfg), journal, scope)
    changed_disk = (
        Path(cfg.paths.base_dir) / cfg.vm.name / 'images' / 'replacement.qcow2'
    )
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_file_storage_paths',
        lambda name: (changed_disk,),
    )

    with pytest.raises(
        AIVMError, match='storage changed after its deletion journal'
    ):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert calls == []
    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None
    persisted = _journal_path(scope, cfg).read_text(encoding='utf-8')
    assert str(changed_disk) in persisted
    assert 'remove-all-storage' in persisted


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
        journal: VMDeletionJournal,
        journal_scope: StoreScope,
        phase: str,
    ) -> None:
        if phase == 'store-finalized':
            raise OSError('simulated crash after final store write')
        real_persist(path, journal, journal_scope, phase)

    monkeypatch.setattr(module, '_persist_phase', crash_after_store_write)
    with pytest.raises(OSError, match='after final store write'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert find_vm(load_store(cfg_path), cfg.vm.name) is None
    journal = module.complete_missing_vm_deletion(scope, cfg_path, cfg.vm.name)
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
        journal: VMDeletionJournal,
        journal_scope: StoreScope,
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


def test_completed_deletion_journal_does_not_skip_recreated_vm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    stale = _new_journal(scope, cfg, cfg_path)
    stale.completed_phases = [
        'attachments-cleaned',
        'credentials-cleaned',
        'domain-and-storage-removed',
        'owned-trees-removed',
        'profile-cleared',
        'store-finalized',
    ]
    stale.status = 'complete'
    _save_journal(_journal_path(scope, cfg), stale, scope)

    journal = delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert journal is not None and journal.status == 'complete'
    assert calls == ['attachments', 'credentials', 'domain', 'trees']
    assert find_vm(load_store(cfg_path), cfg.vm.name) is None


def test_recreated_domain_restarts_stale_mid_deletion_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    stale = _new_journal(scope, cfg, cfg_path)
    stale.completed_phases = [
        'attachments-cleaned',
        'credentials-cleaned',
        'domain-and-storage-removed',
    ]
    _save_journal(_journal_path(scope, cfg), stale, scope)

    journal = delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert journal is not None and journal.status == 'complete'
    assert calls == ['attachments', 'credentials', 'domain', 'trees']


def test_vm_creation_is_blocked_by_unfinished_deletion_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    _stub_external_cleanup(monkeypatch, cfg, calls)
    journal = _new_journal(scope, cfg, cfg_path)
    journal.mark('attachments-cleaned')
    _save_journal(_journal_path(scope, cfg), journal, scope)

    with pytest.raises(AIVMError, match='unfinished deletion journal'):
        require_vm_creation_not_blocked(scope, cfg, cfg_path)

    journal.status = 'complete'
    _save_journal(_journal_path(scope, cfg), journal, scope)
    require_vm_creation_not_blocked(scope, cfg, cfg_path)


@pytest.mark.parametrize(
    'detail',
    [
        'failed to connect to the hypervisor',
        'permission denied while inspecting libvirt',
    ],
)
def test_vm_deletion_domain_inspection_failure_stops_before_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    detail: str,
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined', lambda _name: False
    )
    journal = _new_journal(scope, cfg, cfg_path)
    _save_journal(_journal_path(scope, cfg), journal, scope)
    calls: list[str] = []
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined',
        lambda _name: (_ for _ in ()).throw(AIVMError(detail)),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts',
        lambda *args, **kwargs: calls.append('attachments'),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion.discard_released_credential_material',
        lambda *args, **kwargs: calls.append('credentials'),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_owned_trees',
        lambda *args, **kwargs: calls.append('trees'),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._remove_retained_storage',
        lambda *args, **kwargs: calls.append('storage'),
    )

    with pytest.raises(AIVMError, match=detail):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert calls == []
    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None
    persisted = _load_journal(_journal_path(scope, cfg))
    assert persisted is not None
    assert persisted.completed_phases == []
    assert persisted.status == 'active'


def test_vm_deletion_dumpxml_failure_stops_before_journal_or_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined', lambda _name: True
    )
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_file_storage_paths',
        lambda _name: (_ for _ in ()).throw(AIVMError('dumpxml failed')),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts',
        lambda *args, **kwargs: calls.append('attachments'),
    )

    with pytest.raises(AIVMError, match='dumpxml failed'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert calls == []
    assert not _journal_path(scope, cfg).exists()
    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None


@pytest.mark.parametrize(
    'detail',
    [
        'storage stat command failed',
        'storage permission denied',
    ],
)
def test_vm_deletion_storage_probe_failure_stops_before_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    detail: str,
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_is_defined', lambda _name: False
    )
    journal = _new_journal(scope, cfg, cfg_path)
    _save_journal(_journal_path(scope, cfg), journal, scope)
    calls: list[str] = []
    monkeypatch.setattr(
        'aivm.vm.deletion._path_exists',
        lambda _path: (_ for _ in ()).throw(AIVMError(detail)),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts',
        lambda *args, **kwargs: calls.append('attachments'),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_owned_trees',
        lambda *args, **kwargs: calls.append('trees'),
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._remove_retained_storage',
        lambda *args, **kwargs: calls.append('storage'),
    )

    with pytest.raises(AIVMError, match=detail):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert calls == []
    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None
    persisted = _load_journal(_journal_path(scope, cfg))
    assert persisted is not None
    assert persisted.completed_phases == []
    assert persisted.status == 'active'


def test_vm_deletion_does_not_remove_retained_disk_without_absence_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scope, cfg, cfg_path = _machine_vm(tmp_path)
    disk = (
        Path(cfg.paths.base_dir)
        / cfg.vm.name
        / 'images'
        / f'{cfg.vm.name}.qcow2'
    )
    state = {'checks': 0}
    monkeypatch.setattr(
        'aivm.vm.deletion.domain_file_storage_paths', lambda _name: (disk,)
    )

    def defined(_name: str) -> bool:
        state['checks'] += 1
        # Journal creation and both preflight recaptures see the domain. The
        # post-undefine proof fails closed instead of authorizing direct rm.
        if state['checks'] >= 4:
            raise AIVMError('post-undefine inspection failed')
        return True

    monkeypatch.setattr('aivm.vm.deletion.domain_is_defined', defined)
    monkeypatch.setattr('aivm.vm.deletion._path_exists', lambda _path: True)
    monkeypatch.setattr(
        'aivm.vm.deletion._cleanup_attachment_artifacts', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.vm.deletion.discard_released_credential_material',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.vm.deletion._destroy_and_undefine_vm',
        lambda *a, **k: DomainRemovalReport((disk,), (disk,)),
    )
    removed: list[Path] = []
    monkeypatch.setattr(
        'aivm.vm.deletion._remove_retained_storage',
        lambda _cfg, paths: removed.extend(paths),
    )

    with pytest.raises(AIVMError, match='post-undefine inspection failed'):
        delete_managed_vm(scope, cfg, cfg_path, dry_run=False)

    assert removed == []
    assert find_vm(load_store(cfg_path), cfg.vm.name) is not None
    persisted = _load_journal(_journal_path(scope, cfg))
    assert persisted is not None
    assert 'domain-and-storage-removed' not in persisted.completed_phases
    assert 'store-finalized' not in persisted.completed_phases
