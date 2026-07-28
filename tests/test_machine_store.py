"""Unit coverage for the stage-2 machine-store filesystem contract."""

from __future__ import annotations

import json
import multiprocessing
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import (
    PrincipalEntry,
    Store,
    load_store,
    render_split_fragments,
    save_store,
    save_store_split,
    update_store,
    upsert_attachment,
    upsert_vm,
)
from aivm.machine_store import (
    BOOTSTRAP_DIRECTORY_MODE,
    MACHINE_DIRECTORY_MODE,
    MACHINE_FILE_MODE,
    MachineStoreGroupError,
    MachineStoreLayout,
    ensure_machine_store_layout,
    machine_resource_locks,
    machine_store_layout,
    machine_store_policy,
    ordered_machine_locks,
    resolve_machine_group_gid,
)


def _attachment_worker(
    root: str,
    machine_root: str,
    group_gid: int,
    host_path: str,
    vm_name: str,
    owner_principal_id: str,
    start: Any,
    errors: Any,
) -> None:
    """Perform one contended read-modify-write transaction in a child process."""
    try:
        layout = MachineStoreLayout.from_root(Path(machine_root))
        policy = machine_store_policy(layout, group_gid=group_gid)
        start.wait(timeout=10)

        def mutate(reg: Store) -> None:
            # Keep the lock long enough that the second process must wait.  The
            # assertion is about serialized updates, not process scheduling.
            time.sleep(0.1)
            upsert_attachment(
                reg,
                host_path=host_path,
                vm_name=vm_name,
                owner_principal_id=owner_principal_id,
                guest_dst=f'/home/agent/{Path(host_path).name}',
            )

        update_store(
            mutate,
            Path(root),
            reason=f'Concurrent attachment update for {host_path}.',
            io_policy=policy,
            force_split=True,
        )
        errors.put('')
    except BaseException as ex:  # pragma: no cover - reported in parent
        errors.put(repr(ex))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _single_vm_store(vm_name: str = 'aivm-2404-host') -> Store:
    reg = Store(active_vm=vm_name)
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name
    upsert_vm(reg, cfg)
    return reg


def _shared_vm_store(vm_name: str = 'aivm-2404-host') -> Store:
    reg = _single_vm_store(vm_name)
    reg.store_kind = 'machine'
    reg.schema_version = 10
    reg.principals = [
        PrincipalEntry(
            id='principal-alice',
            vm_name=vm_name,
            host_user='alice',
            host_uid=1001,
            host_gid=1001,
            guest_user='alice-agent',
            state='active',
        ),
        PrincipalEntry(
            id='principal-bob',
            vm_name=vm_name,
            host_user='bob',
            host_uid=1002,
            host_gid=1002,
            guest_user='bob-agent',
            state='active',
        ),
    ]
    return reg


def test_machine_store_layout_uses_isolated_environment(
    isolated_user_state: dict[str, Path],
) -> None:
    layout = machine_store_layout()
    assert layout.root == isolated_user_state['machine']
    assert layout.config_path == layout.root / 'config.toml'
    assert layout.store_lock_path == layout.root / 'locks' / 'store.lock'
    assert layout.vm_locks_dir == layout.root / 'locks' / 'vms'
    assert layout.network_locks_dir == layout.root / 'locks' / 'networks'
    assert layout.state_dir == layout.root / 'state'
    assert layout.bootstrap_dir == layout.root / 'bootstrap'


def test_machine_store_layout_enforces_group_safe_modes(tmp_path: Path) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()

    ensure_machine_store_layout(layout, group_gid=gid)

    for path in (
        layout.root,
        layout.locks_dir,
        layout.vm_locks_dir,
        layout.network_locks_dir,
        layout.state_dir,
    ):
        assert path.is_dir()
        assert _mode(path) == MACHINE_DIRECTORY_MODE
        assert path.stat().st_gid == gid
    assert _mode(layout.bootstrap_dir) == BOOTSTRAP_DIRECTORY_MODE
    assert layout.bootstrap_dir.stat().st_gid == gid


def test_machine_store_rejects_symlinked_root(tmp_path: Path) -> None:
    real_root = tmp_path / 'real'
    real_root.mkdir()
    linked_root = tmp_path / 'linked'
    linked_root.symlink_to(real_root, target_is_directory=True)
    layout = MachineStoreLayout.from_root(linked_root)

    with pytest.raises(RuntimeError, match='symlinked store path'):
        ensure_machine_store_layout(layout, group_gid=os.getgid())


def test_missing_machine_group_has_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_: str) -> None:
        raise KeyError

    monkeypatch.setattr('aivm.machine_store.grp.getgrnam', missing)
    with pytest.raises(MachineStoreGroupError, match='does not exist'):
        resolve_machine_group_gid('definitely-missing')


def test_atomic_replacement_preserves_machine_file_metadata(
    tmp_path: Path,
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()
    ensure_machine_store_layout(layout, group_gid=gid)
    policy = machine_store_policy(layout, group_gid=gid)
    reg = _single_vm_store()

    save_store(reg, layout.config_path, io_policy=policy)
    assert _mode(layout.config_path) == MACHINE_FILE_MODE
    assert layout.config_path.stat().st_gid == gid
    assert _mode(layout.store_lock_path) == MACHINE_FILE_MODE

    # Simulate metadata damage; the next atomic replacement must restore the
    # machine-store contract rather than inheriting tempfile's private mode.
    os.chmod(layout.config_path, 0o600)
    reg.behavior.verbose = 3
    save_store(reg, layout.config_path, io_policy=policy)

    assert _mode(layout.config_path) == MACHINE_FILE_MODE
    assert layout.config_path.stat().st_gid == gid
    assert load_store(layout.config_path, io_policy=policy).behavior.verbose == 3


def test_split_store_fragments_are_group_writable(tmp_path: Path) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()
    ensure_machine_store_layout(layout, group_gid=gid)
    policy = machine_store_policy(layout, group_gid=gid)
    reg = _single_vm_store()

    written = save_store_split(reg, layout.config_path, io_policy=policy)

    assert layout.config_path in written
    for path in written:
        assert _mode(path) == MACHINE_FILE_MODE
        assert path.stat().st_gid == gid
    assert _mode(layout.root / 'vms') == MACHINE_DIRECTORY_MODE


def test_machine_lock_order_is_global_then_network_then_vm(tmp_path: Path) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    specs = ordered_machine_locks(
        layout,
        include_store=True,
        networks=['z-net', 'a-net', 'z-net'],
        vms=['vm-z', 'vm-a', 'vm-z'],
    )
    assert [spec.name for spec in specs] == [
        'store',
        'network:a-net',
        'network:z-net',
        'vm:vm-a',
        'vm:vm-z',
    ]


def test_machine_resource_locks_use_group_safe_files(tmp_path: Path) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()
    ensure_machine_store_layout(layout, group_gid=gid)

    with machine_resource_locks(
        layout,
        group_gid=gid,
        include_store=True,
        networks=['aivm-net'],
        vms=['aivm-2404-host'],
    ) as specs:
        assert len(specs) == 3
        for spec in specs:
            assert spec.path.is_file()
            assert _mode(spec.path) == MACHINE_FILE_MODE
            assert spec.path.stat().st_gid == gid


def test_store_lock_can_be_nested_inside_resource_lock_set(
    tmp_path: Path,
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()
    ensure_machine_store_layout(layout, group_gid=gid)
    policy = machine_store_policy(layout, group_gid=gid)

    with machine_resource_locks(
        layout,
        group_gid=gid,
        include_store=True,
        vms=['aivm-2404-host'],
    ):
        update_store(
            lambda reg: setattr(reg.behavior, 'verbose', 2),
            layout.config_path,
            io_policy=policy,
            force_split=True,
        )

    loaded = load_store(layout.config_path, io_policy=policy)
    assert loaded.behavior.verbose == 2


def test_concurrent_machine_store_updates_retain_both_attachments(
    tmp_path: Path,
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()
    ensure_machine_store_layout(layout, group_gid=gid)
    policy = machine_store_policy(layout, group_gid=gid)
    vm_name = 'aivm-2404-host'
    save_store_split(
        _shared_vm_store(vm_name),
        layout.config_path,
        io_policy=policy,
    )
    alice_path = tmp_path / 'alice-project'
    bob_path = tmp_path / 'bob-project'
    alice_path.mkdir()
    bob_path.mkdir()

    ctx = multiprocessing.get_context('spawn')
    start = ctx.Event()
    errors = ctx.Queue()
    processes = [
        ctx.Process(
            target=_attachment_worker,
            args=(
                str(layout.config_path),
                str(layout.root),
                gid,
                str(host_path),
                vm_name,
                owner,
                start,
                errors,
            ),
        )
        for host_path, owner in (
            (alice_path, 'principal-alice'),
            (bob_path, 'principal-bob'),
        )
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=15)
        assert not process.is_alive()
        assert process.exitcode == 0
    reported = [errors.get(timeout=2) for _ in processes]
    assert reported == ['', '']

    loaded = load_store(layout.config_path, io_policy=policy)
    assert {
        (item.host_path, item.owner_principal_id)
        for item in loaded.attachments
    } == {
        (str(alice_path.resolve()), 'principal-alice'),
        (str(bob_path.resolve()), 'principal-bob'),
    }


def test_interrupted_split_recovery_preserves_unrelated_vm_fragment(
    tmp_path: Path,
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    gid = os.getgid()
    ensure_machine_store_layout(layout, group_gid=gid)
    policy = machine_store_policy(layout, group_gid=gid)
    reg = _single_vm_store('vm-a')
    cfg_b = AgentVMConfig()
    cfg_b.vm.name = 'vm-b'
    upsert_vm(reg, cfg_b)
    save_store_split(reg, layout.config_path, io_policy=policy)

    changed = load_store(layout.config_path, io_policy=policy)
    vm_a = next(vm for vm in changed.vms if vm.name == 'vm-a')
    vm_a.cfg.vm.cpus = 13
    fragment = render_split_fragments(changed)['vm:vm-a']

    txn = layout.root / '.aivm-store-transaction'
    staged = txn / 'new' / 'vms' / 'vm-a.toml'
    staged.parent.mkdir(parents=True)
    staged.write_text(fragment, encoding='utf-8')
    (txn / 'metadata.json').write_text(
        json.dumps(
            {
                'schema_version': 1,
                'write': ['vms/vm-a.toml'],
                'delete': [],
            }
        ),
        encoding='utf-8',
    )

    recovered = load_store(layout.config_path, io_policy=policy)

    assert not txn.exists()
    assert {vm.name for vm in recovered.vms} == {'vm-a', 'vm-b'}
    assert next(vm for vm in recovered.vms if vm.name == 'vm-a').cfg.vm.cpus == 13
    assert (layout.root / 'vms' / 'vm-b.toml').is_file()
    assert _mode(layout.root / 'vms' / 'vm-a.toml') == MACHINE_FILE_MODE
