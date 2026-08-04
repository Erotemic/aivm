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
    DEFAULT_MACHINE_STORE_ROOT,
    MACHINE_DIRECTORY_MODE,
    MACHINE_FILE_MODE,
    PERSONAL_DIRECTORY_MODE,
    PERSONAL_FILE_MODE,
    MachineStoreAccessError,
    MachineStoreGroupError,
    MachineStoreLayout,
    current_machine_group_gid,
    ensure_machine_store_layout,
    machine_resource_locks,
    machine_root_is_shared,
    machine_store_layout,
    machine_store_policy,
    ordered_machine_locks,
    personal_machine_store_root,
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
    layout = MachineStoreLayout.from_root(tmp_path / 'machine', shared=True)
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
    layout = MachineStoreLayout.from_root(tmp_path / 'machine', shared=True)
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
    assert (
        load_store(layout.config_path, io_policy=policy).behavior.verbose == 3
    )


def test_split_store_fragments_are_group_writable(tmp_path: Path) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine', shared=True)
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


def test_machine_lock_order_is_global_then_network_then_vm(
    tmp_path: Path,
) -> None:
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
    layout = MachineStoreLayout.from_root(tmp_path / 'machine', shared=True)
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
        (item.host_path, item.owner_principal_id) for item in loaded.attachments
    } == {
        (str(alice_path.resolve()), 'principal-alice'),
        (str(bob_path.resolve()), 'principal-bob'),
    }


def test_interrupted_split_recovery_preserves_unrelated_vm_fragment(
    tmp_path: Path,
) -> None:
    layout = MachineStoreLayout.from_root(tmp_path / 'machine', shared=True)
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
    assert (
        next(vm for vm in recovered.vms if vm.name == 'vm-a').cfg.vm.cpus == 13
    )
    assert (layout.root / 'vms' / 'vm-b.toml').is_file()
    assert _mode(layout.root / 'vms' / 'vm-a.toml') == MACHINE_FILE_MODE


def test_store_root_stays_clear_of_the_persistent_replay_state_chain() -> None:
    """The group-writable store must not sit on the root replay directory.

    ``_approved_state_directories_are_safe`` refuses any group- or
    world-writable bit on the persistent-host state directory and its parent,
    and rewrites them back to root:root 0755 when it finds one. A store root
    that is either of those paths -- or an ancestor of them -- makes the two
    subsystems fight over the same mode on every operation, and lets a
    store-group member replace a directory a root service reads.
    """
    from aivm.persistent_replay import (
        PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR,
    )

    replay_state = Path(PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR)
    root = DEFAULT_MACHINE_STORE_ROOT
    protected = (replay_state, replay_state.parent)

    assert MACHINE_DIRECTORY_MODE & 0o022, 'store root is group-writable'
    for path in protected:
        assert root != path
        assert root not in path.parents


# ---------------------------------------------------------------------------
# Store root selection
#
# Four rows decide where the store lives. The middle two are the interesting
# ones: a host that shares wins over a personal store, and a host that shares
# but locks this caller out must refuse rather than quietly hand them a second
# authority over the same libvirt domains.
# ---------------------------------------------------------------------------


@pytest.fixture()
def unshared_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """Point the shared root at a path no host-wide store occupies."""
    absent = tmp_path / 'var-lib-aivm-machine'
    monkeypatch.delenv('AIVM_MACHINE_STORE_ROOT', raising=False)
    monkeypatch.setattr(
        'aivm.machine_store.DEFAULT_MACHINE_STORE_ROOT', absent
    )
    return absent


def test_personal_root_is_used_when_the_host_has_no_shared_store(
    unshared_host: Path,
) -> None:
    layout = machine_store_layout()

    assert layout.root == personal_machine_store_root()
    assert not layout.shared
    # The whole point: no group is consulted, so no membership is required.
    assert current_machine_group_gid(layout) == os.getgid()


def test_personal_store_is_private_rather_than_group_shared(
    unshared_host: Path,
) -> None:
    layout = machine_store_layout()

    ensure_machine_store_layout(layout)

    policy = machine_store_policy(layout)
    assert policy.directory_mode == PERSONAL_DIRECTORY_MODE
    assert policy.file_mode == PERSONAL_FILE_MODE
    assert _mode(layout.root) == PERSONAL_DIRECTORY_MODE
    assert layout.root.stat().st_gid == os.getgid()


def test_shared_root_wins_over_the_personal_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared = tmp_path / 'shared'
    shared.mkdir()
    monkeypatch.delenv('AIVM_MACHINE_STORE_ROOT', raising=False)
    monkeypatch.setattr(
        'aivm.machine_store.DEFAULT_MACHINE_STORE_ROOT', shared
    )

    layout = machine_store_layout()

    assert layout.root == shared
    assert layout.shared
    policy = machine_store_policy(layout, group_gid=os.getgid())
    assert policy.directory_mode == MACHINE_DIRECTORY_MODE
    assert policy.file_mode == MACHINE_FILE_MODE


def test_unreachable_shared_store_refuses_instead_of_forking(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A store this caller cannot read must not become a second authority.

    Falling back to a personal store here is the one genuinely unsafe
    outcome of supporting both layouts: the shared store already claims this
    host's domains, and a private store beside it would claim them again.
    """
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o000)
    monkeypatch.delenv('AIVM_MACHINE_STORE_ROOT', raising=False)
    monkeypatch.setattr(
        'aivm.machine_store.DEFAULT_MACHINE_STORE_ROOT', shared
    )

    try:
        with pytest.raises(MachineStoreAccessError) as caught:
            machine_store_layout()
    finally:
        shared.chmod(0o700)

    message = str(caught.value)
    assert 'libvirt' in message
    assert 'usermod' in message
    assert str(personal_machine_store_root()) not in message


def test_explicit_root_override_beats_both_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared = tmp_path / 'shared'
    shared.mkdir()
    sandbox = tmp_path / 'sandbox'
    monkeypatch.setattr(
        'aivm.machine_store.DEFAULT_MACHINE_STORE_ROOT', shared
    )
    monkeypatch.setenv('AIVM_MACHINE_STORE_ROOT', str(sandbox))

    layout = machine_store_layout()

    assert layout.root == sandbox
    # A caller-owned sandbox is not the host-wide store, so it needs no group.
    assert not layout.shared
    assert current_machine_group_gid(layout) == os.getgid()


def test_subdirectories_inherit_the_ownership_of_their_store() -> None:
    """Sublayouts must not be classified on their own name.

    Migration transactions and lock namespaces build layouts rooted inside
    the store. One that answered "personal" because its path is not exactly
    the store root would write caller-owned modes into a group-shared tree.
    """
    assert machine_root_is_shared(DEFAULT_MACHINE_STORE_ROOT)
    assert machine_root_is_shared(
        DEFAULT_MACHINE_STORE_ROOT / 'state' / 'migrations' / 'abc'
    )
    assert not machine_root_is_shared(personal_machine_store_root())
    assert not machine_root_is_shared(Path('/tmp/somewhere-else'))
