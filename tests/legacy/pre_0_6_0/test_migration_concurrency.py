"""Transaction-wide migration concurrency and target revision coverage."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable

import pytest

from aivm.config import AgentVMConfig
from aivm.config_store import (
    CredentialEntry,
    Store,
    load_store,
    save_store,
    save_store_split,
    upsert_credential,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.credentials.validation import credential_id
from aivm.legacy.pre_0_6_0.migration import (
    LegacyStoreSource,
    MigrationPlan,
    build_migration_plan,
)
from aivm.legacy.pre_0_6_0.migration_apply import (
    GuestInstaller,
    MigrationApplyResult,
    MigrationExecutionError,
    apply_migration,
    migration_id_for_plan,
    migration_transaction_dir,
    resume_migration,
    verify_applied_migration,
)
from aivm.machine_store import (
    MachineStoreLayout,
    machine_store_policy,
)


def _public_key(label: str) -> str:
    return f'ssh-ed25519 ZmFrZS1taWdyYXRpb24ta2V5LWJsb2I= {label}'


def _legacy_source(
    tmp_path: Path,
    *,
    label: str,
) -> tuple[LegacyStoreSource, str]:
    host_user = f'tester-{label}'
    home = tmp_path / host_user
    key = home / '.ssh' / 'id_aivm_ed25519'
    key.parent.mkdir(parents=True)
    key.write_text('private-key\n')
    key.with_suffix('.pub').write_text(_public_key(label) + '\n')

    cfg = AgentVMConfig().expanded_paths()
    cfg.vm.name = f'aivm-{label}'
    cfg.vm.user = 'legacy-agent'
    cfg.network.name = f'aivm-net-{label}'
    cfg.paths.ssh_identity_file = str(key)
    cfg.paths.ssh_pubkey_path = str(key.with_suffix('.pub'))
    cfg.paths.state_dir = str(home / '.local' / 'state' / 'aivm')

    reg = Store(schema_version=8, active_vm=cfg.vm.name)
    reg.defaults = cfg
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    old_cred_id = credential_id(cfg.vm.name, 'github.com/kitware/aivm')
    upsert_credential(
        reg,
        CredentialEntry(
            id=old_cred_id,
            vm_name=cfg.vm.name,
            provider_host='github.com',
            owner='Kitware',
            repository='aivm',
            provider_key_id='1234',
            provider_key_title='migration concurrency fixture',
            key_fingerprint='SHA256:ZmFrZUZpbmdlcnByaW50',
            state='active',
        ),
    )
    store_path = home / '.config' / 'aivm' / 'config.toml'
    save_store(reg, store_path)

    data_root = home / '.local' / 'share' / 'aivm' / cfg.vm.name
    credential_source = data_root / 'credentials' / old_cred_id
    credential_source.mkdir(parents=True)
    (credential_source / 'id_ed25519').write_text('private-key\n')
    (credential_source / 'id_ed25519.pub').write_text(
        _public_key(label) + '\n'
    )
    persistent_source = data_root / 'state'
    persistent_source.mkdir(parents=True)
    (persistent_source / 'persistent-attachments.json').write_text('{}\n')

    source = LegacyStoreSource(
        path=store_path,
        host_user=host_user,
        host_uid=os.getuid(),
        host_gid=os.getgid(),
        home=home,
    )
    return source, cfg.vm.name


def _runtime_ok(
    plan: MigrationPlan, layout: MachineStoreLayout
) -> dict[str, object]:
    del layout
    return {
        'status': 'passed',
        'domains': sorted(plan.legacy_vm_cfgs),
        'creator_ssh_verified': sorted(plan.legacy_vm_cfgs),
    }


def _guest_noop(
    vm_name: str, cfg: AgentVMConfig, layout: MachineStoreLayout
) -> None:
    del vm_name, cfg, layout


def _blocking_guest(
    entered: threading.Event,
    release: threading.Event,
) -> GuestInstaller:
    def install(
        vm_name: str, cfg: AgentVMConfig, layout: MachineStoreLayout
    ) -> None:
        del vm_name, cfg, layout
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError('test did not release blocked migration')

    return install


def _thread_call(
    target: Callable[[], MigrationApplyResult],
    result: list[MigrationApplyResult],
    errors: list[BaseException],
    done: threading.Event,
) -> None:
    try:
        result.append(target())
    except BaseException as ex:
        errors.append(ex)
    finally:
        done.set()


def test_apply_rejects_machine_store_mutation_after_planning(
    tmp_path: Path,
) -> None:
    source, _vm_name = _legacy_source(tmp_path, label='reviewed')
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    assert not plan.blocked
    assert not plan.target_machine_store_exists
    assert plan.target_machine_store_sha256

    intervening = Store(schema_version=11, store_kind='machine')
    cfg = AgentVMConfig()
    cfg.vm.name = 'concurrent-vm'
    cfg.network.name = 'concurrent-net'
    upsert_network(
        intervening, network=cfg.network, firewall=cfg.firewall
    )
    upsert_vm_with_network(
        intervening, cfg, network_name=cfg.network.name
    )
    save_store_split(
        intervening,
        layout.config_path,
        io_policy=machine_store_policy(layout, group_gid=os.getgid()),
    )

    with pytest.raises(
        MigrationExecutionError,
        match='Target machine store changed after migration planning',
    ):
        apply_migration(
            plan,
            layout=layout,
            guest_installer=_guest_noop,
            runtime_verifier=_runtime_ok,
        )

    current = load_store(layout.config_path)
    assert [item.name for item in current.vms] == ['concurrent-vm']
    transaction = migration_transaction_dir(
        migration_id_for_plan(plan), layout
    )
    assert not transaction.exists()


def test_two_migrations_are_serialized_and_second_cannot_overwrite(
    tmp_path: Path,
) -> None:
    source_a, vm_a = _legacy_source(tmp_path, label='first')
    source_b, _vm_b = _legacy_source(tmp_path, label='second')
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan_a = build_migration_plan([source_a], layout=layout, check_runtime=False)
    plan_b = build_migration_plan([source_b], layout=layout, check_runtime=False)
    assert not plan_a.blocked
    assert not plan_b.blocked

    entered = threading.Event()
    release = threading.Event()
    first_done = threading.Event()
    second_done = threading.Event()
    first_results: list[MigrationApplyResult] = []
    second_results: list[MigrationApplyResult] = []
    first_errors: list[BaseException] = []
    second_errors: list[BaseException] = []

    first = threading.Thread(
        target=_thread_call,
        args=(
            lambda: apply_migration(
                plan_a,
                layout=layout,
                guest_installer=_blocking_guest(entered, release),
                runtime_verifier=_runtime_ok,
            ),
            first_results,
            first_errors,
            first_done,
        ),
    )
    first.start()
    assert entered.wait(timeout=10)

    second = threading.Thread(
        target=_thread_call,
        args=(
            lambda: apply_migration(
                plan_b,
                layout=layout,
                guest_installer=_guest_noop,
                runtime_verifier=_runtime_ok,
            ),
            second_results,
            second_errors,
            second_done,
        ),
    )
    second.start()
    assert not second_done.wait(timeout=0.2)

    release.set()
    first.join(timeout=10)
    second.join(timeout=10)
    assert first_done.is_set()
    assert second_done.is_set()
    assert not first_errors
    assert first_results[0].journal.status == 'complete'
    assert not second_results
    assert len(second_errors) == 1
    assert isinstance(second_errors[0], MigrationExecutionError)
    assert 'changed after migration planning' in str(second_errors[0])

    current = load_store(layout.config_path)
    assert [item.name for item in current.vms] == [vm_a]
    second_transaction = migration_transaction_dir(
        migration_id_for_plan(plan_b), layout
    )
    assert not second_transaction.exists()


def test_verification_waits_for_partially_completed_apply(
    tmp_path: Path,
) -> None:
    source, _vm_name = _legacy_source(tmp_path, label='verify-race')
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    migration_id = migration_id_for_plan(plan)
    entered = threading.Event()
    release = threading.Event()
    apply_done = threading.Event()
    verify_done = threading.Event()
    apply_results: list[MigrationApplyResult] = []
    verify_results: list[MigrationApplyResult] = []
    apply_errors: list[BaseException] = []
    verify_errors: list[BaseException] = []

    applying = threading.Thread(
        target=_thread_call,
        args=(
            lambda: apply_migration(
                plan,
                layout=layout,
                guest_installer=_blocking_guest(entered, release),
                runtime_verifier=_runtime_ok,
            ),
            apply_results,
            apply_errors,
            apply_done,
        ),
    )
    applying.start()
    assert entered.wait(timeout=10)

    verifying = threading.Thread(
        target=_thread_call,
        args=(
            lambda: verify_applied_migration(
                migration_id,
                layout=layout,
                runtime_verifier=_runtime_ok,
            ),
            verify_results,
            verify_errors,
            verify_done,
        ),
    )
    verifying.start()
    assert not verify_done.wait(timeout=0.2)

    release.set()
    applying.join(timeout=10)
    verifying.join(timeout=10)
    assert apply_done.is_set()
    assert verify_done.is_set()
    assert not apply_errors
    assert not verify_errors
    assert apply_results[0].journal.status == 'complete'
    assert verify_results[0].journal.status == 'complete'


def test_resume_waits_for_partially_completed_apply(
    tmp_path: Path,
) -> None:
    source, _vm_name = _legacy_source(tmp_path, label='resume-race')
    layout = MachineStoreLayout.from_root(tmp_path / 'machine')
    plan = build_migration_plan([source], layout=layout, check_runtime=False)
    migration_id = migration_id_for_plan(plan)
    entered = threading.Event()
    release = threading.Event()
    apply_done = threading.Event()
    resume_done = threading.Event()
    apply_results: list[MigrationApplyResult] = []
    resume_results: list[MigrationApplyResult] = []
    apply_errors: list[BaseException] = []
    resume_errors: list[BaseException] = []

    applying = threading.Thread(
        target=_thread_call,
        args=(
            lambda: apply_migration(
                plan,
                layout=layout,
                guest_installer=_blocking_guest(entered, release),
                runtime_verifier=_runtime_ok,
            ),
            apply_results,
            apply_errors,
            apply_done,
        ),
    )
    applying.start()
    assert entered.wait(timeout=10)

    resuming = threading.Thread(
        target=_thread_call,
        args=(
            lambda: resume_migration(
                migration_id,
                layout=layout,
                guest_installer=_guest_noop,
                runtime_verifier=_runtime_ok,
                check_runtime=False,
            ),
            resume_results,
            resume_errors,
            resume_done,
        ),
    )
    resuming.start()
    assert not resume_done.wait(timeout=0.2)

    release.set()
    applying.join(timeout=10)
    resuming.join(timeout=10)
    assert apply_done.is_set()
    assert resume_done.is_set()
    assert not apply_errors
    assert not resume_errors
    assert apply_results[0].journal.status == 'complete'
    assert resume_results[0].journal.status == 'complete'
    assert resume_results[0].resumed
