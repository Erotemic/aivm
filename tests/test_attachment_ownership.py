"""Shared-machine attachment ownership and replay tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aivm.attachments.ownership import attachment_owner_label
from aivm.attachments.persistent import (
    _persistent_host_manifest_path,
    _sync_persistent_attachment_manifest_on_host,
)
from aivm.attachments.resolve import _resolve_attachment
from aivm.attachments.session import _saved_vm_attachments
from aivm.cli.vm_attach import VMDetachRequest, run_vm_detach
from aivm.config import AgentVMConfig
from aivm.config_store import (
    AttachmentEntry,
    PrincipalEntry,
    Store,
    find_attachment_for_vm,
    find_attachments_for_vm_path,
    load_store,
    save_store_split,
    upsert_attachment,
    upsert_principal,
    upsert_vm,
)
from aivm.errors import AIVMError
from aivm.fs_identity import directory_identity
from aivm.host_identity import HostIdentity
from aivm.machine_store import machine_store_layout
from aivm.services import resolve_vm_name
from aivm.status import ProbeOutcome, render_global_status
from tests.helpers import resolved_test_context


def _principal(vm_name: str, owner: str, host_user: str) -> PrincipalEntry:
    host_id = {'alice': 1001, 'bob': 1002, 'carol': 1003}.get(host_user, 1099)
    return PrincipalEntry(
        id=owner,
        vm_name=vm_name,
        host_user=host_user,
        host_uid=host_id,
        host_gid=host_id,
        guest_user=f'{host_user}-agent',
        state='active',
    )


def _machine_store(vm_names: tuple[str, ...] = ('vm-shared',)) -> Store:
    reg = Store(store_kind='machine', schema_version=10)
    for vm_name in vm_names:
        cfg = AgentVMConfig()
        cfg.vm.name = vm_name
        upsert_vm(reg, cfg)
    return reg


def test_owner_roundtrip_and_owner_scoped_lookup(tmp_path: Path) -> None:
    vm_name = 'vm-shared'
    reg = _machine_store()
    for principal in (
        _principal(vm_name, 'principal-alice', 'alice'),
        _principal(vm_name, 'principal-bob', 'bob'),
    ):
        upsert_principal(reg, principal)
    shared = tmp_path / 'project'
    shared.mkdir()
    for owner, dst in (
        ('principal-alice', '/home/alice-agent/project'),
        ('principal-bob', '/home/bob-agent/project'),
    ):
        upsert_attachment(
            reg,
            host_path=shared,
            vm_name=vm_name,
            owner_principal_id=owner,
            mode='persistent',
            guest_dst=dst,
            tag=f'tag-{owner}',
        )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)

    loaded = load_store(path)
    assert len(find_attachments_for_vm_path(loaded, shared, vm_name)) == 2
    alice = find_attachment_for_vm(
        loaded,
        shared,
        vm_name,
        owner_principal_id='principal-alice',
    )
    assert alice is not None
    assert alice.guest_dst == '/home/alice-agent/project'
    assert 'alice -> alice-agent' in attachment_owner_label(
        loaded, alice.owner_principal_id
    )


def test_foreign_record_requires_explicit_administrative_override(
    tmp_path: Path,
) -> None:
    vm_name = 'vm-shared'
    reg = _machine_store()
    bob = _principal(vm_name, 'principal-bob', 'bob')
    upsert_principal(reg, bob)
    source = tmp_path / 'bob-project'
    source.mkdir()
    upsert_attachment(
        reg,
        host_path=source,
        vm_name=vm_name,
        owner_principal_id=bob.id,
        guest_dst='/home/bob-agent/project',
    )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name

    with pytest.raises(AIVMError, match='owned by another VM principal'):
        _resolve_attachment(
            cfg,
            path,
            source,
            '',
            owner_principal_id='principal-alice',
        )
    resolved = _resolve_attachment(
        cfg,
        path,
        source,
        '',
        owner_principal_id='principal-alice',
        administrative_override=True,
    )
    assert resolved.owner_principal_id == bob.id


def test_detach_blocks_foreign_owner_without_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    source = tmp_path / 'bob-project'
    source.mkdir()
    reg = Store()
    reg.attachments = [
        AttachmentEntry(
            host_path=str(source.resolve()),
            vm_name=cfg.vm.name,
            owner_principal_id='principal-bob',
            mode='direct-virtiofs',
            guest_dst='/home/bob-agent/project',
        )
    ]
    path = tmp_path / 'config.toml'
    from aivm.config_store import save_store

    save_store(reg, path)
    context = resolved_test_context(cfg, host_user='alice')
    monkeypatch.setattr(
        'aivm.cli.vm_attach.resolve_context_for_code',
        lambda **kwargs: (context, path),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attachment_owner_for_context',
        lambda *args: 'principal-alice',
    )

    with pytest.raises(AIVMError, match='owned by another VM principal'):
        run_vm_detach(
            VMDetachRequest(
                config_opt=str(path),
                vm_opt=cfg.vm.name,
                host_src=source,
                dry_run=True,
            )
        )
    assert (
        run_vm_detach(
            VMDetachRequest(
                config_opt=str(path),
                vm_opt=cfg.vm.name,
                host_src=source,
                dry_run=True,
                admin_override=True,
            )
        )
        == 0
    )


def test_vm_resolution_uses_current_principals_attachment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    layout = machine_store_layout()
    reg = _machine_store(('vm-alice', 'vm-bob'))
    upsert_principal(reg, _principal('vm-alice', 'principal-alice', 'alice'))
    upsert_principal(reg, _principal('vm-bob', 'principal-bob', 'bob'))
    source = tmp_path / 'project'
    source.mkdir()
    upsert_attachment(
        reg,
        host_path=source,
        vm_name='vm-alice',
        owner_principal_id='principal-alice',
    )
    upsert_attachment(
        reg,
        host_path=source,
        vm_name='vm-bob',
        owner_principal_id='principal-bob',
    )
    save_store_split(reg, layout.config_path)
    monkeypatch.setattr(
        'aivm.services.current_host_identity',
        lambda: HostIdentity(uid=1002, gid=1002, username='bob'),
    )

    vm_name, path = resolve_vm_name(
        config_opt=str(layout.config_path), vm_opt='', host_src=source
    )
    assert path == layout.config_path
    assert vm_name == 'vm-bob'


def test_machine_persistent_manifest_contains_global_inventory(
    tmp_path: Path,
) -> None:
    layout = machine_store_layout()
    vm_name = 'vm-shared'
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name
    reg = _machine_store()
    for principal in (
        _principal(vm_name, 'principal-alice', 'alice'),
        _principal(vm_name, 'principal-bob', 'bob'),
    ):
        upsert_principal(reg, principal)
    for owner in ('principal-alice', 'principal-bob'):
        source = tmp_path / owner
        source.mkdir()
        source_identity = directory_identity(source)
        upsert_attachment(
            reg,
            host_path=source,
            vm_name=vm_name,
            owner_principal_id=owner,
            mode='persistent',
            guest_dst=f'/srv/{owner}',
            tag=f'tag-{owner}',
            source_dev=source_identity.dev,
            source_ino=source_identity.ino,
        )
    save_store_split(reg, layout.config_path)

    path = _sync_persistent_attachment_manifest_on_host(
        cfg, layout.config_path, dry_run=False
    )
    assert path == _persistent_host_manifest_path(cfg, layout.config_path)
    assert path.is_relative_to(layout.vm_state_dir(vm_name))
    payload = json.loads(path.read_text())
    assert [item['owner_principal_id'] for item in payload['records']] == [
        'principal-alice',
        'principal-bob',
    ]
    assert len({item['attachment_id'] for item in payload['records']}) == 2
    assert path.stat().st_gid == os.getgid()


def test_global_status_reports_owner_and_guest_destination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    vm_name = 'vm-shared'
    reg = _machine_store()
    alice = _principal(vm_name, 'principal-alice', 'alice')
    upsert_principal(reg, alice)
    upsert_attachment(
        reg,
        host_path=tmp_path / 'project',
        vm_name=vm_name,
        owner_principal_id=alice.id,
        guest_dst='/home/alice-agent/project',
    )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)
    monkeypatch.setattr('aivm.status.check_commands', lambda: ([], []))
    monkeypatch.setattr(
        'aivm.status.probe_runtime_environment',
        lambda: ProbeOutcome(True, 'ok'),
    )

    text = render_global_status(path)
    assert 'alice -> alice-agent' in text
    assert 'guest=/home/alice-agent/project' in text


def test_machine_store_rejects_duplicate_guest_destination(
    tmp_path: Path,
) -> None:
    vm_name = 'vm-shared'
    reg = _machine_store()
    alice = _principal(vm_name, 'principal-alice', 'alice')
    bob = _principal(vm_name, 'principal-bob', 'bob')
    upsert_principal(reg, alice)
    upsert_principal(reg, bob)
    alice_src = tmp_path / 'alice-project'
    bob_src = tmp_path / 'bob-project'
    alice_src.mkdir()
    bob_src.mkdir()
    upsert_attachment(
        reg,
        host_path=alice_src,
        vm_name=vm_name,
        owner_principal_id=alice.id,
        guest_dst='/workspace/project',
    )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name

    with pytest.raises(AIVMError, match='guest destination is already owned'):
        _resolve_attachment(
            cfg,
            path,
            bob_src,
            '/workspace/project',
            owner_principal_id=bob.id,
        )


def test_saved_session_attachments_are_principal_scoped(
    tmp_path: Path,
) -> None:
    vm_name = 'vm-shared'
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name
    reg = _machine_store()
    alice = _principal(vm_name, 'principal-alice', 'alice')
    bob = _principal(vm_name, 'principal-bob', 'bob')
    upsert_principal(reg, alice)
    upsert_principal(reg, bob)
    alice_src = tmp_path / 'alice-project'
    bob_src = tmp_path / 'bob-project'
    alice_src.mkdir()
    bob_src.mkdir()
    upsert_attachment(
        reg,
        host_path=alice_src,
        vm_name=vm_name,
        owner_principal_id=alice.id,
        mode='direct-virtiofs',
        guest_dst='/home/alice-agent/project',
    )
    upsert_attachment(
        reg,
        host_path=bob_src,
        vm_name=vm_name,
        owner_principal_id=bob.id,
        mode='direct-virtiofs',
        guest_dst='/home/bob-agent/project',
    )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)

    saved = _saved_vm_attachments(cfg, path, owner_principal_id=alice.id)
    assert [item.source_dir for item in saved] == [str(alice_src.resolve())]
    assert saved[0].owner_principal_id == alice.id


def test_admin_can_target_one_of_multiple_foreign_records(
    tmp_path: Path,
) -> None:
    vm_name = 'vm-shared'
    reg = _machine_store()
    owners = (
        _principal(vm_name, 'principal-alice', 'alice'),
        _principal(vm_name, 'principal-bob', 'bob'),
        _principal(vm_name, 'principal-carol', 'carol'),
    )
    for principal in owners:
        upsert_principal(reg, principal)
    source = tmp_path / 'shared-project'
    source.mkdir()
    for principal in owners[1:]:
        upsert_attachment(
            reg,
            host_path=source,
            vm_name=vm_name,
            owner_principal_id=principal.id,
            guest_dst=f'/srv/{principal.host_user}',
        )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)
    cfg = AgentVMConfig()
    cfg.vm.name = vm_name

    with pytest.raises(AIVMError, match='retry with --owner_principal'):
        _resolve_attachment(
            cfg,
            path,
            source,
            '',
            owner_principal_id='principal-alice',
            administrative_override=True,
        )
    resolved = _resolve_attachment(
        cfg,
        path,
        source,
        '',
        owner_principal_id='principal-alice',
        administrative_override=True,
        administrative_owner_principal_id='principal-bob',
    )
    assert resolved.owner_principal_id == 'principal-bob'
    assert resolved.guest_dst == '/srv/bob'


def test_explicit_owner_target_requires_admin_override(
    tmp_path: Path,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    source = tmp_path / 'project'
    source.mkdir()
    reg = _machine_store()
    bob = _principal(cfg.vm.name, 'principal-bob', 'bob')
    upsert_principal(reg, bob)
    upsert_attachment(
        reg,
        host_path=source,
        vm_name=cfg.vm.name,
        owner_principal_id=bob.id,
        guest_dst='/srv/bob',
    )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)

    with pytest.raises(AIVMError, match='requires --admin_override'):
        _resolve_attachment(
            cfg,
            path,
            source,
            '',
            owner_principal_id='principal-alice',
            administrative_owner_principal_id=bob.id,
        )
    # An owner that names nobody on this VM is refused up front rather than
    # producing a dangling owner the machine store rejects much later.
    with pytest.raises(AIVMError, match='No access identity'):
        _resolve_attachment(
            cfg,
            path,
            source,
            '',
            owner_principal_id='principal-alice',
            administrative_override=True,
            administrative_owner_principal_id='principal-missing',
        )


def test_admin_can_declare_an_attachment_for_another_identity(
    tmp_path: Path,
) -> None:
    """An administrator sets up a root-requiring mode for a sudo-less user.

    Persistent and shared-root attachments need a host bind mount, so on a
    shared workstation only an administrator can create one. Without this
    the admin could only attach as *themselves*, which records the wrong
    owner and hands the guest-side folder to the wrong account.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared'
    source = tmp_path / 'project'
    source.mkdir()
    reg = _machine_store()
    bob = _principal(cfg.vm.name, 'principal-bob', 'bob')
    upsert_principal(reg, bob)
    upsert_principal(
        reg, _principal(cfg.vm.name, 'principal-admin', 'admin')
    )
    path = tmp_path / 'config.toml'
    save_store_split(reg, path)

    resolved = _resolve_attachment(
        cfg,
        path,
        source,
        '',
        owner_principal_id='principal-admin',
        administrative_override=True,
        administrative_owner_principal_id=bob.id,
    )

    assert resolved.owner_principal_id == bob.id
