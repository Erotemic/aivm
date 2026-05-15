"""Tests for test store."""

from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.store import (
    AttachmentEntry,
    Store,
    find_attachment,
    find_attachment_for_vm,
    find_attachments,
    find_attachments_for_vm,
    find_vm,
    load_store,
    remove_attachment,
    save_store,
    upsert_attachment,
    upsert_vm,
)


def test_store_roundtrip(tmp_path: Path) -> None:
    store = Store()
    store.defaults = AgentVMConfig()
    store.defaults.vm.cpus = 2
    store.behavior.yes_sudo = True
    store.behavior.auto_approve_readonly_sudo = False
    store.behavior.verbose = 4
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-b'
    upsert_vm(store, cfg)
    cfg.vm.name = 'vm-a'
    upsert_vm(store, cfg)
    store.attachments.append(
        AttachmentEntry(host_path='/tmp/z', vm_name='vm-b', mode='shared')
    )
    store.attachments.append(
        AttachmentEntry(host_path='/tmp/a', vm_name='vm-a', mode='shared')
    )
    fpath = tmp_path / 'config.toml'
    save_store(store, fpath)

    loaded = load_store(fpath)
    assert loaded.defaults is not None
    assert loaded.defaults.vm.cpus == 2
    assert loaded.behavior.yes_sudo is True
    assert loaded.behavior.auto_approve_readonly_sudo is False
    assert loaded.behavior.verbose == 4
    assert [v.name for v in loaded.vms] == ['vm-a', 'vm-b']
    assert [a.host_path for a in loaded.attachments] == ['/tmp/a', '/tmp/z']
    assert find_vm(loaded, 'vm-a') is not None
    assert find_vm(loaded, 'missing') is None


def test_save_store_logs_reason(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    store = Store()
    store.defaults = AgentVMConfig()
    messages: list[str] = []

    def fake_info(fmt: str, *args: object) -> None:
        messages.append(fmt.format(*args))

    monkeypatch.setattr('aivm.store.log.info', fake_info)
    save_store(
        store,
        tmp_path / 'config.toml',
        reason='Persist runtime defaults after config hydration.',
    )

    assert messages == [
        f'Writing config store to {tmp_path / "config.toml"}',
        '  Reason: Persist runtime defaults after config hydration.',
    ]


def test_upsert_attachment_allows_multiple_vms_for_same_host(
    tmp_path: Path,
) -> None:
    store = Store()
    host = tmp_path / 'project'
    host.mkdir()
    upsert_attachment(store, host_path=host, vm_name='vm1')
    upsert_attachment(store, host_path=host, vm_name='vm2')

    atts = find_attachments(store, host)
    assert sorted(att.vm_name for att in atts) == ['vm1', 'vm2']

    vm2 = find_attachment_for_vm(store, host, 'vm2')
    assert vm2 is not None
    assert vm2.vm_name == 'vm2'

    att = find_attachment(store, host)
    assert att is not None
    assert att.vm_name in {'vm1', 'vm2'}


def test_find_attachments_for_vm_returns_sorted_entries(tmp_path: Path) -> None:
    store = Store()
    host_a = tmp_path / 'a'
    host_b = tmp_path / 'b'
    host_a.mkdir()
    host_b.mkdir()
    upsert_attachment(store, host_path=host_b, vm_name='vm1', tag='tag-b')
    upsert_attachment(store, host_path=host_a, vm_name='vm1', tag='tag-a')
    upsert_attachment(store, host_path=host_b, vm_name='vm2', tag='tag-c')

    atts = find_attachments_for_vm(store, 'vm1')

    assert [att.host_path for att in atts] == [
        str(host_a.resolve()),
        str(host_b.resolve()),
    ]


def test_remove_attachment_removes_single_vm_mapping(tmp_path: Path) -> None:
    store = Store()
    host = tmp_path / 'project'
    host.mkdir()
    upsert_attachment(store, host_path=host, vm_name='vm1')
    upsert_attachment(store, host_path=host, vm_name='vm2')

    changed = remove_attachment(store, host_path=host, vm_name='vm1')

    assert changed is True
    remaining = find_attachments(store, host)
    assert len(remaining) == 1
    assert remaining[0].vm_name == 'vm2'


def test_parse_nested_vm_attachments_equivalent_to_global(tmp_path: Path) -> None:
    """The future split-friendly nested schema keeps the flat model."""
    project = tmp_path / 'project'
    project.mkdir()
    text = f'''
schema_version = 5
active_vm = "vm-a"

[[vms]]
name = "vm-a"
network_name = "aivm-net"

[vms.vm]
cpus = 4

[[vms.attachments]]
host_path = "{project}"
mode = "shared-root"
access = "rw"
guest_dst = "/home/agent/code/project"
tag = "aivm-project"
host_lexical_path = "~/code/project"
'''
    from aivm.store import parse_store_toml

    store = parse_store_toml(text)

    assert [vm.name for vm in store.vms] == ['vm-a']
    assert len(store.attachments) == 1
    att = store.attachments[0]
    assert att.vm_name == 'vm-a'
    assert att.host_path == str(project.resolve())
    assert att.mode == 'shared-root'
    assert att.guest_dst == '/home/agent/code/project'
    assert att.tag == 'aivm-project'
    assert att.host_lexical_path == '~/code/project'
    assert find_attachments_for_vm(store, 'vm-a') == [att]


def test_render_nested_vm_attachments_roundtrip(tmp_path: Path) -> None:
    """Nested rendering emits [[vms.attachments]] and parses back flat."""
    project = tmp_path / 'project'
    project.mkdir()
    store = Store()
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=project,
        vm_name='vm-a',
        mode='shared-root',
        guest_dst='/home/agent/code/project',
        tag='tag-a',
    )
    from aivm.store import parse_store_toml, render_store_toml

    text = render_store_toml(store, attachment_style='nested')
    assert '[[vms.attachments]]' in text
    assert '[[attachments]]' not in text
    assert 'vm_name =' not in text

    loaded = parse_store_toml(text)
    assert [vm.name for vm in loaded.vms] == ['vm-a']
    assert len(loaded.attachments) == 1
    assert loaded.attachments[0].vm_name == 'vm-a'
    assert loaded.attachments[0].host_path == str(project.resolve())
    assert loaded.attachments[0].mode == 'shared-root'


def test_nested_attachment_rejects_conflicting_vm_name(tmp_path: Path) -> None:
    """Nested ownership should not silently disagree with vm_name."""
    project = tmp_path / 'project'
    project.mkdir()
    text = f'''
[[vms]]
name = "vm-a"
network_name = "aivm-net"

[[vms.attachments]]
vm_name = "vm-b"
host_path = "{project}"
'''
    from pytest import raises
    from aivm.store import parse_store_toml

    with raises(ValueError, match='vm_name mismatch'):
        parse_store_toml(text)
