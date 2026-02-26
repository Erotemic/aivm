from __future__ import annotations

from pathlib import Path

import pytest

from aivm.config import AgentVMConfig
from aivm.registry import (
    AttachmentRecord,
    GlobalRegistry,
    find_attachment,
    find_vm,
    load_registry,
    read_dir_metadata,
    save_registry,
    upsert_attachment,
    upsert_vm,
    write_dir_metadata,
)


def test_registry_roundtrip(tmp_path: Path) -> None:
    reg = GlobalRegistry()
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-b'
    upsert_vm(
        reg, cfg, tmp_path / 'b.toml', global_cfg_path=tmp_path / 'b.global'
    )
    cfg.vm.name = 'vm-a'
    upsert_vm(
        reg, cfg, tmp_path / 'a.toml', global_cfg_path=tmp_path / 'a.global'
    )
    reg.attachments.append(
        AttachmentRecord(host_path='/tmp/z', vm_name='vm-b', mode='shared')
    )
    reg.attachments.append(
        AttachmentRecord(host_path='/tmp/a', vm_name='vm-a', mode='shared')
    )
    fpath = tmp_path / 'registry.toml'
    save_registry(reg, fpath)

    loaded = load_registry(fpath)
    assert [v.name for v in loaded.vms] == ['vm-a', 'vm-b']
    assert [a.host_path for a in loaded.attachments] == ['/tmp/a', '/tmp/z']
    assert find_vm(loaded, 'vm-a') is not None
    assert find_vm(loaded, 'missing') is None


def test_upsert_attachment_conflict_and_force(tmp_path: Path) -> None:
    reg = GlobalRegistry()
    host = tmp_path / 'project'
    host.mkdir()
    upsert_attachment(reg, host_path=host, vm_name='vm1')
    with pytest.raises(RuntimeError):
        upsert_attachment(reg, host_path=host, vm_name='vm2')
    upsert_attachment(reg, host_path=host, vm_name='vm2', force=True)
    att = find_attachment(reg, host)
    assert att is not None
    assert att.vm_name == 'vm2'


def test_dir_metadata_read_write(tmp_path: Path) -> None:
    dpath = tmp_path / 'repo'
    dpath.mkdir()
    meta = write_dir_metadata(dpath, vm_name='vmx', config_path='/x/cfg.toml')
    assert meta.exists()
    raw = read_dir_metadata(dpath)
    assert raw['vm_name'] == 'vmx'
    assert raw['config_path'] == '/x/cfg.toml'
