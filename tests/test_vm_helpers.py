"""Tests for test vm helpers."""

from __future__ import annotations

from pathlib import Path

from aivm.config import AgentVMConfig
from aivm.util import CmdError, CmdResult
from aivm.vm import (
    _mac_for_vm,
    create_or_start_vm,
    get_ip_cached,
    vm_has_share,
    vm_share_mappings,
)


def test_mac_for_vm_parsing(monkeypatch) -> None:
    stdout = """
 Interface   Type      Source     Model    MAC
---------------------------------------------------------------
 vnet0       network   default    virtio   52:54:00:12:34:56
"""
    monkeypatch.setattr(
        'aivm.vm.lifecycle.run_cmd', lambda *a, **k: CmdResult(0, stdout, '')
    )
    cfg = AgentVMConfig()
    assert _mac_for_vm(cfg) == '52:54:00:12:34:56'


def test_get_ip_cached(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.state_dir = str(tmp_path)
    ip_dir = tmp_path / 'vmx'
    ip_dir.mkdir()
    (ip_dir / 'vmx.ip').write_text('10.77.0.123\n', encoding='utf-8')
    assert get_ip_cached(cfg) == '10.77.0.123'


def test_vm_share_helpers(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / 'src'
    source.mkdir()
    cfg = AgentVMConfig()
    cfg.share.enabled = True
    cfg.share.host_src = str(source)
    cfg.share.tag = 'hostcode-src'
    xml = f"""
<domain>
  <devices>
    <filesystem type='mount' accessmode='passthrough'>
      <source dir='{source.resolve()}'/>
      <target dir='hostcode-src'/>
    </filesystem>
    <filesystem type='mount' accessmode='passthrough'>
      <source dir='/opt/other'/>
      <target dir='other'/>
    </filesystem>
  </devices>
</domain>
"""
    monkeypatch.setattr(
        'aivm.vm.share.run_cmd', lambda *a, **k: CmdResult(0, xml, '')
    )
    assert vm_has_share(cfg, use_sudo=False) is True
    assert vm_share_mappings(cfg, use_sudo=False) == [
        (str(source.resolve()), 'hostcode-src'),
        ('/opt/other', 'other'),
    ]


def test_create_vm_fallback_when_uefi_firmware_missing(monkeypatch) -> None:
    cfg = AgentVMConfig()
    cfg.share.enabled = False
    monkeypatch.setattr('aivm.vm.lifecycle.vm_exists', lambda *a, **k: False)
    monkeypatch.setattr(
        'aivm.vm.lifecycle.fetch_image', lambda *a, **k: Path('/tmp/base.img')
    )
    monkeypatch.setattr(
        'aivm.vm.lifecycle._write_cloud_init',
        lambda *a, **k: {'seed_iso': Path('/tmp/seed.iso')},
    )
    monkeypatch.setattr(
        'aivm.vm.lifecycle._ensure_disk', lambda *a, **k: Path('/tmp/vm.qcow2')
    )

    calls = []

    def fake_run_cmd(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == 'virt-install' and '--boot' in cmd:
            raise CmdError(
                cmd,
                CmdResult(
                    1,
                    '',
                    "ERROR    Did not find any UEFI binary path for arch 'x86_64'",
                ),
            )
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.run_cmd', fake_run_cmd)
    create_or_start_vm(cfg, dry_run=False, recreate=False)

    virt_calls = [c for c in calls if c and c[0] == 'virt-install']
    assert len(virt_calls) == 2
    assert '--boot' in virt_calls[0]
    assert '--boot' not in virt_calls[1]
