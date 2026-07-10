"""Virtiofs share inspection and in-guest mount helpers.

Covers ``aivm.vm.share``: reading share mappings and shared-memory
backing out of the domain XML, treating an already-attached mapping as
satisfied, and the retry/read-only behavior of ``ensure_share_mounted``
when it drives the ``mount`` inside the guest over SSH.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.util import CmdResult
from aivm.vm import (
    attach_vm_share,
    ensure_share_mounted,
    vm_has_share,
    vm_has_virtiofs_shared_memory,
    vm_share_mappings,
)
from tests.helpers import FakeProc, activate_manager, command_recorder


def test_vm_share_helpers(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """Share probes read source/tag pairs from the domain filesystems."""
    source = tmp_path / 'src'
    source.mkdir()
    cfg = AgentVMConfig()
    source_dir = str(source)
    share_tag = 'hostcode-src'
    xml = f"""
<domain>
  <devices>
    <filesystem type='mount' accessmode='passthrough'>
      <driver type='virtiofs'/>
      <source dir='{source.resolve()}'/>
      <target dir='hostcode-src'/>
    </filesystem>
    <filesystem type='mount' accessmode='passthrough'>
      <driver type='virtio-9p'/>
      <source dir='/opt/other'/>
      <target dir='other'/>
    </filesystem>
  </devices>
</domain>
"""
    activate_manager(monkeypatch)
    command_recorder(monkeypatch, {'virsh dumpxml': FakeProc(0, xml, '')})
    assert vm_has_share(cfg, source_dir, share_tag, use_sudo=False) is True
    assert vm_share_mappings(cfg, use_sudo=False) == [
        (str(source.resolve()), 'hostcode-src'),
    ]


def test_vm_has_virtiofs_shared_memory(monkeypatch: MonkeyPatch) -> None:
    """Shared-memory backing is detected from ``<access mode='shared'/>``."""
    cfg = AgentVMConfig()
    xml_with_shared = """
<domain>
  <memoryBacking>
    <source type='memfd'/>
    <access mode='shared'/>
  </memoryBacking>
</domain>
"""
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch, {'virsh dumpxml': FakeProc(0, xml_with_shared, '')}
    )
    assert vm_has_virtiofs_shared_memory(cfg, use_sudo=False) is True

    xml_without_shared = '<domain><memoryBacking/></domain>'
    # Domain XML is cached on the manager between mutations, so start a
    # fresh manager to observe the changed XML.
    activate_manager(monkeypatch)
    command_recorder(
        monkeypatch, {'virsh dumpxml': FakeProc(0, xml_without_shared, '')}
    )
    assert vm_has_virtiofs_shared_memory(cfg, use_sudo=False) is False


def test_attach_vm_share_treats_existing_mapping_as_satisfied(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """An already-present mapping makes a failed live attach a no-op."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    source = tmp_path / 'src'
    source.mkdir()
    source_dir = str(source.resolve())
    tag = 'hostcode-src'

    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            'true': FakeProc(0, '', ''),
            'virsh domstate': FakeProc(0, 'running\n', ''),
            'virsh attach-device': FakeProc(
                1,
                '',
                'error: Requested operation is not valid: '
                'Target already exists',
            ),
        },
    )
    monkeypatch.setattr(
        'aivm.vm.share.vm_share_mappings',
        lambda *_a, **_k: [(source_dir, tag)],
    )

    attach_vm_share(cfg, source_dir, tag, dry_run=False)

    virsh_calls = [c for c in rec.normalized if c[:1] == ['virsh']]
    assert virsh_calls[0][:2] == ['virsh', 'domstate']
    assert virsh_calls[1][:2] == ['virsh', 'attach-device']


def test_ensure_share_mounted_retries_then_succeeds(
    monkeypatch: MonkeyPatch,
) -> None:
    """A transient mount failure is retried once, then succeeds."""
    cfg = AgentVMConfig()
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    calls = {'n': 0}
    sleeps: list[float] = []

    monkeypatch.setattr(
        'aivm.vm.share.require_ssh_identity', lambda p: p or '/tmp/id_ed25519'
    )
    monkeypatch.setattr(
        'aivm.vm.share.ssh_base_args', lambda *a, **k: ['-i', '/tmp/id_ed25519']
    )

    def fake_run_cmd(self: object, *a: object, **k: Any) -> CmdResult:
        del a, k
        calls['n'] += 1
        if calls['n'] == 1:
            return CmdResult(
                32,
                '',
                'mount: /workspace: wrong fs type, bad option',
            )
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.share.CommandManager.run', fake_run_cmd)
    monkeypatch.setattr('aivm.vm.share.time.sleep', lambda s: sleeps.append(s))
    ensure_share_mounted(
        cfg,
        '10.0.0.2',
        guest_dst='/workspace',
        tag='hostcode-workspace',
        dry_run=False,
    )
    assert calls['n'] == 2
    assert sleeps == [2.0]


def test_ensure_share_mounted_raises_after_retries(
    monkeypatch: MonkeyPatch,
) -> None:
    """A mount that never succeeds raises after exhausting its retries."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-share-fail'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    sleeps: list[float] = []

    monkeypatch.setattr(
        'aivm.vm.share.require_ssh_identity', lambda p: p or '/tmp/id_ed25519'
    )
    monkeypatch.setattr(
        'aivm.vm.share.ssh_base_args', lambda *a, **k: ['-i', '/tmp/id_ed25519']
    )
    monkeypatch.setattr(
        'aivm.vm.share.CommandManager.run',
        lambda self, *a, **k: CmdResult(
            32,
            '',
            'mount: /workspace: wrong fs type, bad option',
        ),
    )
    monkeypatch.setattr('aivm.vm.share.time.sleep', lambda s: sleeps.append(s))

    with pytest.raises(
        RuntimeError, match='Failed to mount shared folder inside guest'
    ):
        ensure_share_mounted(
            cfg,
            '10.0.0.2',
            guest_dst='/workspace',
            tag='hostcode-workspace',
            dry_run=False,
        )
    assert len(sleeps) == 11


def test_ensure_share_mounted_read_only_uses_ro_option(
    monkeypatch: MonkeyPatch,
) -> None:
    """A read-only share mounts virtiofs with the ``ro`` option."""
    cfg = AgentVMConfig()
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    cmds: list[list[str]] = []
    run_kwargs: list[dict] = []

    monkeypatch.setattr(
        'aivm.vm.share.require_ssh_identity', lambda p: p or '/tmp/id_ed25519'
    )
    monkeypatch.setattr(
        'aivm.vm.share.ssh_base_args', lambda *a, **k: ['-i', '/tmp/id_ed25519']
    )

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        cmds.append([str(c) for c in cmd])
        run_kwargs.append(dict(kwargs))
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.share.CommandManager.run', fake_run_cmd)

    ensure_share_mounted(
        cfg,
        '10.0.0.2',
        guest_dst='/workspace',
        tag='hostcode-workspace',
        read_only=True,
        dry_run=False,
    )

    assert len(cmds) == 1
    remote_script = cmds[0][-1]
    assert run_kwargs[0]['timeout'] == 20
    assert 'sudo -n mount -t virtiofs -o ro' in remote_script
    assert 'mount -t virtiofs -o ro' in remote_script
