"""Host-side access preparation for qemu and share binds.

Covers ``aivm.vm.host_access``: that granting qemu access after a
shared-root bind does not recursively re-own the VM base root, and that
the local ``stat`` probe answers present/absent decisively while
reporting EACCES as inconclusive so callers know to retry with sudo.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pytest import MonkeyPatch

from aivm.attachments.shared_root import _ensure_shared_root_host_bind
from aivm.config import AgentVMConfig
from aivm.util import CmdResult
from aivm.vm import ResolvedAttachment
from aivm.vm.host_access import _ensure_qemu_access, _local_stat_answer
from aivm.vm.share import AttachmentAccess, AttachmentMode
from tests.helpers import FakeProc, activate_manager, command_recorder


def test_qemu_access_does_not_recurse_vm_root_after_shared_root_bind(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Granting qemu access must not re-chown the whole VM base root."""
    activate_manager(monkeypatch)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-bind-safe'
    cfg.paths.base_dir = str(tmp_path / 'base')
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        access=AttachmentAccess.RW,
        source_dir=str(source_dir.resolve()),
        guest_dst='/workspace/source',
        tag='hostcode-source',
    )
    run_calls: list[list[str]] = []

    def fake_run_cmd(self: object, cmd: list[str], **kwargs: Any) -> CmdResult:
        del kwargs
        run_calls.append([str(part) for part in cmd])
        if cmd[:2] == ['getent', 'group']:
            return CmdResult(0, 'libvirt-qemu:x:1:\n', '')
        return CmdResult(0, '', '')

    monkeypatch.setattr('aivm.vm.lifecycle.CommandManager.run', fake_run_cmd)
    rec = command_recorder(
        monkeypatch, {'findmnt -n': FakeProc(1, '', '')}, default=FakeProc(0)
    )

    _ensure_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)
    _ensure_qemu_access(cfg, dry_run=False)

    command_text = [' '.join(c) for c in run_calls + rec.normalized]
    base_root = str(Path(cfg.paths.base_dir) / cfg.vm.name)
    assert any(f'mount --bind {source_dir}' in line for line in command_text)
    assert f'chown -R root:libvirt-qemu {base_root}' not in command_text
    assert f'chown -R root:kvm {base_root}' not in command_text


def test_local_stat_answer_tristate(tmp_path: Path) -> None:
    """Local stat is authoritative for present/absent, inconclusive on EACCES.

    Regression: a root-only image directory made ``aivm status`` crash with
    PermissionError because Path.is_file() raises when a parent directory is
    not traversable; existence probes must treat that as "ask with sudo".
    """
    present = tmp_path / 'present.img'
    present.write_text('x', encoding='utf-8')
    assert _local_stat_answer(present, want_file=True) is True
    assert _local_stat_answer(tmp_path, want_file=True) is False
    assert _local_stat_answer(tmp_path, want_file=False) is True
    assert _local_stat_answer(tmp_path / 'missing', want_file=True) is False

    if os.geteuid() == 0:
        return  # root bypasses directory permissions; skip the EACCES leg
    locked = tmp_path / 'locked'
    locked.mkdir()
    inner = locked / 'file.img'
    inner.write_text('x', encoding='utf-8')
    locked.chmod(0o000)
    try:
        assert _local_stat_answer(inner, want_file=True) is None
    finally:
        locked.chmod(0o755)
