"""Shared-root repair behavior for hosts created before 0.6.0."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aivm.attachments.shared_root import _ensure_shared_root_host_bind
from aivm.config import AgentVMConfig
from aivm.vm.share import AttachmentAccess, AttachmentMode, ResolvedAttachment
from tests.helpers import FakeProc, activate_manager, command_recorder


def test_shared_root_host_bind_escalates_into_a_legacy_root_owned_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pre-existing root-owned export root still escalates the child mkdir.

    Hosts created before storage moved under the user keep a root-owned
    ``<base_dir>/<vm>/shared-root``. The decision is per-path, so the export
    root is skipped (it exists) and the per-project target below it still
    escalates. Simulated with a directory the invoking user owns but cannot
    write, which is what ``os.access(W_OK)`` reports for a root-owned one.
    """
    if os.geteuid() == 0:
        pytest.skip('root can write through any mode bits')

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-legacy'
    cfg.paths.base_dir = str(tmp_path / 'base')
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        source_dir=str(source_dir.resolve()),
        guest_dst='/workspace/source',
        tag='hostcode-source',
        access=AttachmentAccess.RW,
    )
    export_root = Path(cfg.paths.base_dir) / cfg.vm.name / 'shared-root'
    export_root.mkdir(parents=True)
    export_root.chmod(0o555)

    activate_manager(monkeypatch, yes_sudo=True, yes=True)
    rec = command_recorder(
        monkeypatch,
        {'findmnt -P -n': FakeProc(1)},
        default=FakeProc(0),
    )
    try:
        _ensure_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)
    finally:
        export_root.chmod(0o755)

    joined = [' '.join(p) for p in rec.calls]
    # The export root already exists, so no mkdir is issued for it at all.
    assert not any(
        line.endswith(str(export_root)) for line in joined if 'mkdir' in line
    )
    # The project target below it is unwritable, so its mkdir escalates.
    assert any(
        line.startswith('sudo')
        and 'mkdir -p' in line
        and 'hostcode-source' in line
        for line in joined
    ), rec.calls
