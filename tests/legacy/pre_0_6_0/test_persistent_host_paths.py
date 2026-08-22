"""Persistent replay paths retained for pre-0.6.0 user stores."""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.attachments.persistent import _persistent_host_manifest_path
from aivm.config import AgentVMConfig


def test_persistent_host_manifest_path_uses_app_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-persistent-app-data'
    cfg.paths.base_dir = '/var/lib/libvirt/aivm/aivm-2404'

    calls: list[tuple[str, str, int]] = []

    def fake_user_app_dir(
        appname: str, kind: str, *, mode: int = 0o777
    ) -> Path:
        calls.append((appname, kind, mode))
        return tmp_path / kind

    monkeypatch.setattr(
        'aivm.legacy.pre_0_6_0.paths.user_app_dir',
        fake_user_app_dir,
    )

    path = _persistent_host_manifest_path(cfg)

    assert calls == [('aivm', 'data', 0o700)]
    assert (
        path
        == tmp_path
        / 'data'
        / cfg.vm.name
        / 'state'
        / 'persistent-attachments.json'
    )
    assert str(cfg.paths.base_dir) not in str(path)
