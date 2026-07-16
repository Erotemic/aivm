"""Regression tests for retained image pins and fail-fast downloads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.config import (
    DEFAULT_UBUNTU_NOBLE_IMG_URL,
    LEGACY_UBUNTU_NOBLE_IMG_URL,
    SUPPORTED_IMAGE_SHA256,
    AgentVMConfig,
)
from aivm.vm.images import fetch_image
from tests.helpers import FakeProc, activate_manager


def _normalized_command(cmd: list[str]) -> list[str]:
    normalized = [str(part) for part in cmd]
    if normalized[:2] == ['sudo', '-n']:
        return normalized[2:]
    if normalized[:1] == ['sudo']:
        return normalized[1:]
    return normalized


def test_default_image_uses_retained_release_archive() -> None:
    assert '/releases/noble/release-20260225/' in DEFAULT_UBUNTU_NOBLE_IMG_URL
    assert DEFAULT_UBUNTU_NOBLE_IMG_URL.endswith(
        '/ubuntu-24.04-server-cloudimg-amd64.img'
    )
    assert SUPPORTED_IMAGE_SHA256[DEFAULT_UBUNTU_NOBLE_IMG_URL] == (
        '7aa6d9f5e8a3a55c7445b138d31a73d1187871211b2b7da9da2e1a6cbf169b21'
    )


def test_legacy_daily_url_is_repaired_before_download(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    activate_manager(monkeypatch)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(tmp_path)
    cfg.image.ubuntu_img_url = LEGACY_UBUNTU_NOBLE_IMG_URL
    monkeypatch.setattr('aivm.vm.images._sudo_file_exists', lambda path: False)
    monkeypatch.setattr(
        'aivm.vm.images._ensure_qemu_access', lambda *args, **kwargs: None
    )
    calls: list[list[str]] = []
    expected = SUPPORTED_IMAGE_SHA256[DEFAULT_UBUNTU_NOBLE_IMG_URL]

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        normalized = _normalized_command(cmd)
        calls.append(normalized)
        if normalized[:1] == ['sha256sum']:
            return FakeProc(0, f'{expected}  {normalized[-1]}\n', '')
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)

    fetch_image(cfg)

    curl = next(command for command in calls if command[:1] == ['curl'])
    assert DEFAULT_UBUNTU_NOBLE_IMG_URL in curl
    assert LEGACY_UBUNTU_NOBLE_IMG_URL not in curl
    assert cfg.image.ubuntu_img_url == DEFAULT_UBUNTU_NOBLE_IMG_URL


def test_failed_download_never_promotes_or_hashes_staging_file(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    activate_manager(monkeypatch)
    cfg = AgentVMConfig()
    cfg.vm.name = 'vmx'
    cfg.paths.base_dir = str(tmp_path)
    monkeypatch.setattr('aivm.vm.images._sudo_file_exists', lambda path: False)
    monkeypatch.setattr(
        'aivm.vm.images._ensure_qemu_access', lambda *args, **kwargs: None
    )
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        normalized = _normalized_command(cmd)
        calls.append(normalized)
        if normalized[:1] == ['curl']:
            return FakeProc(22, '', 'curl: (22) HTTP response code said error')
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)

    with pytest.raises(RuntimeError, match='stopped before the staging file'):
        fetch_image(cfg)

    assert any(command[:1] == ['curl'] for command in calls)
    assert not any(command[:1] == ['mv'] for command in calls)
    assert not any(command[:1] == ['sha256sum'] for command in calls)
