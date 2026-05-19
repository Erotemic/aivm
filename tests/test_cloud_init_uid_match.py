"""Tests for host UID/GID matching baked into the cloud-init user-data."""

from __future__ import annotations

import pytest

from aivm.config import AgentVMConfig
from aivm.vm.cloudinit import _invoking_host_uid_gid, _render_user_data_text


# -- SUDO_UID/SUDO_GID resolution ------------------------------------------


def test_invoking_host_uid_gid_prefers_sudo_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('SUDO_UID', '12345')
    monkeypatch.setenv('SUDO_GID', '54321')
    assert _invoking_host_uid_gid() == (12345, 54321)


def test_invoking_host_uid_gid_falls_back_to_process_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv('SUDO_UID', raising=False)
    monkeypatch.delenv('SUDO_GID', raising=False)
    monkeypatch.setattr('aivm.vm.cloudinit.os.getuid', lambda: 4242)
    monkeypatch.setattr('aivm.vm.cloudinit.os.getgid', lambda: 4243)
    assert _invoking_host_uid_gid() == (4242, 4243)


def test_invoking_host_uid_gid_ignores_non_numeric_sudo_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('SUDO_UID', 'nope')
    monkeypatch.setenv('SUDO_GID', '')
    monkeypatch.setattr('aivm.vm.cloudinit.os.getuid', lambda: 7)
    monkeypatch.setattr('aivm.vm.cloudinit.os.getgid', lambda: 8)
    assert _invoking_host_uid_gid() == (7, 8)


# -- cloud-init user-data rendering ----------------------------------------


def _render_with_uid(
    monkeypatch: pytest.MonkeyPatch,
    *,
    host_uid: int,
    host_gid: int,
    cfg: AgentVMConfig | None = None,
) -> str:
    cfg = cfg or AgentVMConfig()
    monkeypatch.setattr(
        'aivm.vm.cloudinit._invoking_host_uid_gid',
        lambda: (host_uid, host_gid),
    )
    monkeypatch.setattr(
        'aivm.vm.cloudinit.detect_host_timezone', lambda: ''
    )
    return _render_user_data_text(cfg, pubkey='ssh-ed25519 AAAA test')


def test_render_user_data_emits_uid_when_match_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.match_host_user_ids = True
    text = _render_with_uid(monkeypatch, host_uid=692586045, host_gid=692584961, cfg=cfg)
    assert 'uid: 692586045' in text
    assert 'groupmod -g 692584961 agent' in text
    assert 'groupadd -g 692584961 agent' in text
    assert 'chown -R 692586045:692584961 /home/agent' in text


def test_render_user_data_omits_uid_when_match_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.match_host_user_ids = False
    text = _render_with_uid(monkeypatch, host_uid=1234, host_gid=5678, cfg=cfg)
    assert 'uid: 1234' not in text
    assert 'groupmod' not in text
    assert 'groupadd' not in text
    assert 'chown -R' not in text


def test_render_user_data_skips_match_when_host_uid_is_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse to bake uid: 0 into the guest account (that's root)."""
    cfg = AgentVMConfig()
    cfg.vm.match_host_user_ids = True
    text = _render_with_uid(monkeypatch, host_uid=0, host_gid=0, cfg=cfg)
    assert 'uid: 0' not in text
    assert 'groupmod' not in text
    assert 'chown -R 0:0' not in text


def test_render_user_data_respects_custom_guest_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.user = 'devuser'
    cfg.vm.match_host_user_ids = True
    text = _render_with_uid(monkeypatch, host_uid=2001, host_gid=3001, cfg=cfg)
    assert '- name: devuser' in text
    assert 'groupmod -g 3001 devuser' in text
    assert 'chown -R 2001:3001 /home/devuser' in text
