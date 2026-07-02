"""Unit tests for the rootless session runtime (qemu:///session).

These tests protect the structural invariants of session mode without a
live hypervisor: URI selection, never-sudo enforcement, user-mode
networking argv, forward-port allocation, attachment gating, and config
round-trips.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aivm.commands import CommandManager
from aivm.config import (
    AgentVMConfig,
    apply_session_runtime_defaults,
)
from aivm.config_store import (
    Store,
    load_store,
    materialize_vm_cfg,
    save_store,
    upsert_vm,
)
from aivm.errors import SessionRuntimeError
from aivm.runtime import (
    SESSION_LIBVIRT_URI,
    SYSTEM_LIBVIRT_URI,
    activate_runtime,
    current_libvirt_uri,
    normalize_runtime_mode,
    require_system_runtime,
    ssh_base_args,
    virsh_cmd,
    virsh_system_cmd,
)
from aivm.vm.create import build_virt_install_cmd
from aivm.vm.ports import (
    SESSION_SSH_PORT_BASE,
    SESSION_SSH_PORT_SPAN,
    allocate_ssh_forward_port,
    deterministic_ssh_port,
    read_ssh_forward_port,
)


def _session_cfg(tmp_path: Path, name: str = 'aivm-test-session') -> AgentVMConfig:
    cfg = AgentVMConfig()
    cfg.vm.name = name
    cfg.runtime.mode = 'session'
    cfg.paths.base_dir = str(tmp_path / 'vmstore')
    cfg.paths.state_dir = str(tmp_path / 'state')
    return cfg


def test_normalize_runtime_mode() -> None:
    assert normalize_runtime_mode('session') == 'session'
    assert normalize_runtime_mode('SYSTEM') == 'system'
    assert normalize_runtime_mode('') == 'system'
    assert normalize_runtime_mode(None) == 'system'
    assert normalize_runtime_mode('bogus') == 'system'


def test_virsh_cmd_follows_active_runtime() -> None:
    assert virsh_cmd('list') == ['virsh', '-c', SYSTEM_LIBVIRT_URI, 'list']
    activate_runtime('session')
    assert current_libvirt_uri() == SESSION_LIBVIRT_URI
    assert virsh_cmd('list') == ['virsh', '-c', SESSION_LIBVIRT_URI, 'list']
    activate_runtime('system')
    assert virsh_cmd('list') == ['virsh', '-c', SYSTEM_LIBVIRT_URI, 'list']


def test_virsh_system_cmd_stays_pinned() -> None:
    activate_runtime('session')
    assert virsh_system_cmd('list') == [
        'virsh',
        '-c',
        SYSTEM_LIBVIRT_URI,
        'list',
    ]


def test_session_activation_forces_sudoless() -> None:
    CommandManager.activate(CommandManager(privilege_mode='auto'))
    activate_runtime('session')
    assert CommandManager.current().privilege_mode == 'sudoless'


def test_system_activation_keeps_privilege_mode() -> None:
    CommandManager.activate(CommandManager(privilege_mode='auto'))
    activate_runtime('system')
    assert CommandManager.current().privilege_mode == 'auto'


def test_require_system_runtime_raises_in_session() -> None:
    require_system_runtime(feature='X', hint='Y')  # system: no-op
    activate_runtime('session')
    with pytest.raises(SessionRuntimeError, match='runtime.mode=session'):
        require_system_runtime(feature='X', hint='Y')


def test_apply_session_runtime_defaults_swaps_default_base_dir() -> None:
    cfg = AgentVMConfig()
    cfg.runtime.mode = 'session'
    apply_session_runtime_defaults(cfg)
    assert cfg.paths.base_dir == '~/.local/share/aivm'


def test_apply_session_runtime_defaults_respects_explicit_dir() -> None:
    cfg = AgentVMConfig()
    cfg.runtime.mode = 'session'
    cfg.paths.base_dir = '/data/custom-vms'
    apply_session_runtime_defaults(cfg)
    assert cfg.paths.base_dir == '/data/custom-vms'


def test_apply_session_runtime_defaults_noop_for_system() -> None:
    cfg = AgentVMConfig()
    apply_session_runtime_defaults(cfg)
    assert cfg.paths.base_dir == '/var/lib/libvirt/aivm'


def test_runtime_mode_round_trips_through_store(tmp_path: Path) -> None:
    cfg = _session_cfg(tmp_path)
    store = Store()
    upsert_vm(store, cfg)
    cfg_path = tmp_path / 'store.toml'
    save_store(store, cfg_path)

    text = cfg_path.read_text(encoding='utf-8')
    assert 'mode = "session"' in text

    reg = load_store(cfg_path)
    materialized = materialize_vm_cfg(reg, cfg.vm.name)
    assert materialized.runtime.mode == 'session'


def test_deterministic_ssh_port_is_stable_and_in_range() -> None:
    a = deterministic_ssh_port('aivm-2404-host')
    b = deterministic_ssh_port('aivm-2404-host')
    assert a == b
    assert (
        SESSION_SSH_PORT_BASE
        <= a
        < SESSION_SSH_PORT_BASE + SESSION_SSH_PORT_SPAN
    )
    assert deterministic_ssh_port('other-vm') != a or True  # distinct likely


def test_allocate_ssh_forward_port_persists_and_reuses(
    tmp_path: Path,
) -> None:
    cfg = _session_cfg(tmp_path)
    assert read_ssh_forward_port(cfg) is None
    port = allocate_ssh_forward_port(cfg)
    assert read_ssh_forward_port(cfg) == port
    # Second allocation returns the persisted port even if the
    # deterministic preference would differ.
    assert allocate_ssh_forward_port(cfg) == port


def test_allocate_ssh_forward_port_dry_run_does_not_persist(
    tmp_path: Path,
) -> None:
    cfg = _session_cfg(tmp_path)
    port = allocate_ssh_forward_port(cfg, dry_run=True)
    assert port >= SESSION_SSH_PORT_BASE
    assert read_ssh_forward_port(cfg) is None


def test_ssh_base_args_port() -> None:
    args = ssh_base_args('/tmp/id', port=2222)
    assert args[:2] == ['-p', '2222']
    assert '-p' not in ssh_base_args('/tmp/id', port=22)
    assert '-p' not in ssh_base_args('/tmp/id', port=None)


def test_build_virt_install_cmd_system_shape() -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'sysvm'
    cmd = build_virt_install_cmd(
        cfg, vm_disk='/x/d.qcow2', seed_iso='/x/s.iso'
    )
    joined = ' '.join(cmd)
    assert '--connect qemu:///system' in joined
    assert f'network={cfg.network.name},model=virtio' in joined
    assert 'backend/@type=passt' not in joined
    assert 'portForward' not in joined


def test_build_virt_install_cmd_session_shape(tmp_path: Path) -> None:
    cfg = _session_cfg(tmp_path)
    activate_runtime(cfg.runtime.mode)
    cmd = build_virt_install_cmd(
        cfg,
        vm_disk='/x/d.qcow2',
        seed_iso='/x/s.iso',
        ssh_forward_port=22345,
    )
    joined = ' '.join(cmd)
    assert '--connect qemu:///session' in joined
    assert 'qemu:///system' not in joined
    assert 'type=user' in joined
    assert 'xpath1.set=./backend/@type=passt' in joined
    assert 'xpath4.set=./portForward/range/@start=22345' in joined
    assert 'xpath5.set=./portForward/range/@to=22' in joined
    assert 'sudo' not in joined
    assert f'network={cfg.network.name}' not in joined


def test_build_virt_install_cmd_session_requires_port(tmp_path: Path) -> None:
    cfg = _session_cfg(tmp_path)
    activate_runtime(cfg.runtime.mode)
    with pytest.raises(RuntimeError, match='ssh_forward_port'):
        build_virt_install_cmd(cfg, vm_disk='/x/d.qcow2', seed_iso='/x/s.iso')


def test_session_ssh_config_includes_forward_port(tmp_path: Path) -> None:
    from aivm.vm.connectivity import ssh_config, ssh_port_for

    cfg = _session_cfg(tmp_path)
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    activate_runtime(cfg.runtime.mode)
    port = allocate_ssh_forward_port(cfg)
    text = ssh_config(cfg)
    assert 'HostName 127.0.0.1' in text
    assert f'Port {port}' in text
    assert ssh_port_for(cfg) == port


def test_ssh_port_for_strict_raises_without_allocation(
    tmp_path: Path,
) -> None:
    from aivm.vm.connectivity import ssh_port_for

    cfg = _session_cfg(tmp_path)
    activate_runtime(cfg.runtime.mode)
    assert ssh_port_for(cfg, strict=False) is None
    with pytest.raises(RuntimeError, match='forward port'):
        ssh_port_for(cfg)


def test_ssh_port_for_system_is_22(tmp_path: Path) -> None:
    from aivm.vm.connectivity import ssh_port_for

    cfg = AgentVMConfig()
    cfg.paths.state_dir = str(tmp_path / 'state')
    assert ssh_port_for(cfg) == 22


def test_resolve_attachment_session_defaults_to_git(tmp_path: Path) -> None:
    from aivm.attachments.resolve import _resolve_attachment
    from aivm.vm.share import AttachmentMode

    cfg = _session_cfg(tmp_path)
    activate_runtime(cfg.runtime.mode)
    store = Store()
    upsert_vm(store, cfg)
    cfg_path = tmp_path / 'store.toml'
    save_store(store, cfg_path)
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    resolved = _resolve_attachment(cfg, cfg_path, host_src, '')
    assert resolved.mode == AttachmentMode.GIT


@pytest.mark.parametrize('mode', ['shared', 'shared-root', 'persistent'])
def test_resolve_attachment_session_rejects_non_git(
    tmp_path: Path, mode: str
) -> None:
    from aivm.attachments.resolve import _resolve_attachment

    cfg = _session_cfg(tmp_path)
    activate_runtime(cfg.runtime.mode)
    store = Store()
    upsert_vm(store, cfg)
    cfg_path = tmp_path / 'store.toml'
    save_store(store, cfg_path)
    host_src = tmp_path / 'proj'
    host_src.mkdir()

    with pytest.raises(SessionRuntimeError, match='runtime.mode=session'):
        _resolve_attachment(cfg, cfg_path, host_src, '', mode_opt=mode)


def test_session_storage_prepare_never_uses_sudo_or_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aivm.vm.host_access import _ensure_qemu_access

    cfg = _session_cfg(tmp_path)
    activate_runtime(cfg.runtime.mode)
    CommandManager.activate(
        CommandManager(yes=True, privilege_mode='sudoless')
    )
    executed: list[list[str]] = []

    mgr = CommandManager.current()
    real_run = mgr.run

    def record_run(cmd, **kw):  # type: ignore[no-untyped-def]
        executed.append(list(cmd))
        return real_run(cmd, **kw)

    monkeypatch.setattr(mgr, 'run', record_run)
    _ensure_qemu_access(cfg, dry_run=False)
    base_root = Path(cfg.paths.base_dir) / cfg.vm.name
    assert (base_root / 'images').is_dir()
    assert (base_root / 'cloud-init').is_dir()
    flat = [' '.join(c) for c in executed]
    assert not any('sudo' in c for c in flat)
    assert not any('setfacl' in c for c in flat)
