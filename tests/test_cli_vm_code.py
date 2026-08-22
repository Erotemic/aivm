"""Tests for ``aivm code`` SSH-aware fallback logic.

The pure local-launch detection rule and the tunnel orchestration seams are
exercised here without opening an editor or interactive SSH session.
"""

from __future__ import annotations

import shlex
from types import SimpleNamespace

import pytest

from aivm.cli.vm_connect import (
    _TUNNEL_TMUX_SESSION,
    _ensure_remote_tunnel_prerequisites,
    _print_remote_session_recipe,
    _remote_tunnel_name,
    _start_remote_tunnel_session,
    _vscode_can_open_locally,
)
from aivm.config import AgentVMConfig
from aivm.errors import AIVMError
from aivm.tunnel_helper import TUNNEL_HELPER_PATH
from tests.helpers import FakeCommandManager, resolved_test_context


def _scrub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        'SSH_CONNECTION',
        'SSH_CLIENT',
        'SSH_TTY',
        'VSCODE_IPC_HOOK_CLI',
    ):
        monkeypatch.delenv(var, raising=False)


def test_vscode_can_open_locally_when_local_and_code_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scrub_env(monkeypatch)
    monkeypatch.setattr(
        'aivm.cli.vm_connect.which', lambda name: '/usr/bin/code'
    )
    can, reason = _vscode_can_open_locally()
    assert can is True
    assert reason is None


def test_vscode_skipped_when_ssh_connection_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The user's primary case: ssh'd into a remote machine, no VS Code
    terminal wrapping the shell. Skip the launch and print recipe."""
    _scrub_env(monkeypatch)
    monkeypatch.setenv('SSH_CONNECTION', '10.0.0.1 22 10.0.0.2 49152')
    # `which('code')` could return either; SSH should take precedence.
    monkeypatch.setattr(
        'aivm.cli.vm_connect.which', lambda name: '/usr/bin/code'
    )
    can, reason = _vscode_can_open_locally()
    assert can is False
    assert 'SSH_CONNECTION' in (reason or '')


def test_vscode_skipped_when_inside_vscode_terminal_over_ssh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SSH_CONNECTION still wins over VSCODE_IPC_HOOK_CLI.

    The ``code`` IPC hook may be able to talk back to a local VS Code window,
    but the generated ``ssh-remote+<vm>`` target still needs a VM IP / SSH
    config alias that is reachable from the user's workstation. For a libvirt
    NAT VM on a remote hypervisor, that assumption is usually false.
    """
    _scrub_env(monkeypatch)
    monkeypatch.setenv('SSH_CONNECTION', '10.0.0.1 22 10.0.0.2 49152')
    monkeypatch.setenv('VSCODE_IPC_HOOK_CLI', '/run/user/1000/vscode-ipc.sock')
    monkeypatch.setattr(
        'aivm.cli.vm_connect.which', lambda name: '/usr/bin/code'
    )
    can, reason = _vscode_can_open_locally()
    assert can is False
    assert 'SSH_CONNECTION' in (reason or '')


def test_vscode_skipped_when_code_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scrub_env(monkeypatch)
    monkeypatch.setattr('aivm.cli.vm_connect.which', lambda name: None)
    can, reason = _vscode_can_open_locally()
    assert can is False
    assert '`code`' in (reason or '')


def test_remote_tunnel_name_uses_vm_and_hypervisor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = SimpleNamespace(vm=SimpleNamespace(name='aivm-2404', user='agent'))
    monkeypatch.setattr(
        'aivm.cli.vm_connect.socket.gethostname',
        lambda: 'builder.example.test',
    )
    assert _remote_tunnel_name(cfg) == 'aivm-2404-builder'


def test_remote_tunnel_name_preserves_host_qualified_vm_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = SimpleNamespace(
        vm=SimpleNamespace(name='aivm-2404-builder', user='agent')
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect.socket.gethostname', lambda: 'builder'
    )
    assert _remote_tunnel_name(cfg) == 'aivm-2404-builder'


def test_print_remote_session_recipe_includes_tunnel_command(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    cfg.vm.user = 'agent'
    context = resolved_test_context(
        cfg, host_user='joncrall', host_uid=1001, host_gid=1001
    )
    session = SimpleNamespace(
        ip='10.77.0.103',
        share_guest_dst='/home/joncrall/code/aivm',
        reg_path='/home/joncrall/.config/aivm/config.toml',
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect.socket.gethostname', lambda: 'builder'
    )
    _print_remote_session_recipe(
        context,
        session,
        ssh_cfg='~/.ssh/config',
        ssh_cfg_updated=True,
        reason='running in an SSH session (SSH_CONNECTION set)',
    )
    out = capsys.readouterr().out
    # User's primary remote-hypervisor case must prefer a VS Code tunnel,
    # because the VM IP usually lives behind libvirt NAT on the remote host.
    assert (
        'ssh aivm-2404 '
        "'cd /home/joncrall/code/aivm && "
        "code tunnel --name aivm-2404-builder --accept-server-license-terms'"
        in out
    )
    assert 'Remote - Tunnels extension' in out
    assert 'ms-vscode.remote-server' in out
    assert 'connect to: aivm-2404-builder' in out
    assert 'ProxyJump' in out
    assert 'ssh aivm-2404' in out
    # And report the basics they need to verify the session is ready.
    assert '10.77.0.103' in out
    assert 'agent' in out
    assert 'Tunnel:  aivm-2404-builder' in out
    # ssh_cfg_updated=True should be surfaced as host-local state.
    assert 'SSH entry updated on this host in ~/.ssh/config' in out



def test_tunnel_prerequisites_auto_install_only_missing_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    context = resolved_test_context(
        cfg, host_user='joncrall', host_uid=1001, host_gid=1001
    )
    reports = iter([('code',), ()])
    monkeypatch.setattr(
        'aivm.cli.vm_connect._remote_tunnel_missing_commands',
        lambda *a, **k: next(reports),
    )
    calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def fake_provision(
        received: AgentVMConfig,
        ip: str,
        *,
        packages: tuple[str, ...],
        tools: tuple[str, ...],
        dry_run: bool,
    ) -> None:
        assert received is context.effective_cfg
        assert ip == '10.77.0.103'
        assert dry_run is False
        calls.append((packages, tools))

    monkeypatch.setattr(
        'aivm.cli.vm_connect.provision_guest_requirements', fake_provision
    )
    _ensure_remote_tunnel_prerequisites(context, '10.77.0.103')
    assert calls == [((), ('code',))]


def test_tunnel_prerequisites_auto_install_tmux_and_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    context = resolved_test_context(
        cfg, host_user='joncrall', host_uid=1001, host_gid=1001
    )
    reports = iter([('tmux', 'code'), ()])
    monkeypatch.setattr(
        'aivm.cli.vm_connect._remote_tunnel_missing_commands',
        lambda *a, **k: next(reports),
    )
    calls: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def fake_provision(
        cfg: AgentVMConfig,
        ip: str,
        *,
        packages: tuple[str, ...],
        tools: tuple[str, ...],
        dry_run: bool,
    ) -> None:
        del cfg, ip, dry_run
        calls.append((packages, tools))

    monkeypatch.setattr(
        'aivm.cli.vm_connect.provision_guest_requirements', fake_provision
    )
    _ensure_remote_tunnel_prerequisites(context, '10.77.0.103')
    assert calls == [(('tmux',), ('code',))]


def test_tunnel_prerequisites_respect_disabled_provisioning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    cfg.provision.enabled = False
    context = resolved_test_context(
        cfg, host_user='joncrall', host_uid=1001, host_gid=1001
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._remote_tunnel_missing_commands',
        lambda *a, **k: ('code',),
    )
    with pytest.raises(AIVMError, match='provisioning is disabled'):
        _ensure_remote_tunnel_prerequisites(context, '10.77.0.103')


def test_start_remote_tunnel_invokes_inspectable_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    context = resolved_test_context(
        cfg, host_user='joncrall', host_uid=1001, host_gid=1001
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._ensure_guest_tunnel_helper', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._ensure_remote_tunnel_prerequisites',
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect.require_ssh_identity',
        lambda path: '/tmp/id_ed25519',
    )
    manager = FakeCommandManager()
    monkeypatch.setattr(
        'aivm.cli.vm_connect.CommandManager.current', lambda: manager
    )

    guest_path = '/home/agent/projects/has space; still-safe'
    _start_remote_tunnel_session(
        context,
        '10.77.0.103',
        guest_path,
        'aivm-2404-builder',
    )

    assert len(manager.calls) == 1
    remote = str(manager.calls[0][-1])
    assert shlex.split(remote) == [
        TUNNEL_HELPER_PATH,
        'start',
        '--guest-path',
        guest_path,
        '--name',
        'aivm-2404-builder',
        '--session',
        _TUNNEL_TMUX_SESSION,
    ]
    assert '\n' not in remote
