"""Tests for ``aivm code`` SSH-aware fallback logic.

The pure detection rule lives in ``_vscode_can_open_locally``; that's
what we exercise here. The actual launch path (which would invoke
``code --remote``) is exercised manually on a workstation and is not
unit-testable without significant subprocess stubbing.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aivm.cli.vm_connect import (
    _TUNNEL_TMUX_SESSION,
    _build_tunnel_remote_script,
    _print_remote_session_recipe,
    _remote_tunnel_name,
    _vscode_can_open_locally,
)


def _scrub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'VSCODE_IPC_HOOK_CLI'):
        monkeypatch.delenv(var, raising=False)


def test_vscode_can_open_locally_when_local_and_code_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scrub_env(monkeypatch)
    monkeypatch.setattr('aivm.cli.vm_connect.which', lambda name: '/usr/bin/code')
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
    monkeypatch.setattr('aivm.cli.vm_connect.which', lambda name: '/usr/bin/code')
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
    monkeypatch.setattr('aivm.cli.vm_connect.which', lambda name: '/usr/bin/code')
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
    monkeypatch.setattr('aivm.cli.vm_connect.socket.gethostname', lambda: 'namek.kitware.com')
    assert _remote_tunnel_name(cfg) == 'aivm-2404-namek'


def test_print_remote_session_recipe_includes_tunnel_command(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = SimpleNamespace(vm=SimpleNamespace(name='aivm-2404', user='agent'))
    session = SimpleNamespace(
        ip='10.77.0.103',
        share_guest_dst='/home/joncrall/code/aivm',
        reg_path='/home/joncrall/.config/aivm/config.toml',
    )
    monkeypatch.setattr('aivm.cli.vm_connect.socket.gethostname', lambda: 'namek')
    _print_remote_session_recipe(
        cfg,
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
        "code tunnel --name aivm-2404-namek --accept-server-license-terms'"
        in out
    )
    assert 'Remote - Tunnels extension' in out
    assert 'ms-vscode.remote-server' in out
    assert 'connect to: aivm-2404-namek' in out
    assert 'ProxyJump' in out
    assert 'ssh aivm-2404' in out
    # And report the basics they need to verify the session is ready.
    assert '10.77.0.103' in out
    assert 'agent' in out
    assert 'Tunnel:  aivm-2404-namek' in out
    # ssh_cfg_updated=True should be surfaced as host-local state.
    assert 'SSH entry updated on this host in ~/.ssh/config' in out


def test_build_tunnel_remote_script_is_idempotent_and_uses_tmux() -> None:
    script = _build_tunnel_remote_script(
        guest_path='/home/agent/code/aivm',
        tunnel_name='aivm-2404-namek',
    )
    # Guard: required guest binaries.
    assert 'command -v tmux' in script
    assert 'command -v code' in script
    # Idempotency: existing session is a no-op.
    assert f'tmux has-session -t {_TUNNEL_TMUX_SESSION}' in script
    # New session command runs `code tunnel` in the share dir.
    assert f'tmux new-session -d -s {_TUNNEL_TMUX_SESSION}' in script
    assert 'cd /home/agent/code/aivm' in script
    assert 'code tunnel --name aivm-2404-namek --accept-server-license-terms' in script
    # Tunnel session name is the constant — must not vary by VM/host name.
    assert _TUNNEL_TMUX_SESSION == 'aivm-tunnel'


def test_build_tunnel_remote_script_quotes_unusual_paths() -> None:
    """Spaces or shell metachars in the share path must not break the script."""
    script = _build_tunnel_remote_script(
        guest_path="/home/agent/projects/has space; rm -rf /tmp",
        tunnel_name='aivm-2404-namek',
    )
    # The path appears only as a single shell-quoted argument to ``cd``.
    assert "'/home/agent/projects/has space; rm -rf /tmp'" in script
    # And there is no unquoted occurrence of the injection payload.
    assert 'rm -rf /tmp\n' not in script
