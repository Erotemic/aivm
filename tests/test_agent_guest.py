"""Guest routing for independent ssh-agent repository credentials."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from aivm.config import AgentVMConfig
from aivm.config_store import AgentCredentialEntry
from aivm.credentials import agent_guest, guest_config
from aivm.credentials.agent_guest import (
    probe_repository_access,
    reconcile_guest_agent_credentials,
    render_git_config,
    render_ssh_config,
)
from aivm.credentials.agent_schema import agent_credential_id
from aivm.credentials.guest_config import guest_ssh_command
from tests.helpers import FakeCommandManager


def _entry() -> AgentCredentialEntry:
    vm_name = 'aivm-2404'
    principal_id = 'principal-test'
    canonical = 'github.com/erotemic/aivm'
    return AgentCredentialEntry(
        id=agent_credential_id(vm_name, canonical, principal_id),
        vm_name=vm_name,
        principal_id=principal_id,
        provider_host='github.com',
        owner='Erotemic',
        repository='aivm',
        access='write',
        provider_key_id='123',
        provider_key_title='test-agent-key',
        key_fingerprint='SHA256:example',
        state='active',
    )


def test_agent_guest_routing_uses_public_key_selector() -> None:
    entry = _entry()
    ssh = render_ssh_config([entry])
    git = render_git_config([entry])

    alias = f'aivm-agent-cred-{entry.id}'
    assert f'Host {alias}' in ssh
    assert 'HostName github.com' in ssh
    assert (
        f'IdentityFile ~/.local/share/aivm/agent-credentials/{entry.id}/'
        'id_ed25519.pub'
    ) in ssh
    assert 'IdentitiesOnly yes' in ssh
    assert 'id_ed25519\n' not in ssh
    assert f'[url "git@{alias}:Erotemic/aivm.git"]' in git
    assert 'insteadOf = git@github.com:Erotemic/aivm.git' in git
    assert 'insteadOf = https://github.com/Erotemic/aivm.git' in git


def test_guest_ssh_command_forwards_only_named_agent_socket(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = str(tmp_path / 'vm-login-key')
    socket_path = tmp_path / 'dedicated-agent.sock'

    cmd = guest_ssh_command(
        cfg,
        '10.77.0.195',
        'ssh-add -l -E sha256',
        forward_agent_socket=socket_path,
    )

    assert cmd[:4] == [
        'env',
        f'SSH_AUTH_SOCK={socket_path}',
        'ssh',
        '-A',
    ]
    assert not any(part.startswith('ForwardAgent=') for part in cmd)
    assert cmd[-2:] == ['agent@10.77.0.195', 'ssh-add -l -E sha256']

def test_guest_selector_is_private_mode_for_openssh(monkeypatch) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    entry = _entry()
    installed: list[tuple[str, str]] = []

    monkeypatch.setattr(agent_guest, 'ensure_guest_managed_includes', lambda *a, **k: None)
    monkeypatch.setattr(agent_guest, '_remove_stale_public_selectors', lambda *a, **k: None)

    def fake_install(
        cfg_arg,
        ip,
        *,
        relpath,
        text,
        mode,
        manager,
        label,
    ):
        del cfg_arg, ip, text, manager, label
        installed.append((relpath, mode))
        return True

    monkeypatch.setattr(agent_guest, 'install_guest_file_if_changed', fake_install)
    reconcile_guest_agent_credentials(
        cfg,
        '10.77.0.195',
        credentials=(entry,),
        public_keys={entry.id: 'ssh-ed25519 AAAATEST agent-test'},
        manager=FakeCommandManager(),
    )

    selector = next(item for item in installed if item[0].endswith('id_ed25519.pub'))
    assert selector[1] == '600'


def test_guest_file_reconciliation_checks_mode_as_well_as_content(monkeypatch) -> None:
    cfg = AgentVMConfig()
    observed: dict[str, object] = {}

    def fake_run_guest(cfg_arg, ip, *, script, **kwargs):
        del cfg_arg, ip, kwargs
        observed['check_script'] = script
        return SimpleNamespace(code=1)

    def fake_install(cfg_arg, ip, **kwargs):
        del cfg_arg, ip
        observed['install_mode'] = kwargs['mode']

    monkeypatch.setattr(guest_config, 'run_guest', fake_run_guest)
    monkeypatch.setattr(guest_config, 'install_guest_file', fake_install)

    changed = guest_config.install_guest_file_if_changed(
        cfg,
        '10.77.0.195',
        relpath='.local/share/aivm/test.pub',
        text='ssh-ed25519 AAAATEST\n',
        mode='600',
        manager=FakeCommandManager(),
        label='test selector',
    )

    assert changed
    assert 'stat -c %a' in str(observed['check_script'])
    assert '= 600' in str(observed['check_script'])
    assert observed['install_mode'] == '600'


def test_repository_preflight_exercises_managed_git_route(monkeypatch, tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    entry = _entry()
    socket_path = tmp_path / 'agent.sock'
    observed: dict[str, object] = {}

    def fake_run_guest(cfg_arg, ip, *, script, forward_agent_socket, **kwargs):
        del cfg_arg, kwargs
        observed['ip'] = ip
        observed['script'] = script
        observed['socket'] = forward_agent_socket
        return SimpleNamespace(code=0, stdout='', stderr='')

    monkeypatch.setattr(agent_guest, 'run_guest', fake_run_guest)
    probe_repository_access(
        cfg,
        '10.77.0.195',
        socket_path=socket_path,
        credential=entry,
        manager=FakeCommandManager(),
    )

    assert observed['ip'] == '10.77.0.195'
    assert observed['socket'] == socket_path
    assert 'git ls-remote git@github.com:Erotemic/aivm.git HEAD' in str(
        observed['script']
    )

