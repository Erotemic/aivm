"""Guest routing for independent host-agent repository credentials."""

from __future__ import annotations

from pathlib import Path

from aivm.config import AgentVMConfig
from aivm.config_store import AgentCredentialEntry
from aivm.credentials.agent_guest import render_git_config, render_ssh_config
from aivm.credentials.agent_schema import agent_credential_id
from aivm.credentials.guest_config import guest_ssh_command


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

    option = f'ForwardAgent={socket_path}'
    idx = cmd.index(option)
    assert cmd[idx - 1 : idx + 1] == ['-o', option]
    assert 'SSH_AUTH_SOCK' not in ' '.join(cmd)
    assert cmd[-2:] == ['agent@10.77.0.195', 'ssh-add -l -E sha256']
