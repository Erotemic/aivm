"""Connection-time forwarding of independent ssh-agent credentials."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from aivm.config import AgentVMConfig
from aivm.config_store import AgentCredentialEntry, Store
from aivm.credentials import agent
from aivm.credentials.agent_schema import agent_credential_id
from aivm.credentials.agent_transport import (
    AgentForwarding,
    prepare_agent_forwarding,
    prepare_agent_grant_forwarding,
)
from aivm.errors import VMNotRunningError
from tests.helpers import FakeCommandManager, resolved_test_context


def _active_record(vm_name: str, principal_id: str) -> AgentCredentialEntry:
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
        provider_key_title='agent-key',
        key_fingerprint='SHA256:agent-test',
        state='active',
    )


def test_prepare_agent_forwarding_converges_host_and_guest(
    monkeypatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    cfg.vm.user = 'agent'
    principal_id = 'principal-test'
    context = resolved_test_context(
        cfg,
        principal_id=principal_id,
        guest_user='agent',
    )
    record = _active_record(cfg.vm.name, principal_id)
    store = Store(agent_credentials=[record])
    socket_path = tmp_path / 'agent.sock'
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.resolve_store_scope',
        lambda path: SimpleNamespace(is_machine=True),
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.load_scope_store', lambda scope: store
    )
    monkeypatch.setattr(
        agent,
        'ensure_agent_state',
        lambda *a, **k: agent.AgentStatus(
            'running', 42, socket_path, (record.key_fingerprint,)
        ),
    )
    monkeypatch.setattr(
        agent,
        'validated_agent_public_key',
        lambda *a, **k: ('ssh-ed25519 AAAATEST agent-test', record.key_fingerprint),
    )

    def fake_reconcile(cfg_arg, ip, *, credentials, public_keys, manager):
        del cfg_arg, manager
        calls.append(('reconcile', (ip, credentials, public_keys)))

    def fake_probe(
        cfg_arg,
        ip,
        *,
        socket_path,
        expected_fingerprints,
        manager,
    ):
        del cfg_arg, manager
        calls.append(('probe', (ip, socket_path, expected_fingerprints)))

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.reconcile_guest_agent_credentials',
        fake_reconcile,
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.probe_forwarded_agent', fake_probe
    )

    result = prepare_agent_forwarding(
        context,
        tmp_path / 'config.toml',
        '10.77.0.195',
        manager=FakeCommandManager(),
    )

    assert result is not None
    assert result.socket_path == socket_path
    assert result.credential_count == 1
    assert result.fingerprints == (record.key_fingerprint,)
    assert calls[0][0] == 'reconcile'
    assert calls[1] == (
        'probe',
        ('10.77.0.195', socket_path, (record.key_fingerprint,)),
    )


def test_prepare_agent_forwarding_is_noop_without_agent_credentials(
    monkeypatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    principal_id = 'principal-test'
    context = resolved_test_context(cfg, principal_id=principal_id)
    store = Store()

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.resolve_store_scope',
        lambda path: SimpleNamespace(is_machine=True),
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.load_scope_store', lambda scope: store
    )
    monkeypatch.setattr(
        agent,
        'ensure_agent_state',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not run')),
    )
    assert (
        prepare_agent_forwarding(
            context,
            tmp_path / 'config.toml',
            '10.77.0.195',
            manager=FakeCommandManager(),
        )
        is None
    )


def test_prepare_agent_grant_forwarding_verifies_live_guest(
    monkeypatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    context = resolved_test_context(cfg, principal_id='principal-test')
    forwarding = AgentForwarding(
        socket_path=tmp_path / 'agent.sock',
        credential_count=2,
        fingerprints=('SHA256:one', 'SHA256:two'),
    )
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.get_ip_cached',
        lambda cfg_arg: '10.77.0.195',
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.probe_ssh_ready',
        lambda cfg_arg, ip: SimpleNamespace(ok=True),
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.wait_for_ip',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('cached reachable IP should avoid discovery')
        ),
    )

    def fake_prepare(context_arg, store_path, ip, *, manager):
        del context_arg, store_path, manager
        calls.append(('prepare', ip))
        return forwarding

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.prepare_agent_forwarding',
        fake_prepare,
    )

    result = prepare_agent_grant_forwarding(
        context,
        tmp_path / 'config.toml',
        manager=FakeCommandManager(),
    )

    assert result.verified
    assert result.ip == '10.77.0.195'
    assert result.forwarding == forwarding
    assert result.deferred_reason == ''
    assert calls == [('prepare', '10.77.0.195')]


def test_prepare_agent_grant_forwarding_defers_stopped_vm(
    monkeypatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    context = resolved_test_context(cfg, principal_id='principal-test')

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.get_ip_cached', lambda cfg_arg: None
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.wait_for_ip',
        lambda *a, **k: (_ for _ in ()).throw(
            VMNotRunningError("VM aivm-2404 is not running (state='shut off').")
        ),
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.prepare_agent_forwarding',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('must defer')),
    )

    result = prepare_agent_grant_forwarding(
        context,
        tmp_path / 'config.toml',
        manager=FakeCommandManager(),
    )

    assert not result.verified
    assert result.forwarding is None
    assert result.ip is None
    assert 'shut off' in result.deferred_reason


def test_prepare_agent_grant_forwarding_defers_until_ssh_ready(
    monkeypatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    context = resolved_test_context(cfg, principal_id='principal-test')

    monkeypatch.setattr(
        'aivm.credentials.agent_transport.get_ip_cached', lambda cfg_arg: None
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.wait_for_ip',
        lambda *a, **k: '10.77.0.195',
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.probe_ssh_ready',
        lambda cfg_arg, ip: SimpleNamespace(ok=False),
    )
    monkeypatch.setattr(
        'aivm.credentials.agent_transport.prepare_agent_forwarding',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('must defer')),
    )

    result = prepare_agent_grant_forwarding(
        context,
        tmp_path / 'config.toml',
        manager=FakeCommandManager(),
    )

    assert not result.verified
    assert result.ip == '10.77.0.195'
    assert 'SSH is not ready yet' in result.deferred_reason


def test_vm_ssh_forwards_prepared_dedicated_agent(
    monkeypatch, tmp_path: Path
) -> None:
    from aivm.cli.vm_connect import VMSSHCLI
    from aivm.credentials.agent_transport import AgentForwarding
    from aivm.services import PreparedSession
    from tests.helpers import FakeProc, activate_manager, command_recorder

    cfg = AgentVMConfig()
    cfg.vm.name = 'aivm-2404'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = str(tmp_path / 'vm-login-key')
    context = resolved_test_context(
        cfg,
        principal_id='principal-test',
        guest_user='agent',
    )
    host_src = tmp_path / 'repo'
    host_src.mkdir()
    session = PreparedSession(
        context=context,
        cfg_path=tmp_path / 'config.toml',
        host_src=host_src,
        attachment_mode='persistent',
        share_source_dir=str(host_src),
        share_tag='hostcode-repo',
        share_guest_dst='/home/test/code/repo',
        ip='10.77.0.195',
        reg_path=tmp_path / 'config.toml',
        meta_path=None,
    )
    forwarding = AgentForwarding(
        socket_path=Path('/tmp/aivm-agent-credentials-1000/scope-test.sock'),
        credential_count=1,
        fingerprints=('SHA256:agent-test',),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_session', lambda args: session
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_agent_forwarding',
        lambda session: forwarding,
    )
    ssh_config_calls: list[dict[str, object]] = []

    def fake_upsert(cfg_arg, **kwargs):
        del cfg_arg
        ssh_config_calls.append(kwargs)
        return tmp_path / 'ssh-config', False

    monkeypatch.setattr(
        'aivm.cli.vm_connect._upsert_ssh_config_entry', fake_upsert
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect.require_ssh_identity', lambda path: path
    )
    activate_manager(monkeypatch)
    recorder = command_recorder(
        monkeypatch,
        {
            (
                'env',
                f'SSH_AUTH_SOCK={forwarding.socket_path}',
                'ssh',
            ): FakeProc(0, '', '')
        },
    )

    rc = VMSSHCLI.main(
        argv=False,
        config=str(session.cfg_path),
        host_src=str(host_src),
        yes=True,
    )

    assert rc == 0
    assert ssh_config_calls == [
        {
            'dry_run': False,
            'yes': True,
            'forward_agent_socket': str(forwarding.socket_path),
        }
    ]
    ssh_cmd = next(cmd for cmd in recorder.normalized if cmd[0] == 'env')
    assert ssh_cmd[:4] == [
        'env',
        f'SSH_AUTH_SOCK={forwarding.socket_path}',
        'ssh',
        '-A',
    ]
    assert not any(part.startswith('ForwardAgent=') for part in ssh_cmd)
