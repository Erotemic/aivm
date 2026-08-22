"""Tests for the independent ssh-agent credential backend."""

from __future__ import annotations

import base64
from dataclasses import replace
import os
import shutil
import socket
from pathlib import Path
from typing import Any, Sequence

import pytest

from aivm.commands import (
    CommandManager,
    CommandOwnership,
    CommandResult,
    CommandRole,
)
from aivm.config_store import Store
from aivm.credentials import agent, agent_store
from aivm.credentials.guards import require_vm_credentials_released
from aivm.credentials.keys import public_key_fingerprint
from aivm.credentials.models import GitRepository, ProviderDeployKey
from aivm.credentials.schema import CREDENTIAL_KIND_GITHUB_DEPLOY_KEY
from aivm.credentials.validation import credential_id
from aivm.errors import AIVMError


class _FakeManager(CommandManager):
    """Command-manager fake with an in-process ssh-agent and fake keygen."""

    def __init__(self) -> None:
        super().__init__(yes=True)
        self.next_pid = 47000
        self.servers: dict[str, socket.socket] = {}
        self.loaded: dict[str, list[str]] = {}
        self.public_by_private: dict[str, str] = {}
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        cmd: Sequence[str],
        *,
        sudo: bool = False,
        role: CommandRole | None = None,
        ownership: CommandOwnership = 'user',
        user_driven: bool = False,
        check: bool = True,
        capture: bool = True,
        text: bool = True,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        summary: str = '',
        detail: str = '',
    ) -> CommandResult:
        del (
            sudo,
            role,
            ownership,
            user_driven,
            check,
            capture,
            text,
            input_text,
            timeout,
            summary,
            detail,
        )
        tokens = tuple(str(part) for part in cmd)
        self.commands.append(tokens)
        run_env = env if env else dict(os.environ)
        if tokens[:2] == ('ssh-keygen', '-q'):
            private = Path(tokens[tokens.index('-f') + 1])
            private.write_text('fake-private-key\n', encoding='utf-8')
            payload = base64.b64encode(str(private).encode('utf-8')).decode('ascii')
            public = f'ssh-ed25519 {payload} aivm-test'
            private.with_suffix(private.suffix + '.pub').write_text(
                public + '\n', encoding='utf-8'
            )
            self.public_by_private[str(private)] = public
            return CommandResult(0, '', '')
        if tokens[:2] == ('ssh-keygen', '-y'):
            private = tokens[tokens.index('-f') + 1]
            return CommandResult(0, self.public_by_private[private] + '\n', '')
        if tokens[:1] == ('ssh-agent',) and '-a' in tokens:
            socket_path = tokens[tokens.index('-a') + 1]
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_path)
            self.servers[socket_path] = server
            self.loaded[socket_path] = []
            pid = self.next_pid
            self.next_pid += 1
            stdout = (
                f'SSH_AUTH_SOCK={socket_path}; export SSH_AUTH_SOCK;\n'
                f'SSH_AGENT_PID={pid}; export SSH_AGENT_PID;\n'
                f'echo Agent pid {pid};\n'
            )
            return CommandResult(0, stdout, '')
        if tokens == ('ssh-agent', '-k'):
            self.drop_agent(run_env['SSH_AUTH_SOCK'])
            return CommandResult(0, 'Agent pid killed\n', '')
        if tokens == ('ssh-add', '-l', '-E', 'sha256'):
            socket_path = run_env.get('SSH_AUTH_SOCK', '')
            if socket_path not in self.servers:
                return CommandResult(2, '', 'Could not open agent.\n')
            loaded = self.loaded[socket_path]
            if not loaded:
                return CommandResult(1, '', 'The agent has no identities.\n')
            stdout = ''.join(
                f'256 {fingerprint} aivm-test (ED25519)\n'
                for fingerprint in loaded
            )
            return CommandResult(0, stdout, '')
        if tokens == ('ssh-add', '-D'):
            self.loaded[run_env['SSH_AUTH_SOCK']] = []
            return CommandResult(0, '', '')
        if tokens[:1] == ('ssh-add',):
            fingerprints: list[str] = []
            for private_text in tokens[1:]:
                public = self.public_by_private[private_text]
                fingerprints.append(public_key_fingerprint(public))
            self.loaded[run_env['SSH_AUTH_SOCK']] = fingerprints
            return CommandResult(0, '', '')
        raise AssertionError(f'unexpected command: {tokens!r}')

    def drop_agent(self, socket_path: str) -> None:
        server = self.servers.pop(socket_path, None)
        if server is not None:
            server.close()
        self.loaded.pop(socket_path, None)
        try:
            Path(socket_path).unlink()
        except FileNotFoundError:
            pass

    def close(self) -> None:
        for socket_path in list(self.servers):
            self.drop_agent(socket_path)


@pytest.fixture
def isolated_agent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    data = tmp_path / 'data'
    data.mkdir(mode=0o700)
    data.chmod(0o700)
    runtime = tmp_path / 'runtime'
    manager = _FakeManager()
    remote_keys: dict[str, list[ProviderDeployKey]] = {}

    monkeypatch.setattr(agent_store, 'app_data_dir', lambda: data)
    monkeypatch.setattr(agent, '_AGENT_RUNTIME_PARENT', runtime)
    monkeypatch.setattr(agent, '_pid_is_owned_ssh_agent', lambda pid: True)
    monkeypatch.setattr(agent.shutil, 'which', lambda name: f'/fake/{name}')
    monkeypatch.setattr(agent.providers, 'required_tools', lambda kind: ())
    monkeypatch.setattr(
        agent.providers,
        'automation_unavailable_reason',
        lambda kind, repo, manager: '',
    )
    monkeypatch.setattr(
        agent.providers,
        'check_auth',
        lambda kind, repo, manager: None,
    )

    def list_remote(kind: str, repo: GitRepository, *, manager: Any):
        del kind, manager
        return list(remote_keys.get(repo.canonical, ()))

    def add_remote(
        kind: str,
        repo: GitRepository,
        *,
        public_key_path: Path,
        title: str,
        write: bool,
        manager: Any,
    ) -> ProviderDeployKey:
        del kind, manager
        public = public_key_path.read_text(encoding='utf-8').strip()
        remote = ProviderDeployKey(
            key_id=str(len(remote_keys.get(repo.canonical, ())) + 101),
            key=public,
            title=title,
            read_only=not write,
        )
        remote_keys.setdefault(repo.canonical, []).append(remote)
        return remote

    def delete_remote(
        kind: str,
        repo: GitRepository,
        key_id: str,
        *,
        manager: Any,
    ) -> None:
        del kind, manager
        remote_keys[repo.canonical] = [
            item
            for item in remote_keys.get(repo.canonical, ())
            if item.key_id != key_id
        ]

    monkeypatch.setattr(agent.providers, 'list_deploy_keys', list_remote)
    monkeypatch.setattr(agent.providers, 'add_deploy_key', add_remote)
    monkeypatch.setattr(agent.providers, 'delete_deploy_key', delete_remote)
    monkeypatch.setattr(agent, '_save_agent_store', lambda *args, **kwargs: None)
    store = Store()

    try:
        yield manager, remote_keys, store
    finally:
        manager.close()
        shutil.rmtree(runtime, ignore_errors=True)


def _grant(
    manager: _FakeManager,
    store: Store,
    *,
    vm: str = 'vm-a',
    principal: str = 'principal-a',
    repo_name: str = 'alpha',
    access: str = 'read',
) -> agent.AgentCredentialEntry:
    return agent.grant_agent_credential(
        store,
        Path('/tmp/aivm-test-store.toml'),
        vm,
        principal,
        GitRepository('github.com', 'Kitware', repo_name),
        access=access,
        kind=CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
        manager=manager,
    )


def test_pid_check_accepts_nondumpable_same_user_ssh_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Linux may make /proc/<pid> appear root-owned and deny /proc/<pid>/exe
    # for OpenSSH's intentionally non-dumpable agent.  Process UIDs in status
    # still identify the actual user that owns the agent.
    status = "Name:\tssh-agent\nUid:\t1000\t1000\t1000\t1000\n"
    original_read_text = Path.read_text

    def fake_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self == Path('/proc/4242/status'):
            return status
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    monkeypatch.setattr(agent.os, 'getuid', lambda: 1000)
    assert agent._pid_is_owned_ssh_agent(4242)


def test_pid_check_rejects_wrong_process_or_mixed_uids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read_text = Path.read_text
    statuses = {
        4242: "Name:\tpython\nUid:\t1000\t1000\t1000\t1000\n",
        4243: "Name:\tssh-agent\nUid:\t1000\t0\t0\t1000\n",
    }

    def fake_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.parent.parent == Path('/proc') and self.name == 'status':
            return statuses[int(self.parent.name)]
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', fake_read_text)
    monkeypatch.setattr(agent.os, 'getuid', lambda: 1000)
    assert not agent._pid_is_owned_ssh_agent(4242)
    assert not agent._pid_is_owned_ssh_agent(4243)


def test_agent_credential_ids_are_disjoint_from_guest_key_ids() -> None:
    repo = GitRepository('github.com', 'Kitware', 'alpha')
    agent_id = agent.agent_credential_id('vm-a', repo.canonical, 'principal-a')
    guest_id = credential_id('vm-a', repo.canonical, 'principal-a')
    assert agent_id.startswith('agent-git-')
    assert guest_id.startswith('git-')
    assert agent_id != guest_id


def test_grant_creates_separate_host_only_record_and_agent(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, remotes, store = isolated_agent
    record = _grant(manager, store, access='write')

    assert record.state == agent.AGENT_CREDENTIAL_STATE_ACTIVE
    assert record.access == 'write'
    assert agent.private_key_path(record).is_file()
    assert 'agent-credentials' in agent.private_key_path(record).parts
    assert remotes[agent.agent_repository(record).canonical][0].read_only is False

    records = agent.list_agent_credentials(store, record.vm_name, record.principal_id)
    assert records == (record,)
    assert agent_store.list_agent_credentials_for_vm(store, record.vm_name) == (record,)
    status = agent.inspect_agent(
        record.vm_name, record.principal_id, manager=manager
    )
    assert status.runtime_state == 'running'
    assert status.loaded_fingerprints == (record.key_fingerprint,)


def test_existing_guest_key_identity_is_never_adopted(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, _, store = isolated_agent
    record = _grant(manager, store)
    unrelated_guest_fingerprint = 'SHA256:not-loaded-from-guest-store'
    status = agent.inspect_agent(
        record.vm_name, record.principal_id, manager=manager
    )
    assert unrelated_guest_fingerprint not in status.loaded_fingerprints
    assert status.loaded_fingerprints == (record.key_fingerprint,)


def test_doctor_detects_cross_system_key_reuse(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, _, store = isolated_agent
    record = _grant(manager, store)
    report = agent.inspect_doctor(
        store,
        record.vm_name,
        record.principal_id,
        guest_key_fingerprints=(record.key_fingerprint,),
        manager=manager,
    )
    issue = next(item for item in report.issues if item.code == 'guest-key-collision')
    assert issue.fixable is False
    with pytest.raises(AIVMError, match='must not change automatically'):
        agent.fix_doctor(
            store,
            record.vm_name,
            record.principal_id,
            guest_key_fingerprints=(record.key_fingerprint,),
            manager=manager,
        )


def test_doctor_fix_repairs_only_agent_runtime(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, _, store = isolated_agent
    record = _grant(manager, store)
    status = agent.inspect_agent(
        record.vm_name, record.principal_id, manager=manager
    )
    manager.loaded[str(status.socket_path)].append('SHA256:unexpected')

    before = agent.inspect_doctor(
        store,
        record.vm_name, record.principal_id, manager=manager
    )
    issue = next(item for item in before.issues if item.code == 'agent-identities')
    assert issue.fixable is True

    after = agent.fix_doctor(
        store,
        record.vm_name, record.principal_id, manager=manager
    )
    assert after.healthy
    assert after.agent.loaded_fingerprints == (record.key_fingerprint,)


def test_add_retry_reuses_active_provider_grant_after_agent_loss(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, remotes, store = isolated_agent
    record = _grant(manager, store)
    repo_key = agent.agent_repository(record).canonical
    assert len(remotes[repo_key]) == 1

    status = agent.inspect_agent(
        record.vm_name, record.principal_id, manager=manager
    )
    manager.drop_agent(str(status.socket_path))
    try:
        agent._pid_path(record.vm_name, record.principal_id).unlink()
    except FileNotFoundError:
        pass

    retried = _grant(manager, store)
    assert retried == record
    assert len(remotes[repo_key]) == 1
    repaired = agent.inspect_agent(
        record.vm_name, record.principal_id, manager=manager
    )
    assert repaired.runtime_state == 'running'
    assert repaired.loaded_fingerprints == (record.key_fingerprint,)


def test_add_does_not_resurrect_revocation_pending_grant(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, _, store = isolated_agent
    record = _grant(manager, store)
    pending = replace(
        record, state=agent.AGENT_CREDENTIAL_STATE_REVOCATION_PENDING
    )
    for index, item in enumerate(store.agent_credentials):
        if item.id == record.id:
            store.agent_credentials[index] = pending
            break
    else:
        raise AssertionError('agent credential disappeared from the store')

    with pytest.raises(AIVMError, match='already being revoked'):
        _grant(manager, store)


def test_revoke_removes_provider_record_key_and_agent(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, remotes, store = isolated_agent
    record = _grant(manager, store)
    assert remotes[agent.agent_repository(record).canonical]

    agent.revoke_agent_credential(
        store, Path('/tmp/aivm-test-store.toml'), record, manager=manager
    )

    assert remotes[agent.agent_repository(record).canonical] == []
    assert agent.list_agent_credentials(store, record.vm_name, record.principal_id) == ()
    assert not agent.private_key_path(record).exists()
    status = agent.inspect_agent(
        record.vm_name, record.principal_id, manager=manager
    )
    assert status.runtime_state == 'stopped'



def test_vm_delete_guard_sees_independent_agent_credentials(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
) -> None:
    manager, _, store = isolated_agent
    record = _grant(manager, store)
    with pytest.raises(AIVMError, match='ssh-agent repository credentials'):
        require_vm_credentials_released(
            store, record.vm_name, action='deleted'
        )


def test_failed_provider_publication_keeps_pending_host_only_record(
    isolated_agent: tuple[_FakeManager, dict[str, list[ProviderDeployKey]], Store],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, store = isolated_agent
    monkeypatch.setattr(
        agent.providers,
        'automation_unavailable_reason',
        lambda kind, repo, manager: 'provider automation unavailable',
    )
    with pytest.raises(AIVMError, match='Pending credential'):
        _grant(manager, store)
    records = agent.list_agent_credentials(store, 'vm-a', 'principal-a')
    assert len(records) == 1
    assert records[0].state == agent.AGENT_CREDENTIAL_STATE_PENDING
    assert records[0].key_fingerprint
    assert agent.private_key_path(records[0]).is_file()
    status = agent.inspect_agent('vm-a', 'principal-a', manager=manager)
    assert status.runtime_state == 'stopped'
    report = agent.inspect_doctor(store, 'vm-a', 'principal-a', manager=manager)
    issue = next(item for item in report.issues if item.code == 'pending-grant')
    assert issue.fixable is False
