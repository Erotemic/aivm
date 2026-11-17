"""High-value checks for zero-touch user provisioning and activation."""

from __future__ import annotations

import os
import pwd
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm import admin_onboarding as onboard
from aivm import privileged_onboard_user as helper
from aivm.config import AgentVMConfig
from aivm.config_store import (
    PrincipalEntry,
    Store,
    find_principal_for_host,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.errors import AIVMError
from aivm.machine_store import MachineStoreLayout
from aivm.profile_store import UserProfileStore, render_user_profile
from aivm.scoped_store import StoreScope


VM = 'aivm-2404-test'
GUEST = 'benjamin-fenelon-agent'
PUBLIC = 'ssh-ed25519 AAAABENJAMIN aivm-onboard@aivm-2404-test'


def _account(home: Path, *, owner: bool = False) -> pwd.struct_passwd:
    if owner:
        return pwd.struct_passwd((
            pwd.getpwuid(os.getuid()).pw_name, 'x', os.getuid(), os.getgid(),
            '', str(home), '/bin/bash',
        ))
    return pwd.struct_passwd((
        'benjamin.fenelon', 'x', os.getuid() + 5000, os.getgid(),
        '', str(home), '/bin/bash',
    ))


def _profile(account: pwd.struct_passwd) -> str:
    key = Path(account.pw_dir) / '.ssh/id_aivm_ed25519'
    return render_user_profile(UserProfileStore(
        active_vm=VM,
        ssh_identity_file=str(key),
        ssh_pubkey_path=str(key) + '.pub',
        default_guest_user=GUEST,
    ))


def test_helper_creates_owner_key_and_profile_and_retries_safely(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Unit-test the filesystem/ownership decisions without depending on
    # ssh-keygen being installed in the test container.
    def fake_keygen(cmd: list[str], **kwargs: object) -> SimpleNamespace:
        key = Path(cmd[cmd.index('-f') + 1])
        if '-y' in cmd:
            return SimpleNamespace(stdout='ssh-ed25519 AAAATEST fake-comment\n')
        key.write_text('FAKE PRIVATE KEY\n', encoding='utf-8')
        Path(str(key) + '.pub').write_text(
            f'ssh-ed25519 AAAATEST {cmd[-1]}\n', encoding='utf-8'
        )
        return SimpleNamespace(stdout='')

    monkeypatch.setattr(helper.subprocess, 'run', fake_keygen)
    account = _account(tmp_path, owner=True)
    created = helper._prepare_owner(account, VM, GUEST, _profile(account))
    assert created['created_key'] is True
    assert created['created_profile'] is True
    key = Path(str(created['private_path']))
    assert key.stat().st_mode & 0o777 == 0o600
    assert Path(str(created['profile_path'])).stat().st_mode & 0o777 == 0o600
    retried = helper._prepare_owner(account, VM, GUEST, _profile(account))
    assert retried['created_key'] is False
    assert retried['created_profile'] is False
    assert retried['public_key'] == created['public_key']

    # A pre-existing unrelated profile must never be overwritten or cause a
    # second SSH key to be minted.
    other_home = tmp_path / 'other'
    other_home.mkdir()
    other_account = _account(other_home, owner=True)
    conflict = other_home / '.config/aivm/profile.toml'
    conflict.parent.mkdir(parents=True)
    conflict.write_text(
        _profile(other_account).replace(
            f'active_vm = "{VM}"', 'active_vm = "different-vm"',
        ),
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='refusing to overwrite'):
        helper._prepare_owner(other_account, VM, GUEST, _profile(other_account))
    assert not (other_home / '.ssh/id_aivm_ed25519').exists()


def _fake_machine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[StoreScope, list[Store]]:
    cfg = AgentVMConfig()
    cfg.vm.name = VM
    reg = Store(store_kind='machine')
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    state = [reg]
    scope = StoreScope(
        mode='machine', store_path=tmp_path / 'machine/config.toml',
        machine_layout=MachineStoreLayout.from_root(tmp_path / 'machine', shared=True),
    )
    monkeypatch.setattr(onboard, '_target_account', lambda user: _account(tmp_path / 'ben-home'))
    monkeypatch.setattr(onboard, 'load_scope_store', lambda scope: state[0])
    monkeypatch.setattr(onboard, 'save_scope_store', lambda scope, reg, **kwargs: state.__setitem__(0, reg))
    monkeypatch.setattr(onboard, 'machine_resource_locks', lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(onboard, 'current_machine_group_gid', lambda *args: os.getgid())
    monkeypatch.setattr(onboard, 'get_ip_cached', lambda cfg: '10.77.0.12')
    monkeypatch.setattr(onboard, '_resolve_enrollment_ip', lambda cfg, ip: ip or '10.77.0.12')
    return scope, state


def test_onboard_dry_run_does_not_run_privileged_steps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope, state = _fake_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(onboard, '_install_helper', lambda: pytest.fail('installed helper in dry run'))
    report = onboard.onboard_other_principal(
        scope, vm_name=VM, host_user='benjamin.fenelon', dry_run=True,
    )
    assert report.principal.guest_user == GUEST
    assert report.changed is False
    assert state[0].principals == []


def test_onboard_activates_only_after_owner_uid_ssh_proof(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope, state = _fake_machine(monkeypatch, tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(onboard, '_install_helper', lambda: calls.append('install'))

    def fake_helper(action: str, **kwargs: object) -> dict[str, object]:
        calls.append(action)
        if action == 'prepare':
            return {'public_key': PUBLIC}
        return {'verified': True, 'public_key': PUBLIC}

    def fake_guest_prepare(scope: object, *, selector: str, **kwargs: object) -> object:
        calls.append('guest-prepare')
        principal = find_principal_for_host(state[0], vm_name=VM, host_user='benjamin.fenelon')
        assert principal is not None and principal.state == 'pending'
        return SimpleNamespace(principal=principal)

    monkeypatch.setattr(onboard, '_run_helper', fake_helper)
    monkeypatch.setattr(onboard, 'prepare_other_principal', fake_guest_prepare)
    report = onboard.onboard_other_principal(scope, vm_name=VM, host_user='benjamin.fenelon')
    assert report.principal.state == 'active'
    assert calls == ['install', 'prepare', 'guest-prepare', 'verify']
    assert state[0].principals[0].state == 'active'

    # A failed owner SSH proof must not produce an active identity.
    state[0].principals.clear()
    def failed_helper(action: str, **kwargs: object) -> dict[str, object]:
        if action == 'verify':
            raise AIVMError('SSH proof failed')
        return {'public_key': PUBLIC}
    monkeypatch.setattr(onboard, '_run_helper', failed_helper)
    with pytest.raises(AIVMError, match='SSH proof failed'):
        onboard.onboard_other_principal(scope, vm_name=VM, host_user='benjamin.fenelon')
    assert state[0].principals[0].state == 'pending'


def test_onboard_does_not_restore_disabled_or_rotate_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    scope, state = _fake_machine(monkeypatch, tmp_path)
    target = _account(tmp_path / 'ben-home')
    state[0].principals.append(PrincipalEntry(
        id='principal-ben', vm_name=VM,
        host_user=target.pw_name, host_uid=target.pw_uid, host_gid=target.pw_gid,
        guest_user=GUEST, ssh_public_key=PUBLIC, state='disabled',
    ))
    with pytest.raises(AIVMError, match='disabled'):
        onboard.onboard_other_principal(scope, vm_name=VM, host_user=target.pw_name, dry_run=True)
    state[0].principals[0] = replace(state[0].principals[0], state='pending')
    monkeypatch.setattr(onboard, '_install_helper', lambda: None)
    monkeypatch.setattr(onboard, '_run_helper', lambda action, **kwargs: {'public_key': 'ssh-ed25519 AAAADIFFERENT changed'})
    with pytest.raises(AIVMError, match='Refusing silent key rotation'):
        onboard.onboard_other_principal(scope, vm_name=VM, host_user=target.pw_name)


def test_onboard_cli_optional_attachment_targets_new_principal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from aivm.cli import vm_access
    from tests.helpers import run_cli
    from tests.test_cli_vm_access import _write_machine_and_profile

    vm_name, store_path = _write_machine_and_profile(tmp_path)
    principal = PrincipalEntry(
        id='principal-ben', vm_name=vm_name, host_user='benjamin.fenelon',
        host_uid=12055, host_gid=12155, guest_user=GUEST, state='active',
    )
    monkeypatch.setattr(vm_access, 'onboard_other_principal', lambda *a, **kw: (
        onboard.OnboardReport(
            principal=principal, ip='10.77.0.12',
            profile_path=tmp_path / 'ben/profile.toml', changed=True,
        )
    ))
    attachments: list[object] = []
    monkeypatch.setattr(
        vm_access, 'run_vm_attach', lambda req: attachments.append(req) or 0,
    )
    host_dir = tmp_path / 'ben/project'
    result = run_cli([
        'vm', 'access', 'onboard', 'benjamin.fenelon',
        '--vm', vm_name, '--config', str(store_path),
        '--admin_override', '--yes', '--attach', str(host_dir),
    ])
    assert result == 0
    assert len(attachments) == 1
    attach = attachments[0]
    assert attach.owner_principal == principal.id
    assert attach.admin_override is True
    assert attach.mode == 'persistent'
    assert attach.host_src == host_dir


def test_privileged_helper_parses_profile_without_tomllib(tmp_path: Path) -> None:
    """The root-installed helper must work on system Python 3.10."""
    account = _account(tmp_path, owner=True)
    text = _profile(account)
    fields = helper._profile_identity_fields(text)
    assert fields == {
        'active_vm': VM,
        'ssh_identity_file': str(tmp_path / '.ssh/id_aivm_ed25519'),
        'ssh_pubkey_path': str(tmp_path / '.ssh/id_aivm_ed25519.pub'),
        'default_guest_user': GUEST,
    }
    assert helper._profile_identity_fields('# note\n' + text)['active_vm'] == VM
    escaped = text.replace('active_vm = "aivm-2404-test"', 'active_vm = "two\\\"quotes"')
    assert helper._profile_identity_fields(escaped)['active_vm'] == 'two"quotes'


@pytest.mark.parametrize('invalid', [
    'active_vm = "a"\nactive_vm = "b"\n',
    'active_vm = 3\n',
    'active_vm = "a" false\n',
    '[behavior]\nactive_vm = "a"\n',
    'state_dir = """multiline\nactive_vm = "a"\n"""\n',
])
def test_privileged_helper_rejects_ambiguous_profile(invalid: str) -> None:
    with pytest.raises(ValueError):
        helper._profile_identity_fields(invalid)


def test_onboard_bootstrap_auth_failure_requires_explicit_repair(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    scope, state = _fake_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(onboard, '_install_helper', lambda: None)
    monkeypatch.setattr(onboard, '_run_helper', lambda action, **kw: {'public_key': PUBLIC})
    monkeypatch.setattr(
        onboard, 'prepare_other_principal',
        lambda *args, **kw: (_ for _ in ()).throw(AIVMError(
            "Guest preparation failed for 'benjamin.fenelon': "
            'aivm-bootstrap@10.77.0.12: Permission denied (publickey,password,keyboard-interactive).'
        )),
    )
    monkeypatch.setattr(
        onboard, '_repair_bootstrap_through_current_guest_access',
        lambda *args, **kw: pytest.fail('must not silently repair guest bootstrap'),
    )
    with pytest.raises(AIVMError, match='--repair_bootstrap'):
        onboard.onboard_other_principal(
            scope, vm_name=VM, host_user='benjamin.fenelon',
        )
    assert state[0].principals[0].state == 'pending'


def test_onboard_repairs_bootstrap_once_then_verifies_owner_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    scope, state = _fake_machine(monkeypatch, tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(onboard, '_install_helper', lambda: None)
    monkeypatch.setattr(
        onboard, '_run_helper',
        lambda action, **kw: {
            'public_key': PUBLIC,
            **({'verified': True} if action == 'verify' else {}),
        },
    )

    def prepare(*args: object, **kwargs: object) -> None:
        calls.append('prepare')
        if calls.count('prepare') == 1:
            raise AIVMError(
                "Guest preparation failed for 'benjamin.fenelon': "
                'aivm-bootstrap@10.77.0.12: Permission denied (publickey).'
            )
    monkeypatch.setattr(onboard, 'prepare_other_principal', prepare)
    monkeypatch.setattr(
        onboard, '_repair_bootstrap_through_current_guest_access',
        lambda *args, **kwargs: calls.append('repair'),
    )
    report = onboard.onboard_other_principal(
        scope, vm_name=VM, host_user='benjamin.fenelon',
        repair_bootstrap=True,
    )
    assert report.principal.state == 'active'
    assert calls == ['prepare', 'repair', 'prepare']
    assert state[0].principals[0].state == 'active'


def test_onboard_never_repairs_non_authentication_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    scope, state = _fake_machine(monkeypatch, tmp_path)
    monkeypatch.setattr(onboard, '_install_helper', lambda: None)
    monkeypatch.setattr(onboard, '_run_helper', lambda action, **kw: {'public_key': PUBLIC})
    monkeypatch.setattr(
        onboard, 'prepare_other_principal',
        lambda *args, **kw: (_ for _ in ()).throw(AIVMError(
            "Guest preparation failed for 'benjamin.fenelon': connection timed out"
        )),
    )
    monkeypatch.setattr(
        onboard, '_repair_bootstrap_through_current_guest_access',
        lambda *args, **kw: pytest.fail('must not attempt guest repair on timeout'),
    )
    with pytest.raises(AIVMError, match='connection timed out'):
        onboard.onboard_other_principal(
            scope, vm_name=VM, host_user='benjamin.fenelon',
            repair_bootstrap=True,
        )
    assert state[0].principals[0].state == 'pending'


def test_repair_requires_active_registered_admin_guest_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    scope, _ = _fake_machine(monkeypatch, tmp_path)
    with pytest.raises(AIVMError, match='own active VM access identity'):
        onboard._repair_bootstrap_through_current_guest_access(
            scope, vm_name=VM, ip_override='',
        )


def test_repair_uses_current_admin_personal_key_and_guest_sudo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from aivm.host_identity import HostIdentity
    from aivm.guest_bootstrap_install import guest_bootstrap_install_script
    scope, state = _fake_machine(monkeypatch, tmp_path)
    public_path = tmp_path / 'mykey.pub'
    public_path.write_text('ssh-ed25519 AAAAADMIN mykey\n', encoding='utf-8')
    private_path = tmp_path / 'mykey'
    private_path.write_text('FAKE PRIVATE KEY\n', encoding='utf-8')
    principal = PrincipalEntry(
        id='principal-admin', vm_name=VM, host_user='jon.crall',
        host_uid=12001, host_gid=12002, guest_user='agent',
        ssh_public_key='ssh-ed25519 AAAAADMIN stored', state='active',
    )
    state[0].principals.append(principal)
    monkeypatch.setattr(
        onboard, 'current_host_identity',
        lambda: HostIdentity(uid=12001, gid=12002, username='jon.crall'),
    )
    monkeypatch.setattr(
        onboard, 'load_scope_profile',
        lambda scope: UserProfileStore(
            ssh_identity_file=str(private_path),
            ssh_pubkey_path=str(public_path),
        ),
    )
    monkeypatch.setattr(
        onboard, 'require_bootstrap_identity',
        lambda *args, **kw: SimpleNamespace(
            public_key='ssh-ed25519 AAAABOOTSTRAP bootstrap'
        ),
    )
    invocations: list[tuple[list[str], dict[str, object]]] = []

    class FakeCommandManager:
        def intent(self, *a: object, **kw: object) -> object:
            return nullcontext()

        def run(self, cmd: list[str], **kwargs: object) -> SimpleNamespace:
            invocations.append((cmd, kwargs))
            return SimpleNamespace(code=0, stdout='', stderr='')

    monkeypatch.setattr(onboard.CommandManager, 'current', lambda: FakeCommandManager())
    onboard._repair_bootstrap_through_current_guest_access(
        scope, vm_name=VM, ip_override='10.77.0.114',
    )
    assert len(invocations) == 1
    cmd, kw = invocations[0]
    assert cmd[0] == 'ssh'
    assert str(private_path) in cmd
    assert cmd[-5:] == ['agent@10.77.0.114', 'sudo', '-n', 'bash', '-s']
    assert kw['sudo'] is False
    assert 'aivm-guestctl' in str(kw['input_text'])
    assert kw['input_text'] == guest_bootstrap_install_script(
        'ssh-ed25519 AAAABOOTSTRAP bootstrap'
    )


def test_repair_refuses_mismatched_administrator_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from aivm.host_identity import HostIdentity
    scope, state = _fake_machine(monkeypatch, tmp_path)
    public_path = tmp_path / 'otherkey.pub'
    public_path.write_text('ssh-ed25519 AAAAOTHER unknown\n', encoding='utf-8')
    state[0].principals.append(PrincipalEntry(
        id='principal-admin', vm_name=VM, host_user='jon.crall',
        host_uid=12001, host_gid=12002, guest_user='agent',
        ssh_public_key='ssh-ed25519 AAAAADMIN stored', state='active',
    ))
    monkeypatch.setattr(
        onboard, 'current_host_identity',
        lambda: HostIdentity(uid=12001, gid=12002, username='jon.crall'),
    )
    monkeypatch.setattr(
        onboard, 'load_scope_profile',
        lambda scope: UserProfileStore(
            ssh_identity_file=str(tmp_path / 'key'),
            ssh_pubkey_path=str(public_path),
        ),
    )
    with pytest.raises(AIVMError, match='does not match'):
        onboard._repair_bootstrap_through_current_guest_access(
            scope, vm_name=VM, ip_override='10.77.0.114',
        )


def test_onboard_cli_forwards_repair_bootstrap_option(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    from aivm.cli import vm_access
    from tests.helpers import run_cli
    from tests.test_cli_vm_access import _write_machine_and_profile
    vm_name, store_path = _write_machine_and_profile(tmp_path)
    invoked: list[dict[str, object]] = []

    def fake_onboard(*args: object, **kwargs: object) -> onboard.OnboardReport:
        invoked.append(kwargs)
        return onboard.OnboardReport(
            principal=PrincipalEntry(
                id='principal-ben', vm_name=vm_name,
                host_user='benjamin.fenelon', host_uid=12055, host_gid=12155,
                guest_user=GUEST, state='active',
            ),
            ip='10.77.0.114',
            profile_path=tmp_path / 'profile.toml',
            changed=True,
        )

    monkeypatch.setattr(vm_access, 'onboard_other_principal', fake_onboard)
    assert run_cli([
        'vm', 'access', 'onboard', 'benjamin.fenelon',
        '--vm', vm_name, '--config', str(store_path),
        '--admin_override', '--yes', '--repair_bootstrap',
    ]) == 0
    assert len(invoked) == 1
    assert invoked[0]['repair_bootstrap'] is True
