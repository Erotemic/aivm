"""Tests for the transitional shared-machine runtime scope boundary."""

from __future__ import annotations

from pathlib import Path

from aivm.config import AgentVMConfig
from aivm.config_scopes import resolve_legacy_vm_context


def test_machine_scope_ignores_principal_and_user_paths() -> None:
    alice = AgentVMConfig()
    alice.vm.name = 'aivm-2404-shared'
    alice.vm.user = 'alice-agent'
    alice.paths.ssh_identity_file = '/home/alice/.ssh/id_aivm_ed25519'
    alice.paths.ssh_pubkey_path = '/home/alice/.ssh/id_aivm_ed25519.pub'
    alice.paths.state_dir = '/home/alice/.cache/aivm'

    bob = AgentVMConfig()
    bob.vm.name = alice.vm.name
    bob.vm.user = 'bob-agent'
    bob.paths.ssh_identity_file = '/home/bob/.ssh/id_aivm_ed25519'
    bob.paths.ssh_pubkey_path = '/home/bob/.ssh/id_aivm_ed25519.pub'
    bob.paths.state_dir = '/home/bob/.cache/aivm'

    alice_ctx = resolve_legacy_vm_context(
        alice, host_user='alice', host_uid=1001, host_gid=1001
    )
    bob_ctx = resolve_legacy_vm_context(
        bob, host_user='bob', host_uid=1002, host_gid=1002
    )

    assert alice_ctx.machine == bob_ctx.machine
    assert alice_ctx.principal != bob_ctx.principal
    assert alice_ctx.profile != bob_ctx.profile
    assert alice_ctx.ssh_target('10.77.0.119') == (
        'alice-agent@10.77.0.119'
    )
    assert str(bob_ctx.guest_home) == '/home/bob-agent'


def test_legacy_context_snapshots_machine_values() -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg.vm.cpus = 8
    ctx = resolve_legacy_vm_context(
        cfg, host_user='alice', host_uid=1001, host_gid=1001
    )

    cfg.vm.cpus = 16
    cfg.network.name = 'changed-after-resolution'

    assert ctx.machine.vm.cpus == 8
    assert ctx.machine.network.name == 'aivm-net'
    assert ctx.legacy_cfg is cfg


def test_guest_runtime_modules_use_scope_boundary() -> None:
    """Keep legacy principal/path reads at persistence and creation seams."""
    root = Path(__file__).parents[1]
    runtime_modules = [
        'aivm/attachments/guest.py',
        'aivm/attachments/persistent/manifest.py',
        'aivm/attachments/persistent/transport.py',
        'aivm/attachments/resolve.py',
        'aivm/attachments/shared_root.py',
        'aivm/cli/vm_cache.py',
        'aivm/cli/vm_connect.py',
        'aivm/cli/vm_guard.py',
        'aivm/credentials/guest.py',
        'aivm/status.py',
        'aivm/vm/connectivity.py',
        'aivm/vm/provision.py',
        'aivm/vm/share.py',
        'aivm/vm/update/fdguard.py',
    ]
    forbidden = (
        'cfg.vm.user',
        'cfg.paths.ssh_identity_file',
        'cfg.paths.ssh_pubkey_path',
    )
    violations: list[str] = []
    for relpath in runtime_modules:
        text = (root / relpath).read_text(encoding='utf-8')
        for token in forbidden:
            if token in text:
                violations.append(f'{relpath}: {token}')
    assert not violations, '\n'.join(violations)


def test_session_entrypoints_keep_the_resolved_context() -> None:
    """The service/session seam must not reconstruct caller identity later."""
    root = Path(__file__).parents[1]
    session_text = (root / 'aivm/attachments/session.py').read_text(
        encoding='utf-8'
    )
    connect_text = (root / 'aivm/cli/vm_connect.py').read_text(
        encoding='utf-8'
    )
    services_text = (root / 'aivm/services.py').read_text(encoding='utf-8')

    assert 'def load_vm_context_with_path(' in services_text
    assert 'def resolve_context_for_code(' in services_text
    assert 'context: ResolvedVMContext' in services_text
    assert 'resolve_context_for_code(' in session_text
    assert 'resolve_cfg_for_code(' not in session_text
    assert 'session.context' in connect_text
    assert 'session.cfg' not in connect_text
