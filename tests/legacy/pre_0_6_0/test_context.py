"""Runtime adapter tests for stores written before AIVM 0.6.0."""

from __future__ import annotations

from aivm.config import AgentVMConfig
from aivm.legacy.pre_0_6_0.context import (
    resolve_pre_0_6_0_vm_context,
)


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

    alice_ctx = resolve_pre_0_6_0_vm_context(
        alice, host_user='alice', host_uid=1001, host_gid=1001
    )
    bob_ctx = resolve_pre_0_6_0_vm_context(
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
    ctx = resolve_pre_0_6_0_vm_context(
        cfg, host_user='alice', host_uid=1001, host_gid=1001
    )

    cfg.vm.cpus = 16
    cfg.network.name = 'changed-after-resolution'

    assert ctx.machine.vm.cpus == 8
    assert ctx.machine.network.name == 'aivm-net'
    assert ctx.effective_cfg is cfg
