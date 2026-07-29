"""Synthetic end-to-end coverage for the stage 0/1 shared-machine seam.

These tests intentionally stop at captured process boundaries.  They exercise
real store parsing, VM selection, context resolution, attachment resolution,
and prepared-session construction without calling libvirt, sudo, or SSH.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import aivm.legacy.pre_0_6_0.context as legacy_context_mod
from aivm.attachments.session import (
    ReconcileResult,
    _prepare_attached_session,
)
from aivm.config_store import load_store, save_store, upsert_attachment
from aivm.services import load_vm_context_with_path
from .scenario import SharedMachineScenario, SyntheticPrincipal


def _select_host_principal(
    monkeypatch: pytest.MonkeyPatch, principal: SyntheticPrincipal
) -> None:
    monkeypatch.setattr(
        legacy_context_mod.getpass,
        'getuser',
        lambda: principal.host_user,
    )
    monkeypatch.setattr(legacy_context_mod, '_host_uid', lambda: principal.host_uid)
    monkeypatch.setattr(legacy_context_mod, '_host_gid', lambda: principal.host_gid)


def test_two_user_stores_resolve_one_machine_and_distinct_principals(
    monkeypatch: pytest.MonkeyPatch,
    shared_machine_scenario: SharedMachineScenario,
) -> None:
    scenario = shared_machine_scenario
    original_bytes = {
        p.host_user: p.config_path.read_bytes()
        for p in (scenario.alice, scenario.bob)
    }

    contexts = {}
    for principal in (scenario.alice, scenario.bob):
        _select_host_principal(monkeypatch, principal)
        context, path = load_vm_context_with_path(
            str(principal.config_path),
            vm_opt=scenario.vm_name,
            host_src=principal.host_src,
            hydrate_runtime_defaults=False,
            persist_runtime_defaults=False,
        )
        contexts[principal.host_user] = context
        assert path == principal.config_path.resolve()
        assert context.principal.host_user == principal.host_user
        assert context.principal.host_uid == principal.host_uid
        assert context.principal.host_gid == principal.host_gid
        assert context.guest_user == principal.guest_user

    alice = contexts['alice']
    bob = contexts['bob']
    assert alice.machine == bob.machine
    assert alice.principal != bob.principal
    assert alice.profile != bob.profile
    assert alice.machine.vm.name == scenario.vm_name
    assert alice.profile.ssh_identity_file != bob.profile.ssh_identity_file

    for principal in (scenario.alice, scenario.bob):
        assert principal.config_path.read_bytes() == original_bytes[principal.host_user]


def test_prepared_sessions_keep_selected_principal_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    shared_machine_scenario: SharedMachineScenario,
) -> None:
    scenario = shared_machine_scenario

    def fake_reconcile(cfg, host_src, attachment, *, policy, config_store_path):
        del cfg, host_src, policy, config_store_path
        return ReconcileResult(
            attachment=attachment,
            cached_ip=None,
            cached_ssh_ok=False,
        )

    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm', fake_reconcile
    )

    sessions = {}
    for principal in (scenario.alice, scenario.bob):
        _select_host_principal(monkeypatch, principal)
        session = _prepare_attached_session(
            config_opt=str(principal.config_path),
            vm_opt=scenario.vm_name,
            host_src=principal.host_src,
            guest_dst_opt=f'/home/{principal.guest_user}/code/project',
            attach_mode_opt='shared',
            attach_access_opt='rw',
            recreate_if_needed=False,
            ensure_firewall_opt=False,
            dry_run=True,
            yes=True,
        )
        sessions[principal.host_user] = session
        assert session.context.principal.host_user == principal.host_user
        assert session.context.guest_user == principal.guest_user
        assert session.context.profile.ssh_identity_file == str(
            principal.home / '.ssh' / 'id_aivm_ed25519'
        )
        assert session.share_guest_dst == (
            f'/home/{principal.guest_user}/code/project'
        )
        # Transitional compatibility remains available, but identity is carried
        # by the context rather than reconstructed by the caller.
        assert session.cfg is session.context.effective_cfg

    assert sessions['alice'].context.machine == sessions['bob'].context.machine
    assert sessions['alice'].context.principal != sessions['bob'].context.principal


def test_released_shadow_stores_expose_partial_attachment_inventory(
    shared_machine_scenario: SharedMachineScenario,
) -> None:
    """Characterize the split-brain state the machine store must eliminate."""
    scenario = shared_machine_scenario
    for principal in (scenario.alice, scenario.bob):
        store = load_store(principal.config_path)
        upsert_attachment(
            store,
            host_path=principal.host_src,
            vm_name=scenario.vm_name,
            mode='shared',
            guest_dst=f'/home/{principal.guest_user}/code/project',
        )
        save_store(store, principal.config_path)

    alice_store = load_store(scenario.alice.config_path)
    bob_store = load_store(scenario.bob.config_path)

    assert [a.host_path for a in alice_store.attachments] == [
        str(scenario.alice.host_src.resolve())
    ]
    assert [a.host_path for a in bob_store.attachments] == [
        str(scenario.bob.host_src.resolve())
    ]
    assert alice_store.attachments != bob_store.attachments
    assert alice_store.vms[0].name == bob_store.vms[0].name == scenario.vm_name
