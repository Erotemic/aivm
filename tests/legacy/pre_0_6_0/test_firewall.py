"""Firewall cleanup retained only for installations from before 0.6.0."""

from __future__ import annotations

from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.firewall import apply_firewall
from tests.helpers import FakeProc, activate_manager


def test_apply_firewall_cleans_up_the_pre_upgrade_table(
    monkeypatch: MonkeyPatch,
) -> None:
    """Upgrading from the un-namespaced table must not orphan it.

    Older aivm installed rules under cfg.firewall.table directly; the
    namespaced table now sits alongside it, and a leftover legacy table
    keeps dropping traffic (making allowlist edits look ineffective).
    Apply deletes both the current derived table and the legacy name.
    """
    from aivm.firewall import effective_firewall_table

    cfg = AgentVMConfig()
    cfg.firewall.table = 'aivm_sandbox'
    calls = []

    activate_manager(monkeypatch, yes_sudo=False, euid=0)
    monkeypatch.setattr(
        'aivm.firewall._effective_bridge_and_gateway',
        lambda _cfg: ('virbr-aivm', '10.77.0.1'),
    )
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append((cmd, kwargs)) or FakeProc(),
    )

    apply_firewall(cfg, dry_run=False)

    deleted = [
        c[0][4] for c in calls if c[0][:4] == ['nft', 'delete', 'table', 'inet']
    ]
    assert deleted == [effective_firewall_table(cfg), 'aivm_sandbox']
    # The freshly loaded ruleset must target only the namespaced table.
    load = next(c for c in calls if c[0] == ['nft', '-f', '-'])
    script = load[1]['input']
    assert effective_firewall_table(cfg) in script
    assert 'table inet aivm_sandbox ' not in script


def test_remove_firewall_cleans_up_the_pre_upgrade_table(
    monkeypatch: MonkeyPatch,
) -> None:
    """fw remove deletes the namespaced table and the legacy name."""
    from aivm.firewall import effective_firewall_table, remove_firewall

    cfg = AgentVMConfig()
    cfg.firewall.table = 'aivm_sandbox'
    calls = []

    activate_manager(monkeypatch, yes_sudo=False, euid=0)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append((cmd, kwargs)) or FakeProc(),
    )

    remove_firewall(cfg, dry_run=False)

    deleted = [
        c[0][4] for c in calls if c[0][:4] == ['nft', 'delete', 'table', 'inet']
    ]
    assert deleted == [effective_firewall_table(cfg), 'aivm_sandbox']
