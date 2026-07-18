"""Tests for ``aivm.firewall`` nftables script generation and application."""

from __future__ import annotations

from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.firewall import (
    _effective_bridge_and_gateway,
    _nft_script,
    apply_firewall,
    effective_firewall_table,
    firewall_status,
)
from tests.helpers import FakeProc, activate_manager


def test_effective_bridge_and_gateway_prefers_live(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.network.name = 'aivm-net'
    cfg.network.bridge = 'virbr-aivm'
    cfg.network.gateway_ip = '10.77.0.1'

    live_xml = (
        '<network>'
        "<bridge name='virbr-live'/>"
        "<ip address='10.99.0.1'/>"
        '</network>'
    )
    activate_manager(monkeypatch, isatty=True)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: FakeProc(stdout=live_xml),
    )
    bridge, gateway = _effective_bridge_and_gateway(cfg)
    assert bridge == 'virbr-live'
    assert gateway == '10.99.0.1'


def test_nft_script_deduplicates_blocks(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.firewall.block_cidrs = ['10.0.0.0/8', '10.0.0.0/8']
    cfg.firewall.extra_block_cidrs = ['192.168.0.0/16', ' 192.168.0.0/16 ']
    monkeypatch.setattr(
        'aivm.firewall._effective_bridge_and_gateway',
        lambda _cfg: ('virbr-aivm', '10.77.0.1'),
    )
    script = _nft_script(cfg)
    assert script.count('10.0.0.0/8') == 1
    assert script.count('192.168.0.0/16') == 1


def test_nft_script_allows_configured_ports(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.firewall.allow_tcp_ports = [22, 2222, 22]
    cfg.firewall.allow_udp_ports = [53]
    monkeypatch.setattr(
        'aivm.firewall._effective_bridge_and_gateway',
        lambda _cfg: ('virbr-aivm', '10.77.0.1'),
    )
    script = _nft_script(cfg)
    assert 'iifname "virbr-aivm" tcp dport {22, 2222} accept' in script
    assert 'iifname "virbr-aivm" udp dport {53} accept' in script
    assert ('iifname "virbr-aivm" ip daddr {' in script) and (
        'tcp dport {22, 2222} accept' in script
    )


def test_nft_script_invalid_port_raises(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.firewall.allow_tcp_ports = [0]
    monkeypatch.setattr(
        'aivm.firewall._effective_bridge_and_gateway',
        lambda _cfg: ('virbr-aivm', '10.77.0.1'),
    )
    try:
        _nft_script(cfg)
    except RuntimeError as ex:
        assert 'range 1..65535' in str(ex)
    else:
        raise AssertionError('Expected RuntimeError for invalid firewall port')


def test_apply_firewall_disabled_skips(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.firewall.enabled = False
    apply_firewall(cfg, dry_run=False)


def test_firewall_status_uses_readonly_step(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    cfg.firewall.table = 'aivm_fw'
    calls = []

    activate_manager(monkeypatch, isatty=True)
    monkeypatch.setattr(
        'aivm.commands.subprocess.run',
        lambda cmd, **kwargs: calls.append((cmd, kwargs))
        or FakeProc(stdout='table inet aivm_fw {}'),
    )

    table = effective_firewall_table(cfg)
    text = firewall_status(cfg)

    assert text == 'table inet aivm_fw {}'
    assert calls == [
        (
            ['sudo', 'nft', 'list', 'table', 'inet', table],
            {
                'input': None,
                'capture_output': True,
                'text': True,
                'env': None,
                'timeout': None,
            },
        )
    ]


def test_apply_firewall_runs_delete_then_apply(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
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
    assert calls[0][0][:4] == ['nft', 'delete', 'table', 'inet']
    assert calls[1][0][:4] == ['nft', 'delete', 'table', 'inet']
    assert calls[2][0] == ['nft', '-f', '-']


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


def test_firewall_tables_are_isolated_per_network() -> None:
    cfg_a = AgentVMConfig()
    cfg_a.firewall.table = 'aivm_fw'
    cfg_a.network.name = 'net-a'
    cfg_a.network.bridge = 'virbr-a'
    cfg_a.network.subnet_cidr = '10.70.0.0/24'

    cfg_b = AgentVMConfig()
    cfg_b.firewall.table = 'aivm_fw'
    cfg_b.network.name = 'net-b'
    cfg_b.network.bridge = 'virbr-b'
    cfg_b.network.subnet_cidr = '10.80.0.0/24'

    assert effective_firewall_table(cfg_a) != effective_firewall_table(cfg_b)
    assert effective_firewall_table(cfg_a).startswith('aivm_fw_')
    assert effective_firewall_table(cfg_b).startswith('aivm_fw_')


def test_firewall_dry_run_does_not_probe_virsh(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg = AgentVMConfig()
    activate_manager(monkeypatch, isatty=True)

    def fail_run(*args: object, **kwargs: object) -> FakeProc:
        del args, kwargs
        raise AssertionError('firewall dry-run must not execute subprocesses')

    monkeypatch.setattr('aivm.commands.subprocess.run', fail_run)

    apply_firewall(cfg, dry_run=True)
