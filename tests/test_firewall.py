"""Tests for ``aivm.firewall`` nftables script generation and application."""

from __future__ import annotations

from pytest import MonkeyPatch

from aivm.config import AgentVMConfig
from aivm.firewall import (
    _effective_bridge_and_gateway,
    _nft_script,
    apply_firewall,
    effective_firewall_table,
    ensure_firewall_ready,
    firewall_status,
)
from tests.helpers import (
    CommandRecorder,
    FakeProc,
    activate_manager,
    capture_logs,
    command_recorder,
)


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
        lambda cmd, **kwargs: (
            calls.append((cmd, kwargs))
            or FakeProc(stdout='table inet aivm_fw {}')
        ),
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


def _fw_scenario(
    monkeypatch: MonkeyPatch,
    *,
    sudo_ok: bool,
    table_present: bool,
) -> tuple[AgentVMConfig, CommandRecorder, list[str]]:
    """One host account facing one live nftables state.

    ``sudo_ok=False`` is the shared-workstation default: a member of the
    libvirt group with no sudoers entry, for whom every ``sudo`` invocation
    fails before the wrapped program starts.
    """
    cfg = AgentVMConfig()
    activate_manager(monkeypatch, yes_sudo=True)

    def route(normalized: list[str]) -> FakeProc:
        if not sudo_ok:
            # sudo declines before the wrapped program starts, so nothing is
            # ever observed about the table -- which is the whole point.
            return FakeProc(1, '', 'sudo: a password is required\n')
        if normalized[:3] == ['nft', 'list', 'table']:
            if table_present:
                return FakeProc(0, 'table inet x { }\n')
            return FakeProc(1, '', 'Error: No such file or directory\n')
        return FakeProc(0)

    rec = command_recorder(monkeypatch, default=route)
    warnings = capture_logs(
        monkeypatch, 'aivm.firewall.log', levels=('warning',)
    )
    return cfg, rec, warnings


def test_unverifiable_firewall_is_not_treated_as_a_missing_one(
    monkeypatch: MonkeyPatch,
) -> None:
    """A caller who cannot read nftables must not trigger a repair.

    This is the shared-workstation case: an administrator installed the
    table, and an ordinary libvirt-group user cannot see it because ``nft``
    has no unprivileged read. Inferring "absent" from that silence would
    schedule an install the caller cannot perform and abort a session that
    had nothing wrong with it.
    """
    cfg, rec, warnings = _fw_scenario(
        monkeypatch, sudo_ok=False, table_present=True
    )

    ensure_firewall_ready(cfg)

    assert not rec.ran('nft', '-f')
    assert not rec.ran('nft', 'delete')
    joined = '\n'.join(warnings)
    assert 'UNVERIFIED' in joined
    assert 'sudo aivm firewall apply' in joined


def test_unverifiable_firewall_never_blocks_the_caller(
    monkeypatch: MonkeyPatch,
) -> None:
    """Being unable to check the firewall must not stop the user working."""
    cfg, _rec, _warnings = _fw_scenario(
        monkeypatch, sudo_ok=False, table_present=False
    )

    # Returns rather than raising: the whole point is that a blind spot in
    # the firewall check is not a reason to refuse a session.
    ensure_firewall_ready(cfg)


def test_missing_firewall_is_installed_when_the_caller_can(
    monkeypatch: MonkeyPatch,
) -> None:
    cfg, rec, warnings = _fw_scenario(
        monkeypatch, sudo_ok=True, table_present=False
    )
    monkeypatch.setattr(
        'aivm.firewall._effective_bridge_and_gateway',
        lambda _cfg: ('virbr-aivm', '10.77.0.1'),
    )

    ensure_firewall_ready(cfg)

    assert rec.ran('nft', '-f')
    assert not warnings


def test_present_firewall_is_left_alone(monkeypatch: MonkeyPatch) -> None:
    cfg, rec, warnings = _fw_scenario(
        monkeypatch, sudo_ok=True, table_present=True
    )

    ensure_firewall_ready(cfg)

    assert not rec.ran('nft', '-f')
    assert not warnings


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
