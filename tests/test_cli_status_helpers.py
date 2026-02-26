from __future__ import annotations

from aivm.cli import _check_firewall, _check_network, _check_vm_state
from aivm.config import AgentVMConfig
from aivm.util import CmdResult


def test_check_network_parsing_and_permission(monkeypatch) -> None:
    cfg = AgentVMConfig()
    cfg.network.name = "aivm-net"

    monkeypatch.setattr(
        "aivm.cli.run_cmd",
        lambda *a, **k: CmdResult(1, "", "permission denied"),
    )
    ok, detail = _check_network(cfg, use_sudo=False)
    assert ok is None
    assert "status --sudo" in detail

    monkeypatch.setattr(
        "aivm.cli.run_cmd",
        lambda *a, **k: CmdResult(0, "Active: yes\nAutostart: no\n", ""),
    )
    ok, detail = _check_network(cfg, use_sudo=True)
    assert ok is True
    assert "autostart=no" in detail


def test_check_firewall_branches(monkeypatch) -> None:
    cfg = AgentVMConfig()
    cfg.firewall.enabled = False
    ok, detail = _check_firewall(cfg, use_sudo=False)
    assert ok is None
    assert "disabled" in detail

    cfg.firewall.enabled = True
    monkeypatch.setattr(
        "aivm.cli.run_cmd",
        lambda *a, **k: CmdResult(1, "", "operation not permitted"),
    )
    ok, detail = _check_firewall(cfg, use_sudo=False)
    assert ok is None
    assert "status --sudo" in detail

    monkeypatch.setattr("aivm.cli.run_cmd", lambda *a, **k: CmdResult(0, "", ""))
    ok, detail = _check_firewall(cfg, use_sudo=True)
    assert ok is True
    assert "present" in detail


def test_check_vm_state_branches(monkeypatch) -> None:
    cfg = AgentVMConfig()

    monkeypatch.setattr(
        "aivm.cli.run_cmd",
        lambda *a, **k: CmdResult(1, "", "authentication failed"),
    )
    ok, defined, detail = _check_vm_state(cfg, use_sudo=False)
    assert ok is None
    assert defined is False
    assert "status --sudo" in detail

    calls = []

    def fake_run_cmd(cmd, **kwargs):
        calls.append(cmd)
        if cmd[3] == "dominfo":
            return CmdResult(0, "ok", "")
        return CmdResult(0, "running", "")

    monkeypatch.setattr("aivm.cli.run_cmd", fake_run_cmd)
    ok, defined, detail = _check_vm_state(cfg, use_sudo=True)
    assert ok is True
    assert defined is True
    assert "state=running" in detail
    assert len(calls) == 2
