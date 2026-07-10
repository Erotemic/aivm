"""Tests for top-level status CLI behavior."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from aivm.cli.main import StatusCLI
from aivm.config import AgentVMConfig
from aivm.config_store import Store, save_store
from aivm.errors import AIVMError
from aivm.status import (
    ProbeOutcome,
    anticipated_status_sudo_commands,
    render_global_status,
)

main_mod = importlib.import_module('aivm.cli.main')

_BROKEN_STORE = """\
schema_version = 7
active_vm = "ghost"
[[vms]]
name = "ghost"
network_name = "aivm-net"
[vms.vm]
name = "ghost"
"""


def test_status_surfaces_config_errors(tmp_path: Path) -> None:
    """A store that parses but does not resolve must not look like "no context".

    ``AIVMError`` subclasses ``RuntimeError``, so a broad ``except RuntimeError``
    around VM resolution swallows a real, actionable config error and renders
    the benign global-status fallback in its place.
    """
    store = tmp_path / 'config.toml'
    store.write_text(_BROKEN_STORE, encoding='utf-8')
    with pytest.raises(AIVMError, match="unknown network 'aivm-net'"):
        StatusCLI.main(argv=False, config=str(store), vm='ghost')


def test_status_falls_back_when_store_defines_no_vms(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """The fallback survives: an empty store genuinely has no VM context."""
    store = tmp_path / 'config.toml'
    store.write_text('schema_version = 7\n', encoding='utf-8')
    rc = StatusCLI.main(argv=False, config=str(store))
    assert rc == 0
    assert 'No VM context resolved for this directory.' in capsys.readouterr().out


def test_status_cli_uses_vm_opt_and_sudo(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'chosen-vm'
    cfg_path = tmp_path / 'config.toml'

    called: dict[str, object] = {}  # type: ignore

    def fake_load_cfg_with_path(
        config: str | None, vm_opt: str = ''
    ) -> tuple[AgentVMConfig, Path]:
        called['vm_opt'] = vm_opt
        return cfg, cfg_path

    monkeypatch.setattr(
        main_mod,
        'load_cfg_with_path',
        fake_load_cfg_with_path,
    )
    monkeypatch.setattr(main_mod, 'cfg_path', lambda _: cfg_path)
    monkeypatch.setattr(
        main_mod.CommandManager,
        'confirm_sudo_scope',
        lambda self, **k: called.setdefault('sudo', k),
    )
    monkeypatch.setattr(
        main_mod,
        'render_status',
        lambda cfg_arg, path_arg, *, detail, use_sudo: (
            called.setdefault(
                'render', (cfg_arg.vm.name, path_arg, detail, use_sudo)
            )
            or 'status'
        ),
    )

    rc = StatusCLI.main(
        argv=False,
        config=str(cfg_path),
        vm='chosen-vm',
        sudo=True,
        detail=False,
        yes=False,
    )
    assert rc == 0
    assert called['vm_opt'] == 'chosen-vm'
    assert (called['sudo']['purpose']).startswith(  # type: ignore
        'Inspect host/libvirt/firewall/VM state'
    )
    assert (called['sudo']['preview_cmds']) == anticipated_status_sudo_commands(  # type: ignore
        cfg, detail=False
    )
    assert called['render'] == ('chosen-vm', cfg_path, False, True)


def test_status_never_mode_ignores_sudo_flag(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """`--sudo` cannot override privilege_mode=never; it downgrades to probes.

    This branch compares against PrivilegeMode.NEVER. A regression to a bare
    mode string would make it dead code and silently escalate.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'chosen-vm'
    cfg_path = tmp_path / 'config.toml'
    # The mode must come from the store: _BaseCommand.cli() builds the active
    # CommandManager from it, overwriting any manager activated beforehand.
    store = Store()
    store.behavior.privilege_mode = 'never'
    save_store(store, cfg_path, reason='never-mode fixture')
    called: dict[str, object] = {}

    def fake_render(
        cfg_arg: AgentVMConfig, path_arg: Path, *, detail: bool, use_sudo: bool
    ) -> str:
        called['use_sudo'] = use_sudo
        return 'status'

    monkeypatch.setattr(
        main_mod, 'load_cfg_with_path', lambda config, vm_opt='': (cfg, cfg_path)
    )
    monkeypatch.setattr(main_mod, 'cfg_path', lambda _: cfg_path)
    monkeypatch.setattr(
        main_mod.CommandManager,
        'confirm_sudo_scope',
        lambda self, **k: called.setdefault('sudo_scope', k),
    )
    monkeypatch.setattr(main_mod, 'render_status', fake_render)

    rc = StatusCLI.main(
        argv=False, config=str(cfg_path), vm='chosen-vm', sudo=True, yes=True
    )

    assert rc == 0
    assert called['use_sudo'] is False, '--sudo survived privilege_mode=never'
    assert 'sudo_scope' not in called, 'never mode must not preflight sudo'
    assert 'ignoring --sudo' in capsys.readouterr().out


def test_render_global_status_wording(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr('aivm.status.check_commands', lambda: ([], []))
    monkeypatch.setattr(
        'aivm.status.probe_runtime_environment',
        lambda: ProbeOutcome(True, 'ok', ''),
    )
    monkeypatch.setattr('aivm.status.store_path', lambda: 'dummy.toml')
    monkeypatch.setattr('aivm.status.load_store', lambda _: Store())
    text = render_global_status()
    assert 'No VM context resolved for this directory.' in text
