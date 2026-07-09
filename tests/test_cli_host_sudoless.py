"""Tests for `aivm host sudoless setup`: host work, no policy writes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pytest import CaptureFixture, MonkeyPatch

from aivm.cli.host_sudoless import SudolessSetupCLI
from aivm.config import AgentVMConfig
from aivm.config_store import load_store, save_store
from aivm.config_store.models import Store, VMEntry
from tests.helpers import FakeProc, activate_manager


def _store_with_vm(cfg_path: Path, *, privilege_mode: str) -> Store:
    """Persist a store whose policy setup must not touch."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg.firewall.enabled = True
    store = Store(
        active_vm='vm-a',
        vms=[VMEntry(name='vm-a', network_name='aivm-net', cfg=cfg)],
    )
    store.behavior.privilege_mode = privilege_mode
    save_store(store, cfg_path, reason='test fixture')
    return store


def _stub_host_probes(monkeypatch: MonkeyPatch) -> list[list[str]]:
    """Pretend the libvirt group is already joined and qemu can traverse.

    Returns the list that every executed command argv is recorded into.
    """
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.qemu_traversal_blockers', lambda p: []
    )
    ran: list[list[str]] = []

    def fake_run(cmd: list[str], **kw: Any) -> FakeProc:
        ran.append([str(c) for c in cmd])
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_run)
    return ran


def test_setup_writes_no_config_by_default(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Setup establishes host capability and leaves policy alone."""
    activate_manager(monkeypatch, yes=True)
    _stub_host_probes(monkeypatch)
    cfg_path = tmp_path / 'config.toml'
    _store_with_vm(cfg_path, privilege_mode='as-needed')
    before = cfg_path.read_bytes()
    base_dir = tmp_path / 'vmstore'

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), base_dir=str(base_dir), yes=True
    )

    assert rc == 0
    assert cfg_path.read_bytes() == before, 'setup rewrote the config store'
    reg = load_store(cfg_path)
    assert reg.behavior.privilege_mode == 'as-needed'
    assert reg.defaults is None
    assert reg.vms[0].cfg.firewall.enabled is True

    out = capsys.readouterr().out
    # It must say what to change rather than changing it.
    assert 'Nothing in your config changed' in out
    assert '[defaults.paths]' in out
    assert f'base_dir = "{base_dir}"' in out


def _add_defaults(cfg_path: Path, store: Store, base_dir: str) -> None:
    store.defaults = AgentVMConfig()
    store.defaults.vm.name = 'chosen-name'
    store.defaults.paths.base_dir = base_dir
    save_store(store, cfg_path, reason='add defaults')


def test_setup_persist_writes_only_base_dir(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """--persist writes base_dir and nothing else."""
    activate_manager(monkeypatch, yes=True)
    _stub_host_probes(monkeypatch)
    cfg_path = tmp_path / 'config.toml'
    store = _store_with_vm(cfg_path, privilege_mode='as-needed')
    _add_defaults(cfg_path, store, '/var/lib/libvirt/aivm')
    base_dir = tmp_path / 'vmstore'

    rc = SudolessSetupCLI.main(
        argv=False,
        config=str(cfg_path),
        base_dir=str(base_dir),
        persist=True,
        yes=True,
    )

    assert rc == 0
    reg = load_store(cfg_path)
    assert reg.defaults is not None
    assert reg.defaults.paths.base_dir == str(base_dir)
    # The lossy writes the old setup made must not reappear, and no unrelated
    # default may be rewritten on the way past.
    assert reg.behavior.privilege_mode == 'as-needed'
    assert reg.defaults.firewall.enabled is True
    assert reg.defaults.vm.name == 'chosen-name'
    assert reg.vms[0].cfg.firewall.enabled is True


def test_setup_persist_refuses_to_materialize_a_defaults_section(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Creating [defaults] to hold one path would pin every other default.

    Notably ``vm.name``, whose factory derives a value from the hostname.
    """
    activate_manager(monkeypatch, yes=True)
    ran = _stub_host_probes(monkeypatch)
    cfg_path = tmp_path / 'config.toml'
    _store_with_vm(cfg_path, privilege_mode='as-needed')
    before = cfg_path.read_bytes()
    base_dir = tmp_path / 'vmstore'

    rc = SudolessSetupCLI.main(
        argv=False,
        config=str(cfg_path),
        base_dir=str(base_dir),
        persist=True,
        yes=True,
    )

    assert rc == 2
    assert cfg_path.read_bytes() == before
    assert load_store(cfg_path).defaults is None
    out = capsys.readouterr().out
    assert 'no [defaults] section' in out
    assert '[defaults.paths]' in out
    # The host work still happened; only the config write was declined.
    assert any(c[:2] == ['mkdir', '-p'] for c in ran)
    assert any(c[0] == 'setfacl' for c in ran)


def test_setup_never_disables_the_firewall_under_never_mode(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A never-sudo config gets a warning about nftables, not a silent disable."""
    activate_manager(monkeypatch, yes=True, privilege_mode='never')
    _stub_host_probes(monkeypatch)
    cfg_path = tmp_path / 'config.toml'
    _store_with_vm(cfg_path, privilege_mode='never')
    before = cfg_path.read_bytes()
    base_dir = tmp_path / 'vmstore'

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), base_dir=str(base_dir), yes=True
    )

    assert rc == 0
    assert cfg_path.read_bytes() == before
    reg = load_store(cfg_path)
    assert reg.vms[0].cfg.firewall.enabled is True
    assert reg.behavior.privilege_mode == 'never'
    out = capsys.readouterr().out
    assert 'firewall.enabled is true' in out


def test_setup_reports_no_config_gap_when_base_dir_already_resolves(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Preparing the already-configured base_dir implies no config change."""
    activate_manager(monkeypatch, yes=True)
    _stub_host_probes(monkeypatch)
    cfg_path = tmp_path / 'config.toml'
    base_dir = tmp_path / 'vmstore'
    store = _store_with_vm(cfg_path, privilege_mode='as-needed')
    store.defaults = AgentVMConfig()
    store.defaults.paths.base_dir = str(base_dir)
    save_store(store, cfg_path, reason='pin base_dir')
    before = cfg_path.read_bytes()

    rc = SudolessSetupCLI.main(argv=False, config=str(cfg_path), yes=True)

    assert rc == 0
    assert cfg_path.read_bytes() == before
    out = capsys.readouterr().out
    assert 'Nothing in your config needs to change' in out


def test_setup_reads_persisted_mode_not_its_own_escalation_manager(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Setup swaps in an `as-needed` manager to run usermod; the report must not.

    The policy report describes what the user chose, so it reads the store
    rather than the manager setup is currently running under.
    """
    activate_manager(monkeypatch, yes=True, privilege_mode='never')
    _stub_host_probes(monkeypatch)
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: False
    )
    cfg_path = tmp_path / 'config.toml'
    _store_with_vm(cfg_path, privilege_mode='never')

    rc = SudolessSetupCLI.main(
        argv=False,
        config=str(cfg_path),
        base_dir=str(tmp_path / 'vmstore'),
        yes=True,
        yes_sudo=True,
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "behavior.privilege_mode = 'never'" in out
    assert "= 'as-needed'" not in out


def test_setup_dry_run_touches_nothing(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    activate_manager(monkeypatch, yes=True)
    _stub_host_probes(monkeypatch)
    cfg_path = tmp_path / 'config.toml'
    store = _store_with_vm(cfg_path, privilege_mode='as-needed')
    _add_defaults(cfg_path, store, '/var/lib/libvirt/aivm')
    before = cfg_path.read_bytes()
    base_dir = tmp_path / 'vmstore'

    def explode(*a: Any, **k: Any) -> None:
        raise AssertionError('dry_run must not execute commands')

    monkeypatch.setattr('aivm.commands.subprocess.run', explode)
    rc = SudolessSetupCLI.main(
        argv=False,
        config=str(cfg_path),
        base_dir=str(base_dir),
        persist=True,
        dry_run=True,
        yes=True,
    )

    assert rc == 0
    assert cfg_path.read_bytes() == before
    assert not base_dir.exists()
