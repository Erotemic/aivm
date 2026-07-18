"""Tests for `aivm host permissions`: setup's host work and check's verdicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pytest import CaptureFixture, MonkeyPatch

from aivm.cli.host import HostModalCLI
from aivm.cli.host_permissions import (
    HostPermissionsCheckCLI,
    HostPermissionsModalCLI,
    HostPermissionsSetupCLI,
)
from aivm.config import AgentVMConfig
from aivm.config_store import load_store, save_store, upsert_vm
from aivm.config_store.models import Store, VMEntry
from tests.helpers import FakeProc, activate_manager


def test_host_permissions_command_has_no_compatibility_alias() -> None:
    registrations = {
        name
        for name, value in vars(HostModalCLI).items()
        if value is HostPermissionsModalCLI
    }
    assert registrations == {'permissions'}


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
        'aivm.cli.host_permissions.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.qemu_traversal_blockers', lambda p: []
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

    rc = HostPermissionsSetupCLI.main(
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

    rc = HostPermissionsSetupCLI.main(
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

    rc = HostPermissionsSetupCLI.main(
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

    rc = HostPermissionsSetupCLI.main(argv=False, config=str(cfg_path), yes=True)

    assert rc == 0
    assert cfg_path.read_bytes() == before
    out = capsys.readouterr().out
    assert 'Nothing in your config needs to change' in out


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
    rc = HostPermissionsSetupCLI.main(
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


# ---------------------------------------------------------------------------
# `aivm host permissions check`
# ---------------------------------------------------------------------------


def _check_store(
    cfg_path: Path,
    *,
    privilege_mode: str,
    base_dir: str,
    firewall_enabled: bool,
) -> None:
    """Persist a store the way real flows do (via ``upsert_vm``).

    ``upsert_vm`` splits the config across the ``[[vms]]`` record and its
    ``[[networks]]`` record (which owns the firewall settings); check must
    read the truth from that shape, not from ``rec.cfg`` defaults.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-a'
    cfg.firewall.enabled = firewall_enabled
    cfg.paths.base_dir = base_dir
    store = Store()
    store.behavior.privilege_mode = privilege_mode
    upsert_vm(store, cfg)
    save_store(store, cfg_path, reason='test fixture')


def _stub_check_probes(
    monkeypatch: MonkeyPatch,
    *,
    writable_dirs: set[str] | None = None,
    blockers: list[Path] | None = None,
) -> None:
    """Pin the host probes so check verdicts depend only on the store.

    ``writable_dirs=None`` means every dir is user-writable; otherwise only
    the listed ones are.  These probes (group membership, live libvirt, path
    ownership) read real host state, which is exactly what a unit test must
    not depend on.
    """
    monkeypatch.setattr(
        'aivm.cli.host_permissions.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.libvirt_without_sudo_ok', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.qemu_traversal_blockers',
        lambda p: list(blockers or []),
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.which', lambda name: f'/usr/bin/{name}'
    )
    if writable_dirs is None:
        monkeypatch.setattr(
            'aivm.cli.host_permissions.user_can_write_path', lambda p: True
        )
    else:
        monkeypatch.setattr(
            'aivm.cli.host_permissions.user_can_write_path',
            lambda p: str(p) in writable_dirs,
        )


def test_check_reports_friction_not_failure_under_as_needed(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Root-owned storage + firewall on is friction, not failure, by default.

    Under 'as-needed' those items render as ⚠️ with a summary of what sudo
    will be used for, and the exit code stays 0: sudo-where-needed is the
    configured policy working, not the host being broken.
    """
    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir='/var/lib/libvirt/aivm',
        firewall_enabled=True,
    )
    _stub_check_probes(monkeypatch, writable_dirs=set())

    rc = HostPermissionsCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 0, out
    assert '❌' not in out
    assert '⚠️' in out
    assert 'sudo will be used for:' in out
    assert 'the nftables firewall' in out
    assert 'VM storage under /var/lib/libvirt/aivm' in out


def test_check_fails_every_mode_on_qemu_traversal_blockers(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Blocked qemu traversal breaks VM start with or without sudo."""
    cfg_path = tmp_path / 'config.toml'
    vmstore = tmp_path / 'vmstore'
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(vmstore),
        firewall_enabled=False,
    )
    _stub_check_probes(monkeypatch, blockers=[tmp_path])

    rc = HostPermissionsCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 2, out
    assert 'Broken in every privilege mode' in out


def test_firewall_enabled_anywhere_reads_network_records(
    tmp_path: Path,
) -> None:
    """The persisted firewall truth lives on ``[[networks]]``, not vm cfgs."""
    from aivm.cli.host_permissions import _firewall_enabled_anywhere

    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tmp_path / 'vmstore'),
        firewall_enabled=False,
    )
    assert _firewall_enabled_anywhere(str(cfg_path)) is False

    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tmp_path / 'vmstore'),
        firewall_enabled=True,
    )
    assert _firewall_enabled_anywhere(str(cfg_path)) is True


# ---------------------------------------------------------------------------
# `aivm host permissions setup --adopt`
# ---------------------------------------------------------------------------


def _adopt_env(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    *,
    initial_state: str,
) -> tuple[Path, Path, Any]:
    """A store with one VM on a root-owned tree, plus a scripted recorder.

    ``initial_state`` is what ``virsh domstate`` reports until a
    ``virsh shutdown`` is recorded, after which it reports ``shut off`` --
    letting the real shutdown/wait code run against the fake boundary.
    """
    from tests.helpers import command_recorder

    cfg_path = tmp_path / 'config.toml'
    tree = tmp_path / 'rootish-store'
    tree.mkdir()
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tree),
        firewall_enabled=False,
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.user_can_write_path',
        lambda p: str(p) != str(tree),
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.which',
        lambda name: '/usr/bin/setfacl' if name == 'setfacl' else None,
    )
    monkeypatch.setattr('aivm.vm.domain.time.sleep', lambda s: None)

    state = {'value': initial_state}

    def domstate(cmd: list[str]) -> FakeProc:
        return FakeProc(0, state['value'] + '\n')

    def shutdown(cmd: list[str]) -> FakeProc:
        state['value'] = 'shut off'
        return FakeProc(0, '', '')

    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': domstate,
            'virsh shutdown': shutdown,
            'virsh start': FakeProc(0),
            'bash -c': FakeProc(0),
        },
    )
    return cfg_path, tree, rec


def test_adopt_cycles_running_vm_around_the_group_handoff(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A running VM is stopped, storage is adopted, and it is restarted."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='running'
    )
    before = cfg_path.read_bytes()

    rc = HostPermissionsSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    # The store is untouched: adoption changes ownership, not config.
    assert cfg_path.read_bytes() == before

    script = [c for c in rec.normalized if c[:2] == ['bash', '-c']][0][-1]
    assert 'os.walk' in script
    assert '/proc/self/mountinfo' in script
    assert "followlinks=False" in script
    assert str(tree) in script
    # The handoff runs escalated, between shutdown and restart.
    raw_bash = [c for c in rec.calls if 'bash' in c[:3]][0]
    assert raw_bash[0] == 'sudo'
    order = [c[:2] for c in rec.normalized]
    assert order.index(['virsh', 'shutdown']) < order.index(['bash', '-c'])
    assert order.index(['bash', '-c']) < order.index(['virsh', 'start'])
    assert 'Stopping vm-a first' in out
    assert 'will be restarted even if' in out


def test_adopt_leaves_stopped_vm_alone(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A VM that is already off is not started by adoption."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='shut off'
    )

    rc = HostPermissionsSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    assert rc == 0
    assert any(c[:2] == ['bash', '-c'] for c in rec.normalized)
    assert not any(c[:2] == ['virsh', 'shutdown'] for c in rec.normalized)
    assert not any(c[:2] == ['virsh', 'start'] for c in rec.normalized)


def test_adopt_refuses_shallow_system_paths(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """chgrp -R on something like /var/lib must be refused outright."""
    from tests.helpers import command_recorder

    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir='/var/lib',
        firewall_enabled=False,
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.user_can_write_path', lambda p: False
    )
    rec = command_recorder(monkeypatch, {})  # strict: any command raises

    rc = HostPermissionsSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 2
    assert 'Refusing to adopt /var/lib' in out
    assert rec.normalized == []


def test_adopt_reports_when_nothing_needs_adopting(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """All-writable storage means adoption runs no commands at all."""
    from tests.helpers import command_recorder

    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tmp_path / 'mine'),
        firewall_enabled=False,
    )
    monkeypatch.setattr(
        'aivm.cli.host_permissions.user_in_libvirt_group', lambda: True
    )
    rec = command_recorder(monkeypatch, {})  # strict: any command raises

    rc = HostPermissionsSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 0
    assert 'Nothing to adopt' in out
    assert rec.normalized == []
