"""Tests for `aivm host sudoless`: setup's host work and check's verdicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pytest import CaptureFixture, MonkeyPatch

from aivm.cli.host_sudoless import SudolessCheckCLI, SudolessSetupCLI
from aivm.config import AgentVMConfig
from aivm.config_store import load_store, save_store, upsert_vm
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


# ---------------------------------------------------------------------------
# `aivm host sudoless check`
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
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.libvirt_unprivileged_ok', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.qemu_traversal_blockers',
        lambda p: list(blockers or []),
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.which', lambda name: f'/usr/bin/{name}'
    )
    if writable_dirs is None:
        monkeypatch.setattr(
            'aivm.cli.host_sudoless.user_can_write_path', lambda p: True
        )
    else:
        monkeypatch.setattr(
            'aivm.cli.host_sudoless.user_can_write_path',
            lambda p: str(p) in writable_dirs,
        )


def test_check_passes_never_mode_when_store_needs_no_sudo(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """The e2e shape: user-owned storage + firewall off + mode 'never' → 0.

    Regression test: check used to grade the built-in /var/lib default
    instead of the VM's actual base_dir, and read ``rec.cfg.firewall``
    (always the default True) instead of the network record's persisted
    value, so this exact store failed with rc 2.
    """
    cfg_path = tmp_path / 'config.toml'
    vmstore = tmp_path / 'vmstore'
    _check_store(
        cfg_path,
        privilege_mode='never',
        base_dir=str(vmstore),
        firewall_enabled=False,
    )
    _stub_check_probes(monkeypatch)

    rc = SudolessCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 0, out
    assert '✅ Host is ready for sudoless operation.' in out
    assert str(vmstore) in out
    assert '/var/lib/libvirt/aivm' not in out
    assert 'firewall disabled; nothing needs root' in out


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

    rc = SudolessCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 0, out
    assert '❌' not in out
    assert '⚠️' in out
    assert 'sudo will be used for:' in out
    assert 'the nftables firewall' in out
    assert 'VM storage under /var/lib/libvirt/aivm' in out


def test_check_fails_never_mode_when_sudo_would_be_needed(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """The same friction is a hard failure once the user chose 'never'."""
    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='never',
        base_dir='/var/lib/libvirt/aivm',
        firewall_enabled=True,
    )
    _stub_check_probes(monkeypatch, writable_dirs=set())

    rc = SudolessCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 2, out
    assert '❌' in out
    assert "privilege_mode = 'never' cannot be honored yet" in out


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

    rc = SudolessCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 2, out
    assert 'Broken in every privilege mode' in out


def test_firewall_enabled_anywhere_reads_network_records(
    tmp_path: Path,
) -> None:
    """The persisted firewall truth lives on ``[[networks]]``, not vm cfgs."""
    from aivm.cli.host_sudoless import _firewall_enabled_anywhere

    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='never',
        base_dir=str(tmp_path / 'vmstore'),
        firewall_enabled=False,
    )
    assert _firewall_enabled_anywhere(str(cfg_path)) is False

    _check_store(
        cfg_path,
        privilege_mode='never',
        base_dir=str(tmp_path / 'vmstore'),
        firewall_enabled=True,
    )
    assert _firewall_enabled_anywhere(str(cfg_path)) is True


# ---------------------------------------------------------------------------
# `aivm host sudoless setup --adopt`
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
    tree = (tmp_path / 'rootish-store').resolve()
    tree.mkdir()
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tree),
        firewall_enabled=False,
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_can_write_path',
        lambda p: str(p) != str(tree),
    )
    # The post-adopt traversal verification probes real host state (o+x /
    # ACLs), which a sandboxed tmp tree cannot satisfy deterministically.
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.qemu_traversal_blockers', lambda p: []
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
    """A running VM is stopped, the tree group-owned, and the VM restarted.

    The ordering matters: libvirt restores the disk ownership it recorded
    at start, so the chgrp must land while the VM is off.  The privileged
    script is the artifact: chgrp/chmod/setgid on exactly the adopted tree.
    """
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='running'
    )
    before = cfg_path.read_bytes()

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    # The store is untouched: adoption changes ownership, not config.
    assert cfg_path.read_bytes() == before

    script = [c for c in rec.normalized if c[:2] == ['bash', '-c']][0][-1]
    assert f'tree={tree}' in script
    assert 'chgrp libvirt' in script
    assert 'chmod g+rwX' in script
    assert 'chmod g+s' in script
    # Never a blanket recursive pass: every operation goes through find
    # with the mountpoint prune list, computed from the kernel mount table
    # at execution time (binds of user folders live under the tree).
    assert 'chgrp -R' not in script
    assert 'chmod -R' not in script
    assert '/proc/self/mounts' in script
    assert script.count('"${prune[@]}"') == 3
    assert '! -type l' in script
    # The handoff runs escalated, between shutdown and restart.
    raw_bash = [c for c in rec.calls if 'bash' in c[:3]][0]
    assert raw_bash[0] == 'sudo'
    order = [c[:2] for c in rec.normalized]
    assert order.index(['virsh', 'shutdown']) < order.index(['bash', '-c'])
    assert order.index(['bash', '-c']) < order.index(['virsh', 'start'])
    assert 'Stopping vm-a first' in out
    assert 'restarts as soon as the handoff is done' in out


def test_adopt_leaves_stopped_vm_alone(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A VM that is already off is not started by adoption."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='shut off'
    )

    rc = SudolessSetupCLI.main(
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
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_can_write_path', lambda p: False
    )
    rec = command_recorder(monkeypatch, {})  # strict: any command raises

    rc = SudolessSetupCLI.main(
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
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    rec = command_recorder(monkeypatch, {})  # strict: any command raises

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 0
    assert 'Nothing to adopt' in out
    assert rec.normalized == []


def test_attachment_mounts_under_decodes_and_filters(tmp_path: Path) -> None:
    """Mount enumeration keeps strictly-below targets, decoding \\040."""
    from aivm.cli.host_sudoless import _attachment_mounts_under

    tree = tmp_path / 'storage'
    mounts = tmp_path / 'mounts'
    mounts.write_text(
        # outside the tree: ignored
        '/dev/sda1 / ext4 rw 0 0\n'
        f'/dev/sda1 {tmp_path}/elsewhere ext4 rw 0 0\n'
        # the tree itself (not strictly below): ignored
        f'/dev/sda1 {tree} ext4 rw 0 0\n'
        # binds below the tree: returned, octal escapes decoded
        f'/dev/sda1 {tree}/vm/persistent-root/hostcode-a ext4 rw 0 0\n'
        f'/dev/sdb1 {tree}/vm/shared-root/with\\040space ext4 rw 0 0\n',
        encoding='utf-8',
    )

    got = _attachment_mounts_under(tree, mounts_path=str(mounts))

    assert got == [
        f'{tree}/vm/persistent-root/hostcode-a',
        f'{tree}/vm/shared-root/with space',
    ]


def test_adopt_lists_bind_mounts_it_will_exclude(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """The preflight names every excluded bind before anything runs."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='shut off'
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless._attachment_mounts_under',
        lambda t, **k: [
            f'{t}/vm-a/persistent-root/hostcode-proj',
            f'{t}/vm-a/shared-root/hostcode-docs',
        ],
    )

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    assert '2 attached folder(s) are bind-mounted under this tree' in out
    assert 'persistent-root/hostcode-proj' in out
    assert 'shared-root/hostcode-docs' in out
    assert any(c[:2] == ['bash', '-c'] for c in rec.normalized)


def test_adopt_refuses_mountpoints_find_cannot_match(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A glob-metacharacter mountpoint cannot be pruned reliably: refuse."""
    from tests.helpers import command_recorder

    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path = tmp_path / 'config.toml'
    tree = tmp_path / 'storage'
    tree.mkdir()
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tree),
        firewall_enabled=False,
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_can_write_path',
        lambda p: str(p) != str(tree),
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless._attachment_mounts_under',
        lambda t, **k: [f'{t}/vm-a/persistent-root/host*code'],
    )
    rec = command_recorder(monkeypatch, {})  # strict: any command raises

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 2
    assert 'cannot be safely excluded' in out
    assert 'Detach those folders first' in out
    assert rec.normalized == []


def test_check_never_recommends_disabling_the_firewall(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Firewall sudo is presented as inherent, never as a thing to disable.

    The firewall is the guest's egress containment; check must not hand out
    'disable it' as a convenience tip.  With everything else green the
    verdict also must not point at `sudoless setup`, which cannot remove
    this item.
    """
    cfg_path = tmp_path / 'config.toml'
    _check_store(
        cfg_path,
        privilege_mode='as-needed',
        base_dir=str(tmp_path / 'mine'),
        firewall_enabled=True,
    )
    _stub_check_probes(monkeypatch)

    rc = SudolessCheckCLI.main(argv=False, config=str(cfg_path))

    out = capsys.readouterr().out
    assert rc == 0, out
    assert 'disable' not in out.lower()
    assert 'egress containment' in out
    assert 'not a problem to fix' in out
    assert 'sudoless setup' not in out  # nothing setup-fixable remains
    # A wall, not a warning: no amount of setup removes this item.
    assert '🧱 firewall compatibility' in out
    assert '⚠️' not in out


def test_adopt_aborts_when_vm_state_cannot_be_determined(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """An unreadable VM state must abort before any mutation.

    A running-but-unseen VM would silently undo the ownership handoff at
    its next shutdown, so 'probe failed' may never be read as 'stopped'.
    """
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='running'
    )
    rec.route(
        'virsh domstate',
        FakeProc(1, '', 'error: failed to connect to the hypervisor'),
    )

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 2, out
    assert 'Cannot determine the state of VM' in out
    assert 'Aborting before any change' in out
    assert not any(c[:2] == ['bash', '-c'] for c in rec.normalized)
    assert not any(c[:2] == ['virsh', 'shutdown'] for c in rec.normalized)


def test_adopt_treats_missing_domain_as_stopped(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A store record without a defined domain is normal; adoption proceeds."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='running'
    )
    rec.route(
        'virsh domstate',
        FakeProc(1, '', "error: failed to get domain 'vm-a'"),
    )

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    assert rc == 0
    assert any(c[:2] == ['bash', '-c'] for c in rec.normalized)
    assert not any(c[:2] == ['virsh', 'shutdown'] for c in rec.normalized)
    assert not any(c[:2] == ['virsh', 'start'] for c in rec.normalized)


def test_adopt_restarts_stopped_vm_when_the_handoff_fails(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """A failing privileged script must not strand the VM it stopped."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='running'
    )
    rec.route('bash -c', FakeProc(1, '', 'chgrp: cannot access ...'))

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 2, out
    assert 'did not complete' in out
    order = [c[:2] for c in rec.normalized]
    assert order.index(['virsh', 'shutdown']) < order.index(['bash', '-c'])
    # The restart still ran, after the failure.
    assert order.index(['bash', '-c']) < order.index(['virsh', 'start'])


def test_adopt_requires_setfacl_before_touching_anything(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Group ownership alone does not grant qemu traversal; refuse early.

    libvirt-qemu is not a libvirt-group member, so without the ACLs the
    adopted tree may be untraversable and the VM unbootable.
    """
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='running'
    )
    monkeypatch.setattr('aivm.cli.host_sudoless.which', lambda name: None)

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 2, out
    assert 'needs setfacl' in out
    assert rec.normalized == []


def test_adopt_fails_when_traversal_still_blocked_after_handoff(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Success is verified, not assumed: blocked qemu traversal fails loudly."""
    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path, tree, rec = _adopt_env(
        monkeypatch, tmp_path, initial_state='shut off'
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.qemu_traversal_blockers', lambda p: [tree]
    )

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 2, out
    assert 'still cannot' in out


def test_adopt_canonicalizes_and_dedupes_storage_spellings(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    """Symlinked/dotted base_dir spellings resolve to one physical adoption.

    The mount table reports canonical paths, so the prune list (and the VM
    cycling set) must be keyed by the resolved tree: two VMs whose configs
    spell the same tree differently get one privileged pass, and the script
    receives the canonical path.
    """
    from tests.helpers import command_recorder

    activate_manager(monkeypatch, yes=True, yes_sudo=True)
    cfg_path = tmp_path / 'config.toml'
    real = (tmp_path / 'real-store').resolve()
    real.mkdir()
    link = tmp_path / 'alias'
    link.symlink_to(real)

    # Two VMs: one via the symlink, one via a dotted spelling.
    cfg_a = AgentVMConfig()
    cfg_a.vm.name = 'vm-a'
    cfg_a.firewall.enabled = False
    cfg_a.paths.base_dir = str(link)
    cfg_b = AgentVMConfig()
    cfg_b.vm.name = 'vm-b'
    cfg_b.firewall.enabled = False
    cfg_b.paths.base_dir = str(tmp_path / 'x' / '..' / 'real-store')
    store = Store()
    store.behavior.privilege_mode = 'as-needed'
    upsert_vm(store, cfg_a)
    upsert_vm(store, cfg_b)
    save_store(store, cfg_path, reason='test fixture')

    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_in_libvirt_group', lambda: True
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.user_can_write_path',
        lambda p: str(p) != str(real),
    )
    monkeypatch.setattr(
        'aivm.cli.host_sudoless.qemu_traversal_blockers', lambda p: []
    )
    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, 'shut off\n'),
            'bash -c': FakeProc(0),
        },
    )

    rc = SudolessSetupCLI.main(
        argv=False, config=str(cfg_path), adopt=True, yes=True
    )

    out = capsys.readouterr().out
    assert rc == 0, out
    scripts = [c[-1] for c in rec.normalized if c[:2] == ['bash', '-c']]
    # One physical tree -> one privileged pass, on the canonical path.
    assert len(scripts) == 1
    assert f'tree={real}' in scripts[0]
    assert str(link) not in scripts[0]
    # Both VMs are grouped onto the resolved tree (probed once each).
    assert rec.count('virsh', 'domstate', 'vm-a') == 1
    assert rec.count('virsh', 'domstate', 'vm-b') == 1
