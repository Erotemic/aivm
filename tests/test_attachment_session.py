"""Tests for the ``aivm vm attach`` CLI entry and ``_record_attachment``.

These drive ``VMAttachCLI``/``VMSSHCLI``/``VMCodeCLI`` at the command
boundary with the session seams stubbed, plus the ``_record_attachment``
persistence helper. The ``_prepare_attached_session``/``restore_*``
orchestration tests live in ``test_attachment_session_restore.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest

from aivm.attachments.session import _record_attachment
from aivm.cli.vm_attach import VMAttachCLI
from aivm.cli.vm_connect import VMSSHCLI, VMCodeCLI
from aivm.commands import SudoUnavailableError
from aivm.config import AgentVMConfig
from aivm.config_store import (
    AttachmentEntry,
    Store,
    load_store,
    save_store,
    upsert_attachment,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.errors import AIVMError
from aivm.status import ProbeOutcome
from aivm.util import CmdResult
from aivm.vm.share import AttachmentAccess, AttachmentMode, ResolvedAttachment
from tests.helpers import (
    FakeProc,
    activate_manager,
    command_recorder,
    is_locale_pinned,
    patch_ns,
    resolved_test_context,
    returns,
)

AttachEnv = tuple[AgentVMConfig, Path, Path, ResolvedAttachment]


def _only_attachment(cfg_path: Path) -> AttachmentEntry:
    """Return the single attachment record persisted at ``cfg_path``.

    Reading the store back is the observable artifact of a real
    ``_record_attachment`` call, replacing a stub that only proved the
    function was invoked.
    """
    records = load_store(cfg_path).attachments
    assert len(records) == 1, records
    return records[0]


@pytest.fixture
def make_attach_env(tmp_path: Path) -> Callable[..., AttachEnv]:
    """Build ``(cfg, cfg_path, host_src, attachment)`` for an attach test.

    Every ``test_vm_attach_*`` case opens with the same scaffold: a named
    VM config, a sandbox ``config.toml``, a freshly ``mkdir``'d host
    folder, and a matching :class:`ResolvedAttachment`. The keyword
    defaults describe the common ``shared``/``/workspace/proj`` case;
    override ``mode``/``guest_dst``/``tag``/``dirname`` as needed.
    """

    def _make(
        *,
        name: str,
        dirname: str = 'proj',
        mode: AttachmentMode = AttachmentMode.DIRECT_VIRTIOFS,
        guest_dst: str = '/workspace/proj',
        tag: str = 'hostcode-proj',
    ) -> AttachEnv:
        cfg = AgentVMConfig()
        cfg.vm.name = name
        cfg_path = tmp_path / 'config.toml'
        host_src = tmp_path / dirname
        host_src.mkdir()
        attachment = ResolvedAttachment(
            vm_name=cfg.vm.name,
            mode=mode,
            source_dir=str(host_src.resolve()),
            guest_dst=guest_dst,
            tag=tag,
        )
        return cfg, cfg_path, host_src, attachment

    return _make


def patch_vm_attach_env(
    monkeypatch: pytest.MonkeyPatch,
    cfg: AgentVMConfig,
    cfg_path: Path,
    attachment: ResolvedAttachment,
    *,
    running: bool | None,
) -> None:
    """Stub the four ``aivm.cli.vm_attach`` seams every attach test shares.

    Patches the resolved-context, persistence, and attachment seams
    unconditionally; ``probe_vm_state`` reports ``running`` unless it is
    ``None`` (the caller installs its own probe to inspect kwargs).
    """

    mapping: dict[str, Any] = {
        '_resolve_attach_context': returns(
            (resolved_test_context(cfg), cfg_path)
        ),
        'record_vm': returns(cfg_path),
        '_resolve_attachment': returns(attachment),
    }
    if running is not None:
        mapping['probe_vm_state'] = returns((ProbeOutcome(running, ''), True))
    patch_ns(monkeypatch, 'aivm.cli.vm_attach', mapping)


def _fake_prepare_session(
    cfg: AgentVMConfig,
    cfg_path: Any,
    host_src: Path,
    attachment: ResolvedAttachment,
    captured: list,
) -> Any:
    """Return a fake _prepare_attached_session callable that records its kwargs."""
    from aivm.services import PreparedSession

    def fake_prepare(**kw: Any) -> PreparedSession:
        captured.append(kw)
        return PreparedSession(
            context=resolved_test_context(cfg),
            cfg_path=cfg_path,
            host_src=kw['host_src'],
            attachment_mode=attachment.mode,
            share_source_dir=attachment.source_dir,
            share_tag=attachment.tag,
            share_guest_dst=attachment.guest_dst,
            ip='10.0.0.1',
            reg_path=cfg_path,
            meta_path=None,
        )

    return fake_prepare


def test_vm_attach_mounts_share_when_vm_running(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(name='vm-running')
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=True)
    monkeypatch.setattr(
        'aivm.cli.vm_attach.vm_share_mappings', lambda *a, **k: []
    )

    attached: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attach_vm_share',
        lambda *a, **k: attached.append((a, k)),
    )

    resolved: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: resolved.append((a, k)) or '10.77.0.55',
    )

    mounted: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted',
        lambda *a, **k: mounted.append((a, k)),
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 0
    assert attached
    assert resolved
    assert len(mounted) == 1
    args, kwargs = mounted[0]
    assert args[1] == '10.77.0.55'
    assert kwargs['guest_dst'] == '/workspace/proj'
    assert kwargs['tag'] == 'hostcode-proj'
    # The real _record_attachment persisted the share; the store is the artifact.
    att = _only_attachment(cfg_path)
    assert att.host_path == str(host_src.resolve())
    assert att.mode == 'direct-virtiofs'
    assert att.access == 'rw'
    assert att.guest_dst == '/workspace/proj'
    assert att.tag == 'hostcode-proj'
    assert att.host_lexical_paths == []


def test_vm_attach_skips_guest_mount_when_vm_not_running(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(name='vm-stopped')
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=False)
    monkeypatch.setattr(
        'aivm.cli.vm_attach.vm_share_mappings', lambda *a, **k: []
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attach_vm_share', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('_resolve_ip_for_ssh_ops should not be called')
        ),
    )
    refreshes: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach.refresh_cloud_init_seed_for_next_boot',
        lambda *a, **k: refreshes.append((a, k)) or None,
    )
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('ensure_share_mounted should not be called')
        ),
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
    )
    assert rc == 0
    # Even with the VM stopped, the attachment is still persisted.
    att = _only_attachment(cfg_path)
    assert att.host_path == str(host_src.resolve())
    assert att.mode == 'direct-virtiofs'
    assert att.guest_dst == '/workspace/proj'
    assert att.tag == 'hostcode-proj'


def test_vm_attach_persistent_syncs_manifest_and_replays_when_running(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(
        name='vm-persistent-running', mode=AttachmentMode.PERSISTENT
    )
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=True)
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.77',
    )

    syncs: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: syncs.append((a, k)) or cfg_path,
    )
    # The root-owned replay manifest sync escalates for real; the seam is
    # the subject of test_persistent_host.py, so stub it here.
    replay_syncs: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_host_replay_manifest',
        lambda *a, **k: replay_syncs.append((a, k)) or cfg_path,
    )
    host_replays: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._reconcile_persistent_host_binds',
        lambda *a, **k: host_replays.append((a, k)) or None,
    )
    guest_mounts: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._ensure_attachment_available_in_guest',
        lambda *a, **k: guest_mounts.append((a, k)) or None,
    )
    replays: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._reconcile_persistent_attachments_in_guest',
        lambda *a, **k: replays.append((a, k)) or None,
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        mode='persistent',
        yes=True,
    )

    assert rc == 0
    assert syncs
    assert replay_syncs
    assert host_replays
    assert host_replays[0][1]['only_guest_dst'] == '/workspace/proj'
    assert guest_mounts
    assert replays
    assert replays[0][1]['only_guest_dst'] == '/workspace/proj'
    assert guest_mounts[0][1]['ensure_shared_root_host_side'] is True
    att = _only_attachment(cfg_path)
    assert att.host_path == str(host_src.resolve())
    assert att.mode == 'persistent'
    assert att.source_dev > 0
    assert att.source_ino > 0
    assert att.guest_dst == '/workspace/proj'


def test_attach_without_sudo_names_both_ways_out(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    """A sudo-less caller learns which knob to turn, not just that sudo failed.

    Persistent mode needs a host bind mount, so an ordinary user on a shared
    workstation cannot create one. The bare credential failure says nothing
    about ``--mode shared`` or about asking an administrator, which are the
    only two things that actually get them unstuck.
    """
    cfg, cfg_path, host_src, attachment = make_attach_env(
        name='vm-no-sudo', mode=AttachmentMode.PERSISTENT
    )
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=False)

    def refuse_sudo(*_a: Any, **_k: Any) -> None:
        raise SudoUnavailableError(
            ['sudo', '-v'],
            CmdResult(1, '', 'sudo: a password is required'),
            purpose='Reconcile persistent host binds',
        )

    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_host_replay_manifest', refuse_sudo
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: cfg_path,
    )

    with pytest.raises(AIVMError) as excinfo:
        VMAttachCLI.main(
            argv=False,
            config=str(cfg_path),
            host_src=str(host_src),
            mode='persistent',
            yes=True,
        )

    message = str(excinfo.value)
    assert 'could not obtain sudo credentials' in message
    assert '--mode direct-virtiofs' in message
    assert '--admin_override' in message


def test_vm_attach_persistent_prepares_dedicated_export_when_vm_stopped(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(
        name='vm-persistent-stopped', mode=AttachmentMode.PERSISTENT
    )
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=False)
    syncs: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: syncs.append((a, k)) or cfg_path,
    )
    # The root-owned replay manifest sync escalates for real; the seam is
    # the subject of test_persistent_host.py, so stub it here.
    replay_syncs: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_host_replay_manifest',
        lambda *a, **k: replay_syncs.append((a, k)) or cfg_path,
    )
    host_replays: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._reconcile_persistent_host_binds',
        lambda *a, **k: host_replays.append((a, k)) or None,
    )
    prepares: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._prepare_persistent_attachment_host_and_vm',
        lambda *a, **k: prepares.append((a, k)) or None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('_resolve_ip_for_ssh_ops should not be called')
        ),
    )
    refreshes: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach.refresh_cloud_init_seed_for_next_boot',
        lambda *a, **k: refreshes.append((a, k)) or None,
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        mode='persistent',
        yes=True,
    )

    assert rc == 0
    assert prepares
    assert prepares[0][1]['vm_running'] is False
    assert syncs
    assert replay_syncs
    assert host_replays
    assert host_replays[0][1]['only_guest_dst'] == '/workspace/proj'
    assert refreshes
    att = _only_attachment(cfg_path)
    assert att.host_path == str(host_src.resolve())
    assert att.mode == 'persistent'
    assert att.source_dev > 0
    assert att.source_ino > 0


def test_vm_attach_uses_single_escalating_probe(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    """Attach makes one probe call; escalation lives inside probe_vm_state."""
    cfg, cfg_path, host_src, attachment = make_attach_env(name='vm-needs-sudo')
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=None)

    probe_calls: list[dict] = []

    def fake_probe(*a: object, **k: object) -> tuple[ProbeOutcome, bool]:
        probe_calls.append(dict(k))
        return (ProbeOutcome(True, 'vm-needs-sudo state=running'), True)

    monkeypatch.setattr('aivm.cli.vm_attach.probe_vm_state', fake_probe)
    monkeypatch.setattr(
        'aivm.cli.vm_attach.vm_share_mappings', lambda *a, **k: []
    )

    attached: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attach_vm_share',
        lambda *a, **k: attached.append((a, k)),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.77',
    )

    mounted: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted',
        lambda *a, **k: mounted.append((a, k)),
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=False,
    )
    assert rc == 0
    assert attached
    assert mounted
    assert probe_calls == [{'use_sudo': True}]
    att = _only_attachment(cfg_path)
    assert att.host_path == str(host_src.resolve())
    assert att.mode == 'direct-virtiofs'


def test_vm_attach_git_mode_sets_up_guest_repo_when_running(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(
        name='vm-git',
        dirname='repo',
        mode=AttachmentMode.GIT,
        guest_dst='/workspace/repo',
        tag='',
    )
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=True)
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.88',
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.vm_share_mappings',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('vm_share_mappings should not be called in git mode')
        ),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.attach_vm_share',
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError('attach_vm_share should not be called in git mode')
        ),
    )

    sync_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_git_clone_attachment',
        lambda *a, **k: sync_calls.append((a, k)) or (host_src, 'ssh', 'git'),
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        mode='git',
        yes=True,
    )
    assert rc == 0
    assert len(sync_calls) == 1
    att = _only_attachment(cfg_path)
    assert att.host_path == str(host_src.resolve())
    assert att.mode == 'git'
    assert att.guest_dst == '/workspace/repo'
    assert att.tag == ''


def test_record_attachment_is_idempotent_when_unchanged(tmp_path: Path) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'repo'
    host_src.mkdir()
    guest_dst = '/workspace/repo'

    reg = Store()
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    upsert_attachment(
        reg,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode='git',
        guest_dst=guest_dst,
        tag='',
    )
    save_store(reg, cfg_path)

    out = _record_attachment(
        cfg,
        cfg_path,
        host_src=host_src,
        mode='git',
        access=AttachmentAccess.RW,
        guest_dst=guest_dst,
        tag='',
    )
    assert out == cfg_path
    records = load_store(cfg_path).attachments
    assert len(records) == 1
    assert records[0].mode == 'git'
    assert records[0].guest_dst == guest_dst


def test_record_attachment_passes_reason_to_update_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    cfg_path = tmp_path / 'config.toml'
    real = tmp_path / 'real-repo'
    real.mkdir()
    host_src = tmp_path / 'repo'
    host_src.symlink_to(real)

    calls: list[dict[str, Any]] = []

    def fake_update_store(
        mutate: Callable[[Store], None],
        path: Path,
        **kwargs: Any,
    ) -> Store:
        reg = Store()
        mutate(reg)
        calls.append({'path': path, **kwargs})
        return reg

    monkeypatch.setattr(
        'aivm.attachments.session.update_store', fake_update_store
    )

    out = _record_attachment(
        cfg,
        cfg_path,
        host_src=host_src,
        mode='git',
        access=AttachmentAccess.RW,
        guest_dst='/workspace/repo',
        tag='',
    )

    assert out == cfg_path
    assert calls == [
        {
            'path': cfg_path,
            'reason': (
                f'Persist attachment record for {host_src} on VM vm-git '
                '(owner=legacy, mode=git, access=rw, '
                'guest_dst=/workspace/repo).'
            ),
        }
    ]


@pytest.mark.parametrize('cli_cls', [VMCodeCLI, VMSSHCLI], ids=['code', 'ssh'])
def test_vm_connect_clis_pass_lexical_host_src_to_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, cli_cls: Any
) -> None:
    """Both VMCodeCLI and VMSSHCLI must pass the lexical (non-resolved)
    host_src so downstream symlink detection works."""
    cfg = AgentVMConfig()
    cfg.vm.name = f'vm-{cli_cls.__name__.lower()}-lexical'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.DIRECT_VIRTIOFS,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj-abc12345',
    )

    captured: list[dict] = []
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_attached_session',
        _fake_prepare_session(cfg, cfg_path, host_src, attachment, captured),
    )

    # dry_run=True exits immediately after getting the session - no subprocess needed
    cli_cls.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
        dry_run=True,
    )

    assert captured, 'expected _prepare_attached_session to be called'
    passed = captured[0]['host_src']
    assert passed == host_src.expanduser().absolute()



@pytest.mark.parametrize('cli_cls', [VMCodeCLI, VMSSHCLI], ids=['code', 'ssh'])
def test_code_and_ssh_route_through_shared_foreground_preparation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    cli_cls: Any,
) -> None:
    """Both launchers must call the common preparation seam, not duplicate it."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-common-prep-seam'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    inner = _fake_prepare_session(cfg, cfg_path, host_src, attachment, [])
    calls: list[Any] = []

    def fake_foreground(args: Any) -> Any:
        calls.append(args)
        return inner(host_src=host_src)

    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_session', fake_foreground
    )
    assert (
        cli_cls.main(
            argv=False,
            config=str(cfg_path),
            host_src=str(host_src),
            yes=True,
            dry_run=True,
        )
        == 0
    )
    assert len(calls) == 1


def test_code_and_ssh_share_identical_foreground_preparation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Launcher choice happens only after one common startup pipeline."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared-foreground-prep'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_attached_session',
        _fake_prepare_session(cfg, cfg_path, host_src, attachment, captured),
    )

    common = dict(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
        dry_run=True,
    )
    assert VMCodeCLI.main(**common) == 0
    assert VMSSHCLI.main(**common) == 0

    assert len(captured) == 2
    first = dict(captured[0])
    second = dict(captured[1])
    first_bootstrap = first.pop('bootstrap_missing_vm')
    second_bootstrap = second.pop('bootstrap_missing_vm')
    assert first == second
    assert first_bootstrap.func is second_bootstrap.func
    assert first_bootstrap.args == second_bootstrap.args
    assert first_bootstrap.keywords == second_bootstrap.keywords



def test_vm_ssh_continues_when_repository_agent_setup_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Repository credential failures do not prevent VM access."""
    from tests.helpers import capture_logs

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-ssh-agent-failure'
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_attached_session',
        _fake_prepare_session(cfg, cfg_path, host_src, attachment, []),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect.prepare_agent_forwarding',
        lambda *a, **k: (_ for _ in ()).throw(
            AIVMError('forwarded agent is unavailable')
        ),
    )
    ssh_config_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_connect._upsert_ssh_config_entry',
        lambda *a, **k: (
            ssh_config_calls.append(k) or (tmp_path / 'ssh_config', False)
        ),
    )
    monkeypatch.setattr('aivm.cli.vm_connect.require_ssh_identity', lambda p: p)
    warnings = capture_logs(
        monkeypatch, 'aivm.cli.vm_connect.log', levels=('warning',)
    )
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0, '', '')})

    rc = VMSSHCLI.main(
        argv=False, config=str(cfg_path), host_src=str(host_src), yes=True
    )

    assert rc == 0
    assert ssh_config_calls[0]['forward_agent_socket'] == ''
    ssh_cmd = recorder.only('ssh')
    assert '-A' not in ssh_cmd
    assert not any(part.startswith('SSH_AUTH_SOCK=') for part in ssh_cmd)
    assert warnings == [
        'Repository ssh-agent setup failed; continuing without credential '
        'forwarding: forwarded agent is unavailable'
    ]


def test_vm_ssh_continues_when_ssh_config_update_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Managed SSH alias maintenance is optional for a direct shell."""
    from tests.helpers import capture_logs

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-ssh-config-failure'
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_attached_session',
        _fake_prepare_session(cfg, cfg_path, host_src, attachment, []),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_agent_forwarding',
        lambda session: None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._upsert_ssh_config_entry',
        lambda *a, **k: (_ for _ in ()).throw(
            PermissionError('ssh config is read-only')
        ),
    )
    monkeypatch.setattr('aivm.cli.vm_connect.require_ssh_identity', lambda p: p)
    warnings = capture_logs(
        monkeypatch, 'aivm.cli.vm_connect.log', levels=('warning',)
    )
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0, '', '')})

    rc = VMSSHCLI.main(
        argv=False, config=str(cfg_path), host_src=str(host_src), yes=True
    )

    assert rc == 0
    assert recorder.only('ssh')
    assert warnings == [
        'Could not update the managed SSH config entry for '
        'vm-ssh-config-failure; continuing without it: ssh config is read-only'
    ]


def test_vm_code_tunnel_continues_when_ssh_config_update_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Tunnel startup does not depend on the workstation SSH alias."""
    from tests.helpers import capture_logs

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-code-config-failure'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    session = _fake_prepare_session(
        cfg, cfg_path, host_src, attachment, []
    )(host_src=host_src)
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_session', lambda args: session
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_foreground_agent_forwarding',
        lambda session: None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._upsert_ssh_config_entry',
        lambda *a, **k: (_ for _ in ()).throw(
            PermissionError('ssh config is read-only')
        ),
    )
    tunnel_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_connect._start_remote_tunnel_session',
        lambda *a: tunnel_calls.append(a),
    )
    warnings = capture_logs(
        monkeypatch, 'aivm.cli.vm_connect.log', levels=('warning',)
    )

    rc = VMCodeCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        yes=True,
        tunnel=True,
        no_attach=True,
    )

    assert rc == 0
    assert len(tunnel_calls) == 1
    assert warnings == [
        'Could not update the managed SSH config entry for '
        'vm-code-config-failure; continuing without it: ssh config is read-only'
    ]


@pytest.mark.parametrize(
    ('ssh_exit', 'expect_rc', 'expect_error'),
    [
        pytest.param(0, 0, False, id='clean_exit'),
        pytest.param(127, 0, False, id='shell_status_is_not_our_error'),
        pytest.param(255, 1, True, id='ssh_transport_failure'),
    ],
)
def test_vm_ssh_reports_only_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    ssh_exit: int,
    expect_rc: int,
    expect_error: bool,
) -> None:
    """An interactive shell's exit status is the user's, not an aivm error.

    `exit` propagates the last command's status, so ending a session after
    a typo'd command used to print a scary ERROR for a perfectly healthy
    run. Only ssh's own exit code 255 (connection/transport failure) is
    aivm's to report.
    """
    from tests.helpers import capture_logs

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-ssh-exit'
    cfg.paths.ssh_identity_file = str(tmp_path / 'id_ed25519')
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.DIRECT_VIRTIOFS,
        source_dir=str(host_src.resolve()),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.cli.vm_connect._prepare_attached_session',
        _fake_prepare_session(cfg, cfg_path, host_src, attachment, []),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_connect._upsert_ssh_config_entry',
        lambda *a, **k: (tmp_path / 'ssh_config', False),
    )
    monkeypatch.setattr('aivm.cli.vm_connect.require_ssh_identity', lambda p: p)
    errors = capture_logs(
        monkeypatch, 'aivm.cli.vm_connect.log', levels=('error',)
    )
    command_recorder(monkeypatch, {'ssh': FakeProc(ssh_exit, '', '')})

    rc = VMSSHCLI.main(
        argv=False, config=str(cfg_path), host_src=str(host_src), yes=True
    )

    out = capsys.readouterr().out
    assert rc == expect_rc
    if expect_error:
        assert any('SSH connection' in msg for msg in errors)
        assert 'SSH session ended' not in out
    else:
        assert errors == []
        assert 'SSH session ended' in out


@pytest.mark.parametrize(
    ('reply', 'expected'),
    [
        pytest.param(FakeProc(0, 'running\n', ''), True, id='running'),
        pytest.param(FakeProc(0, 'shut off\n', ''), False, id='shut-off'),
        pytest.param(
            FakeProc(1, '', 'error: authentication failed: access denied'),
            None,
            id='inconclusive',
        ),
    ],
)
def test_nonsudo_running_probe_pins_c_locale(
    monkeypatch: pytest.MonkeyPatch,
    reply: object,
    expected: bool | None,
) -> None:
    """Every answer this probe gives is read out of English text.

    Both the running/not-running verdict and the 'inconclusive, needs sudo'
    verdict string-match the reply, so a localized virsh would report a
    running VM as stopped and a permission failure as a definite 'no'.
    """
    from aivm.attachments.session import _probe_vm_running_nonsudo

    activate_manager(monkeypatch)
    rec = command_recorder(monkeypatch, {'virsh domstate': reply})

    assert _probe_vm_running_nonsudo('vm-locale') is expected
    assert rec.calls and all(is_locale_pinned(call) for call in rec.calls)
