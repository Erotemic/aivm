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
from aivm.config import AgentVMConfig
from aivm.config_store import (
    Store,
    save_store,
    upsert_attachment,
    upsert_network,
    upsert_vm_with_network,
)
from aivm.status import ProbeOutcome
from aivm.vm.share import AttachmentAccess, AttachmentMode, ResolvedAttachment
from tests.helpers import patch_ns, returns

AttachEnv = tuple[AgentVMConfig, Path, Path, ResolvedAttachment]


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
        mode: AttachmentMode = AttachmentMode.SHARED,
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

    Patches ``load_cfg_with_path``/``record_vm``/``_resolve_attachment``
    unconditionally; ``probe_vm_state`` reports ``running`` unless it is
    ``None`` (the caller installs its own probe to inspect kwargs).
    """
    mapping: dict[str, Any] = {
        'load_cfg_with_path': returns((cfg, cfg_path)),
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
            cfg=cfg,
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
    monkeypatch.setattr(
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
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
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
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


def test_vm_attach_persistent_syncs_manifest_and_replays_when_running(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(
        name='vm-persistent-running', mode=AttachmentMode.PERSISTENT
    )
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=True)
    monkeypatch.setattr(
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.77',
    )

    syncs: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: syncs.append((a, k)) or cfg_path,
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
    assert guest_mounts
    assert replays
    assert guest_mounts[0][1]['ensure_shared_root_host_side'] is True


def test_vm_attach_persistent_prepares_dedicated_export_when_vm_stopped(
    monkeypatch: pytest.MonkeyPatch,
    make_attach_env: Callable[..., AttachEnv],
) -> None:
    cfg, cfg_path, host_src, attachment = make_attach_env(
        name='vm-persistent-stopped', mode=AttachmentMode.PERSISTENT
    )
    patch_vm_attach_env(monkeypatch, cfg, cfg_path, attachment, running=False)
    monkeypatch.setattr(
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
    )
    syncs: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._sync_persistent_attachment_manifest_on_host',
        lambda *a, **k: syncs.append((a, k)) or cfg_path,
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
    assert refreshes


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
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
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
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
    )
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


def test_record_attachment_skips_save_when_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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

    save_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.session.save_store',
        lambda *a, **k: save_calls.append((a, k)) or cfg_path,
    )

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
    assert save_calls == []


def test_record_attachment_passes_reason_to_save_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    cfg_path = tmp_path / 'config.toml'
    host_src = tmp_path / 'repo'
    host_src.mkdir()

    save_kwargs: list[dict] = []
    monkeypatch.setattr(
        'aivm.attachments.session.save_store',
        lambda *a, **k: save_kwargs.append(dict(k)) or cfg_path,
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
    assert save_kwargs == [
        {
            'reason': (
                f'Persist attachment record for {host_src} on VM vm-git '
                '(mode=git, access=rw, guest_dst=/workspace/repo).'
            )
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
        mode=AttachmentMode.SHARED,
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
