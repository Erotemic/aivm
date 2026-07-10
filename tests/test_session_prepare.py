"""Tests for :func:`aivm.attachments.session._prepare_attached_session`.

``_prepare_attached_session`` is the reconcile entry point that ``aivm
code`` and friends call to turn a folder request into a running,
share-mounted VM.  These tests drive it directly (they do not go through
the ``vm update`` CLI) across the flows it must cover:

- bootstrapping a missing VM (with and without stored defaults, and
  preserving an interactive ``yes=False``), and
- restoring the shares a previously attached VM already carried, in both
  the per-folder ``shared`` mode and the ``shared-root`` mode.

Every one of these re-patches the same handful of seams around the
function; :func:`attached_session_harness` installs them once so each
test overrides only the seam it is exercising.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch

from aivm.attachments.session import ReconcileResult, _prepare_attached_session
from aivm.cli.vm_connect import _bootstrap_vm_for_folder
from aivm.config import AgentVMConfig
from aivm.status import ProbeOutcome
from aivm.vm.share import AttachmentMode, ResolvedAttachment


@dataclass
class AttachedSessionHarness:
    """Mutable handle over the stubbed ``_prepare_attached_session`` seams.

    ``cfg``/``cfg_path``/``host_src`` are the scaffolding the tests share;
    ``attachment``/``reconcile``/``probe`` are the literals the default
    seams hand back (a test may swap them or re-patch a seam outright).
    ``calls`` records the bootstrap steps (``config_init``/``vm_create``)
    and ``state['ready']`` gates whether the config resolver "sees" a VM
    yet.
    """

    monkeypatch: MonkeyPatch
    tmp_path: Path
    cfg: AgentVMConfig
    cfg_path: Path
    host_src: Path
    attachment: ResolvedAttachment
    reconcile: ReconcileResult
    probe: ProbeOutcome
    calls: list[str] = field(default_factory=list)
    state: dict[str, bool] = field(default_factory=lambda: {'ready': True})


@pytest.fixture
def attached_session_harness(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> AttachedSessionHarness:
    """Install the seams every ``_prepare_attached_session`` test re-patches.

    Defaults describe the happy path: the config resolver returns the
    harness VM (unless a test flips ``state['ready']`` off to force a
    bootstrap), attachment resolution/reconciliation return the prebuilt
    literals, and the guest/IP/SSH probes report success.  The bootstrap
    seams (``InitCLI.main`` and ``create_vm_from_defaults``) record their
    step name and flip ``state['ready']`` on.
    """
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    cfg = AgentVMConfig()
    cfg.vm.name = 'bootstrap-vm'
    cfg_path = tmp_path / 'config.toml'

    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        source_dir=str(host_src),
        guest_dst=str(host_src),
        tag='hostcode-proj',
    )
    reconcile = ReconcileResult(
        attachment=attachment,
        cached_ip=None,
        cached_ssh_ok=False,
    )
    probe = ProbeOutcome(True, 'ready', '')

    harness = AttachedSessionHarness(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        cfg=cfg,
        cfg_path=cfg_path,
        host_src=host_src,
        attachment=attachment,
        reconcile=reconcile,
        probe=probe,
    )

    def fake_resolve_cfg_for_code(**kwargs: Any) -> tuple[AgentVMConfig, Path]:
        del kwargs
        if not harness.state['ready']:
            raise RuntimeError(
                f'No VM definitions found in config store: {cfg_path}. '
                'Run `aivm config init` then `aivm vm create` first.'
            )
        return harness.cfg, cfg_path

    def fake_vm_create(*args: Any, **kwargs: Any) -> int:
        del args, kwargs
        harness.calls.append('vm_create')
        harness.state['ready'] = True
        return 0

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        fake_resolve_cfg_for_code,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        lambda *a, **k: harness.attachment,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: harness.reconcile,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment',
        lambda *a, **k: tmp_path / 'dummy',
    )
    monkeypatch.setattr(
        'aivm.attachments.session.get_ip_cached', lambda *a, **k: '10.0.0.2'
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: harness.probe,
    )
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted', lambda *a, **k: None
    )
    monkeypatch.setattr(
        'aivm.cli.config.InitCLI.main',
        lambda *a, **k: harness.calls.append('config_init') or 0,
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults', fake_vm_create
    )
    return harness


def test_prepare_attached_session_bootstraps_missing_vm(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    harness = attached_session_harness
    harness.state['ready'] = False

    bootstrap = partial(
        _bootstrap_vm_for_folder,
        config_opt=None,
        vm_opt='',
        host_src=harness.host_src,
        guest_dst_opt='',
        attach_mode_opt='',
        attach_access_opt='',
        yes=True,
        dry_run=False,
    )
    session = _prepare_attached_session(
        config_opt=None,
        vm_opt='',
        host_src=harness.host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
        bootstrap_missing_vm=bootstrap,
    )
    assert session.cfg.vm.name == 'bootstrap-vm'
    assert harness.calls == ['config_init', 'vm_create']


def test_prepare_attached_session_interactive_bootstrap_preserves_yes_false(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    harness = attached_session_harness
    monkeypatch = harness.monkeypatch
    harness.state['ready'] = False

    init_kwargs: list[dict[str, Any]] = []
    create_kwargs: list[dict[str, Any]] = []

    def fake_init(*a: object, **k: Any) -> int:
        del a
        init_kwargs.append(dict(k))
        return 0

    def fake_vm_create(*a: Any, **k: Any) -> int:
        del a
        create_kwargs.append(dict(k))
        harness.state['ready'] = True
        return 0

    monkeypatch.setattr('aivm.cli.config.InitCLI.main', fake_init)
    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults', fake_vm_create
    )
    monkeypatch.setattr('aivm.cli.vm_connect.sys.stdin.isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda prompt='': 'y')

    bootstrap = partial(
        _bootstrap_vm_for_folder,
        config_opt=None,
        vm_opt='',
        host_src=harness.host_src,
        guest_dst_opt='',
        attach_mode_opt='',
        attach_access_opt='',
        yes=False,
        dry_run=False,
    )
    session = _prepare_attached_session(
        config_opt=None,
        vm_opt='',
        host_src=harness.host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=False,
        bootstrap_missing_vm=bootstrap,
    )

    assert session.cfg.vm.name == 'bootstrap-vm'
    assert init_kwargs == [
        {
            'argv': False,
            'config': None,
            'yes': False,
            'defaults': False,
            'force': False,
        }
    ]
    assert len(create_kwargs) == 1
    # ``yes=False`` propagation is the contract this test guards; the rest of
    # the call shape is verified indirectly by the function signature.
    assert create_kwargs[0]['yes'] is False
    assert create_kwargs[0]['dry_run'] is False
    assert create_kwargs[0]['force'] is False
    assert create_kwargs[0]['vm_override'] is None
    assert create_kwargs[0]['initial_attachment_host_src'] == harness.host_src


def test_prepare_attached_session_bootstraps_create_only_when_defaults_exist(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    from aivm.config_store import Store, save_store

    harness = attached_session_harness
    harness.state['ready'] = False

    store = Store()
    store.defaults = AgentVMConfig()
    save_store(store, harness.cfg_path)

    bootstrap = partial(
        _bootstrap_vm_for_folder,
        config_opt=str(harness.cfg_path),
        vm_opt='',
        host_src=harness.host_src,
        guest_dst_opt='',
        attach_mode_opt='',
        attach_access_opt='',
        yes=True,
        dry_run=False,
    )
    session = _prepare_attached_session(
        config_opt=str(harness.cfg_path),
        vm_opt='',
        host_src=harness.host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
        bootstrap_missing_vm=bootstrap,
    )
    assert session.cfg.vm.name == 'bootstrap-vm'
    assert harness.calls == ['vm_create']


def test_prepare_attached_session_restores_saved_vm_attachments(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    from aivm.config_store import (
        Store,
        save_store,
        upsert_attachment,
        upsert_vm,
    )

    harness = attached_session_harness
    monkeypatch = harness.monkeypatch
    host_src = harness.host_src
    cfg_path = harness.cfg_path
    other_src = harness.tmp_path / 'docs'
    other_src.mkdir()
    cfg = harness.cfg
    cfg.vm.name = 'restore-vm'

    store = Store()
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=host_src,
        vm_name=cfg.vm.name,
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )
    upsert_attachment(
        store,
        host_path=other_src,
        vm_name=cfg.vm.name,
        guest_dst='/workspace/docs',
        tag='hostcode-docs',
    )
    save_store(store, cfg_path)

    current_attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        source_dir=str(host_src.resolve()),
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
    )

    def fake_resolve_attachment(
        _cfg: AgentVMConfig,
        cfg_path: Path,
        host_path: Path,
        _guest_dst_opt: str,
    ) -> ResolvedAttachment:
        host_path = Path(host_path).resolve()
        if host_path == host_src.resolve():
            return current_attachment
        if host_path == other_src.resolve():
            return ResolvedAttachment(
                vm_name=cfg.vm.name,
                source_dir=str(other_src.resolve()),
                guest_dst='/workspace/docs',
                tag='hostcode-docs',
            )
        raise AssertionError(f'unexpected host_path={host_path}')

    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        fake_resolve_attachment,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=current_attachment,
            cached_ip='10.0.0.2',
            cached_ssh_ok=True,
        ),
    )

    mappings = [(str(host_src.resolve()), 'hostcode-proj')]

    def fake_vm_share_mappings(*a: Any, **k: Any) -> list:
        del a, k
        return list(mappings)

    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings', fake_vm_share_mappings
    )

    attached: list[tuple[tuple, dict]] = []

    def fake_attach_vm_share(*a: Any, **k: Any) -> None:
        attached.append((a, k))
        mappings.append((str(other_src.resolve()), 'hostcode-docs'))

    monkeypatch.setattr(
        'aivm.attachments.session.attach_vm_share', fake_attach_vm_share
    )

    mounted: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted',
        lambda *a, **k: mounted.append((a, k)),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted',
        lambda *a, **k: mounted.append((a, k)),
    )
    recorded: list[dict] = []

    def fake_record_attachment(
        cfg_arg: AgentVMConfig,
        cfg_path_arg: Path,
        *,
        host_src: Path,
        mode: str,
        access: str,
        guest_dst: str,
        tag: str,
    ) -> Path:
        del cfg_arg, cfg_path_arg
        recorded.append(
            {
                'host_src': str(host_src),
                'mode': mode,
                'access': access,
                'guest_dst': guest_dst,
                'tag': tag,
            }
        )
        return cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment', fake_record_attachment
    )

    session = _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
    )

    assert session.cfg.vm.name == 'restore-vm'
    assert len(attached) == 1
    attach_args, attach_kwargs = attached[0]
    assert attach_args[1] == str(other_src.resolve())
    assert attach_args[2] == 'hostcode-docs'
    assert attach_kwargs['dry_run'] is False
    assert [kwargs['guest_dst'] for _, kwargs in mounted] == [
        '/workspace/proj',
        '/workspace/docs',
    ]
    assert len(recorded) == 2
    assert recorded[1]['mode'] == 'shared'
    assert recorded[1]['guest_dst'] == '/workspace/docs'


def test_prepare_attached_session_restores_saved_shared_root_attachments(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    from aivm.config_store import (
        Store,
        save_store,
        upsert_attachment,
        upsert_vm,
    )

    harness = attached_session_harness
    monkeypatch = harness.monkeypatch
    host_src = harness.host_src
    cfg_path = harness.cfg_path
    other_src = harness.tmp_path / 'docs'
    other_src.mkdir()
    cfg = harness.cfg
    cfg.vm.name = 'restore-shared-root-vm'

    store = Store()
    upsert_vm(store, cfg)
    upsert_attachment(
        store,
        host_path=host_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        guest_dst='/workspace/proj',
        tag='token-proj',
    )
    upsert_attachment(
        store,
        host_path=other_src,
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        guest_dst='/workspace/docs',
        tag='token-docs',
    )
    save_store(store, cfg_path)

    current_attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        source_dir=str(host_src.resolve()),
        guest_dst='/workspace/proj',
        tag='token-proj',
    )

    def fake_resolve_attachment(
        _cfg: AgentVMConfig,
        cfg_path: Path,
        host_path: Path,
        _guest_dst_opt: str,
    ) -> ResolvedAttachment:
        host_path = Path(host_path).resolve()
        if host_path == host_src.resolve():
            return current_attachment
        if host_path == other_src.resolve():
            return ResolvedAttachment(
                vm_name=cfg.vm.name,
                mode=AttachmentMode.SHARED_ROOT,
                source_dir=str(other_src.resolve()),
                guest_dst='/workspace/docs',
                tag='token-docs',
            )
        raise AssertionError(f'unexpected host_path={host_path}')

    monkeypatch.setattr(
        'aivm.attachments.session._resolve_attachment',
        fake_resolve_attachment,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: ReconcileResult(
            attachment=current_attachment,
            cached_ip='10.0.0.3',
            cached_ssh_ok=True,
        ),
    )

    primary_ready_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.session._ensure_attachment_available_in_guest',
        lambda *a, **k: primary_ready_calls.append((a, k)) or None,
    )

    shared_root_host_binds: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_host_bind',
        lambda *a, **k: (
            shared_root_host_binds.append((a, k)) or Path('/tmp/token')
        ),
    )
    shared_root_vm_mappings: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_vm_mapping',
        lambda *a, **k: shared_root_vm_mappings.append((a, k)) or None,
    )
    shared_root_guest_binds: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_guest_bind',
        lambda *a, **k: shared_root_guest_binds.append((a, k)) or None,
    )

    recorded: list[dict] = []

    def fake_record_attachment(
        cfg_arg: AgentVMConfig,
        cfg_path_arg: Path,
        *,
        host_src: Path,
        mode: str,
        access: str,
        guest_dst: str,
        tag: str,
    ) -> Path:
        del cfg_arg, cfg_path_arg
        recorded.append(
            {
                'host_src': str(host_src),
                'mode': mode,
                'access': access,
                'guest_dst': guest_dst,
                'tag': tag,
            }
        )
        return cfg_path

    monkeypatch.setattr(
        'aivm.attachments.session._record_attachment', fake_record_attachment
    )

    session = _prepare_attached_session(
        config_opt=str(cfg_path),
        vm_opt='',
        host_src=host_src,
        guest_dst_opt='',
        recreate_if_needed=False,
        ensure_firewall_opt=True,
        dry_run=False,
        yes=True,
    )

    assert session.cfg.vm.name == 'restore-shared-root-vm'
    assert len(primary_ready_calls) == 2
    primary_args, primary_kwargs = primary_ready_calls[0]
    restored_args, restored_kwargs = primary_ready_calls[1]
    assert primary_args[2].guest_dst == '/workspace/proj'
    assert primary_kwargs['ensure_shared_root_host_side'] is True
    assert restored_args[2].guest_dst == '/workspace/docs'
    assert restored_kwargs['ensure_shared_root_host_side'] is True
    assert restored_kwargs['allow_disruptive_shared_root_rebind'] is False
    assert len(shared_root_host_binds) == 0
    assert len(shared_root_vm_mappings) == 0
    assert len(shared_root_guest_binds) == 0
    assert len(recorded) == 2
    assert recorded[1]['mode'] == AttachmentMode.SHARED_ROOT
    assert recorded[1]['guest_dst'] == '/workspace/docs'
