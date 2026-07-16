"""Tests for :func:`aivm.attachments.session._prepare_attached_session`.

``_prepare_attached_session`` is the reconcile entry point that ``aivm
code`` and friends call to turn a folder request into a running,
share-mounted VM.  These tests drive it directly (they do not go through
the ``vm update`` CLI) across the flows it must cover:

- bootstrapping a missing VM (with and without stored defaults, and
  preserving an interactive ``yes=False``), and
- restoring the shares a previously attached VM already carried, in both
  the per-folder ``shared`` mode and the ``shared-root`` mode.

Following §6.2 of the 0.5.0 refactor plan, these assert on observable
artifacts -- the config-store contents left on disk, the cached-IP file
read back, and the commands recorded at the true guest/virsh boundaries
-- rather than on which internal seam was called.  The real store,
attachment-resolution, and attachment-recording code all run; only the
heavy ``_reconcile_attached_vm`` orchestrator and the ssh/virsh guest
surfaces stay faked.  :func:`attached_session_harness` installs that
residue once so each test overrides only the seam it is exercising.
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
from aivm.config_store import (
    Store,
    load_store,
    save_store,
    upsert_attachment,
    upsert_vm,
)
from aivm.errors import AIVMError
from aivm.services import resolve_cfg_for_code as real_resolve_cfg_for_code
from aivm.status import ProbeOutcome
from aivm.vm.paths import _paths
from aivm.vm.share import AttachmentMode, ResolvedAttachment
from tests.helpers import activate_manager, make_cfg, noop


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
    """Install the residual seams every ``_prepare_attached_session`` test shares.

    Defaults describe the happy path: the config resolver returns the
    harness VM (unless a test flips ``state['ready']`` off to force a
    bootstrap), the heavy VM reconciliation returns the prebuilt literal,
    and the ssh probe reports success.  A cached-IP file is written under
    ``tmp_path`` so the real ``get_ip_cached`` resolves ``10.0.0.2`` off
    disk instead of blocking on ``wait_for_ip``.  The bootstrap seams
    (``InitCLI.main`` and ``create_vm_from_defaults``) record their step
    name and flip ``state['ready']`` on.  Attachment resolution and
    recording are deliberately *not* faked here -- the tests assert on the
    store those real helpers leave behind.
    """
    activate_manager(monkeypatch)
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    cfg = make_cfg(tmp_path, **{'vm.name': 'bootstrap-vm'})
    cfg_path = tmp_path / 'config.toml'

    # Seed the cached-IP file the real get_ip_cached reads, so IP resolution
    # is a file-on-disk artifact rather than a stubbed return value.
    ip_file = _paths(cfg)['ip_file']
    ip_file.parent.mkdir(parents=True, exist_ok=True)
    ip_file.write_text('10.0.0.2', encoding='utf-8')

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
        'aivm.attachments.session._reconcile_attached_vm',
        lambda *a, **k: harness.reconcile,
    )
    monkeypatch.setattr(
        'aivm.attachments.session.probe_ssh_ready',
        lambda *a, **k: harness.probe,
    )
    monkeypatch.setattr('aivm.attachments.guest.ensure_share_mounted', noop)
    monkeypatch.setattr(
        'aivm.cli.config.init.initialize_config_defaults',
        lambda *a, **k: harness.calls.append('config_init') or 0,
    )
    monkeypatch.setattr(
        'aivm.vm.create_ops.create_vm_from_defaults', fake_vm_create
    )
    return harness


def test_prepare_attached_session_bootstraps_missing_vm(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    """A missing VM is bootstrapped, and the attachment lands in the store.

    The bootstrap ``config init`` + ``vm create`` order is the subject, so
    it stays asserted directly.  Beyond that, the real ``_record_attachment``
    persists the folder: the store gained VM/network/attachment records are
    the artifact the bootstrap ultimately produces.  The top-of-function
    guards are exercised too -- a missing path and a plain file are both
    refused before any bootstrap work runs.
    """
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

    # The path guards must reject bad input before touching the bootstrap.
    missing = harness.tmp_path / 'does-not-exist'
    with pytest.raises(FileNotFoundError):
        _prepare_attached_session(
            config_opt=None,
            vm_opt='',
            host_src=missing,
            guest_dst_opt='',
            recreate_if_needed=False,
            ensure_firewall_opt=True,
            dry_run=False,
            yes=True,
            bootstrap_missing_vm=bootstrap,
        )
    a_file = harness.tmp_path / 'a-file'
    a_file.write_text('x', encoding='utf-8')
    with pytest.raises(AIVMError):
        _prepare_attached_session(
            config_opt=None,
            vm_opt='',
            host_src=a_file,
            guest_dst_opt='',
            recreate_if_needed=False,
            ensure_firewall_opt=True,
            dry_run=False,
            yes=True,
            bootstrap_missing_vm=bootstrap,
        )
    assert harness.calls == []  # guards abort before any bootstrap work

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

    store = load_store(harness.cfg_path)
    atts = [a for a in store.attachments if a.vm_name == 'bootstrap-vm']
    assert len(atts) == 1
    att = atts[0]
    assert att.host_path == str(harness.host_src.resolve())
    assert att.mode == 'shared'
    assert att.access == 'rw'
    assert att.guest_dst == str(harness.host_src)
    assert att.tag == 'hostcode-proj'
    assert att.host_lexical_paths == []
    assert any(v.name == 'bootstrap-vm' for v in store.vms)
    assert any(n.name == harness.cfg.network.name for n in store.networks)


def test_prepare_attached_session_interactive_bootstrap_preserves_yes_false(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    """Interactive bootstrap forwards ``yes=False`` to init + create.

    ``yes=False`` propagation to the ``config init`` and ``vm create``
    consent flow is the contract under test, so those kwargs stay asserted
    directly.  The attachment the run persists to the store is the
    observable end state.
    """
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

    monkeypatch.setattr(
        'aivm.cli.config.init.initialize_config_defaults', fake_init
    )
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
            'config_opt': str(harness.cfg_path.resolve()),
            'yes': False,
            'defaults': False,
            'force': False,
            'standalone_guidance': False,
        }
    ]
    assert len(create_kwargs) == 1
    # ``yes=False`` propagation is the contract this test guards; the rest of
    # the call shape is verified indirectly by the function signature.
    assert create_kwargs[0]['yes'] is False
    assert create_kwargs[0]['dry_run'] is False
    assert create_kwargs[0]['force'] is False
    assert create_kwargs[0]['vm_override'] is None
    assert create_kwargs[0]['configuration_reviewed'] is True
    assert create_kwargs[0]['initial_attachment_host_src'] == harness.host_src

    # The bootstrapped session still persisted the folder attachment.
    store = load_store(harness.cfg_path)
    assert any(a.vm_name == 'bootstrap-vm' for a in store.attachments)


def test_prepare_attached_session_bootstraps_create_only_when_defaults_exist(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    """Stored defaults skip ``config init`` and only run ``vm create``.

    With defaults already in the store the bootstrap should not re-run
    ``config init``; the ``['vm_create']`` step list is the subject.  The
    persisted attachment is the artifact the run leaves behind.  A final
    check drives the sensitive-path guard: when the preflight declines, the
    function aborts before any config work.
    """
    harness = attached_session_harness
    monkeypatch = harness.monkeypatch
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

    persisted = load_store(harness.cfg_path)
    assert any(a.vm_name == 'bootstrap-vm' for a in persisted.attachments)

    # A declined sensitive-path preflight must abort at the guard, before
    # config resolution or any bootstrap work.
    outcomes = iter([(False, None)])

    def decline_then_allow(*a: Any, **k: Any) -> tuple[bool, None]:
        del a, k
        return next(outcomes, (True, None))

    with monkeypatch.context() as m:
        m.setattr(
            'aivm.attachments.safety.attachment_safety_preflight',
            decline_then_allow,
        )
        with pytest.raises(AIVMError, match='sensitive path'):
            _prepare_attached_session(
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


def test_prepare_attached_session_restores_saved_vm_attachments(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    """A running VM's saved ``shared`` attachments are all restored.

    The store is seeded with the primary folder plus a second ``shared``
    folder.  Real config resolution, ``_resolve_attachment`` and
    ``_record_attachment`` run; only the virtiofs mapping/attach probes and
    the guest mount surface stay faked.  The observable artifacts are the
    ordered guest mounts (primary then secondary) and the store holding
    both attachment records afterward.
    """
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

    # Resolve the VM from the real store instead of the bootstrap stub.
    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        real_resolve_cfg_for_code,
    )
    # The heavy orchestrator stays faked but passes the resolved attachment
    # through, reporting a reachable, ssh-ready VM.
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda cfg, host_src, attachment, **k: ReconcileResult(
            attachment=attachment,
            cached_ip='10.0.0.2',
            cached_ssh_ok=True,
        ),
    )

    # Faked virtiofs boundary: the secondary is initially absent from the VM
    # mappings, so restore must attach it before mounting.
    mappings = [(str(host_src.resolve()), 'hostcode-proj')]
    monkeypatch.setattr(
        'aivm.attachments.session.vm_share_mappings',
        lambda *a, **k: list(mappings),
    )

    def fake_attach_vm_share(*a: Any, **k: Any) -> None:
        del a, k
        mappings.append((str(other_src.resolve()), 'hostcode-docs'))

    monkeypatch.setattr(
        'aivm.attachments.session.attach_vm_share', fake_attach_vm_share
    )

    mounted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted',
        lambda *a, **k: mounted.append(k),
    )
    monkeypatch.setattr(
        'aivm.attachments.session.ensure_share_mounted',
        lambda *a, **k: mounted.append(k),
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
    # Both folders were mounted in the guest, primary first then secondary.
    assert [k['guest_dst'] for k in mounted] == [
        '/workspace/proj',
        '/workspace/docs',
    ]
    # Both attachments remain (or become) recorded for the VM.
    saved = load_store(cfg_path)
    by_path = {a.host_path: a for a in saved.attachments}
    assert str(host_src.resolve()) in by_path
    docs = by_path[str(other_src.resolve())]
    assert docs.vm_name == 'restore-vm'
    assert docs.mode == 'shared'
    assert docs.guest_dst == '/workspace/docs'


def test_prepare_attached_session_restores_saved_shared_root_attachments(
    attached_session_harness: AttachedSessionHarness,
) -> None:
    """A running VM's saved ``shared-root`` attachments are all restored.

    Real config resolution and attachment resolution/recording run; the
    guest-availability helper is faked so its per-attachment kwargs are the
    artifact -- both the primary and the secondary shared-root folder are
    made available with the host-side flag set and disruptive rebinds
    disabled.  The store holding both records is the persisted end state.
    """
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

    monkeypatch.setattr(
        'aivm.attachments.session.resolve_cfg_for_code',
        real_resolve_cfg_for_code,
    )
    monkeypatch.setattr(
        'aivm.attachments.session._reconcile_attached_vm',
        lambda cfg, host_src, attachment, **k: ReconcileResult(
            attachment=attachment,
            cached_ip='10.0.0.3',
            cached_ssh_ok=True,
        ),
    )

    primary_ready_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(
        'aivm.attachments.session._ensure_attachment_available_in_guest',
        lambda *a, **k: primary_ready_calls.append((a, k)) or None,
    )

    shared_root_host_binds: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_host_bind',
        lambda *a, **k: (
            shared_root_host_binds.append((a, k)) or Path('/tmp/token')
        ),
    )
    shared_root_vm_mappings: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_vm_mapping',
        lambda *a, **k: shared_root_vm_mappings.append((a, k)) or None,
    )
    shared_root_guest_binds: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_shared_root_guest_bind',
        lambda *a, **k: shared_root_guest_binds.append((a, k)) or None,
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
    # The faked guest-availability step short-circuits the lower helpers.
    assert len(shared_root_host_binds) == 0
    assert len(shared_root_vm_mappings) == 0
    assert len(shared_root_guest_binds) == 0

    # Both shared-root attachments are recorded for the VM.
    saved = load_store(cfg_path)
    by_path = {a.host_path: a for a in saved.attachments}
    assert str(host_src.resolve()) in by_path
    docs = by_path[str(other_src.resolve())]
    assert docs.vm_name == 'restore-shared-root-vm'
    assert docs.mode == AttachmentMode.SHARED_ROOT
    assert docs.guest_dst == '/workspace/docs'
