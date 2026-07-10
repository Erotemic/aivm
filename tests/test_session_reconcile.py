"""Tests for :func:`aivm.attachments.session._reconcile_attached_vm`.

``_reconcile_attached_vm`` is the heavy orchestration pivot that ``aivm
code`` and its siblings call to bring a VM, its network, its firewall,
and its virtiofs shares into the desired state before an SSH/editor
session opens.  Every other session test stubs it wholesale; this file
drives the real function.

The key enabling fact is that ``_reconcile_attached_vm`` never touches
``subprocess`` directly -- every virsh/ssh/nft/mount call funnels through
the :class:`~aivm.commands.CommandManager`.  So these tests fake the one
true boundary (``aivm.commands.subprocess.run`` via
:func:`tests.helpers.command_recorder`), script the virsh/ssh/nft/mount
surfaces, and let the whole reconcile orchestration -- probe ordering,
share-mapping alignment, live-attach, firewall/network reconciliation --
run for real against a config rooted in ``tmp_path``.  No live VM is
needed.

Assertions are on observable artifacts only: the recorded (sudo-stripped)
argv, the returned :class:`~aivm.attachments.session.ReconcileResult`, and
captured warnings.

The only collaborator stubbed is ``create_or_start_vm`` and only in the
three tests that force its *recreate*/*dry-run*/*full-build* path (which
issues the fetch-image/virt-install surface that cannot be practically
scripted through ``subprocess.run``).  The stopped-VM test exercises the
real ``create_or_start_vm`` start path so the "must start a stopped VM"
decision is genuinely covered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest
from pytest import MonkeyPatch

from aivm.attachments.session import (
    ReconcilePolicy,
    _reconcile_attached_vm,
)
from aivm.attachments.shared_root import (
    _shared_root_host_dir,
    _shared_root_host_target,
)
from aivm.errors import AIVMError
from aivm.vm.paths import _paths
from aivm.vm.share import (
    AttachmentMode,
    ResolvedAttachment,
)
from tests.helpers import (
    FakeProc,
    activate_manager,
    capture_logs,
    command_recorder,
    make_cfg,
)

VM_NAME = 'recon-vm'
PROJ_TAG = 'hostcode-proj'
PROJ_DST = '/workspace/proj'

# Every path that evaluates ``virsh_needs_sudo`` under the default
# (as-needed) privilege mode issues one cached ``virsh list --name`` probe
# to learn whether the libvirt group grants unprivileged access.  Answering
# it success keeps commands unprivileged (the recorder strips sudo anyway).
LIBVIRT_PROBE = 'virsh list --name'


def _domain_xml(
    *,
    filesystems: tuple[tuple[str, str], ...] = (),
    shared_memory: bool = False,
) -> str:
    """Render a minimal libvirt domain XML for ``virsh dumpxml`` replies.

    ``filesystems`` are ``(source_dir, target_tag)`` virtiofs mappings and
    ``shared_memory`` adds the memfd/shared backing that
    ``vm_has_virtiofs_shared_memory`` requires.
    """
    mem = (
        "  <memoryBacking>\n"
        "    <source type='memfd'/>\n"
        "    <access mode='shared'/>\n"
        "  </memoryBacking>\n"
        if shared_memory
        else ''
    )
    devices = ''.join(
        "    <filesystem type='mount' accessmode='passthrough'>\n"
        "      <driver type='virtiofs'/>\n"
        f"      <source dir='{src}'/>\n"
        f"      <target dir='{tag}'/>\n"
        "    </filesystem>\n"
        for src, tag in filesystems
    )
    return (
        "<domain type='kvm'>\n"
        f"{mem}"
        "  <devices>\n"
        f"{devices}"
        "  </devices>\n"
        "</domain>\n"
    )


def _states(*states: str) -> Callable[[list[str]], FakeProc]:
    """Route ``virsh domstate`` to yield each state once, repeating the last."""
    remaining = list(states)

    def _run(_cmd: list[str]) -> FakeProc:
        state = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        return FakeProc(0, state + '\n')

    return _run


def _sequence(*procs: FakeProc) -> Callable[[list[str]], FakeProc]:
    """Route a command to yield each proc once, repeating the last."""
    remaining = list(procs)

    def _run(_cmd: list[str]) -> FakeProc:
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    return _run


def _make_env(
    tmp_path: Path,
    *,
    mode: AttachmentMode = AttachmentMode.SHARED,
    tag: str = PROJ_TAG,
    guest_dst: str = PROJ_DST,
) -> tuple[Any, Path, ResolvedAttachment]:
    """Build ``(cfg, host_src, attachment)`` rooted under ``tmp_path``."""
    cfg = make_cfg(tmp_path, **{'vm.name': VM_NAME})
    host_src = tmp_path / 'proj'
    host_src.mkdir()
    attachment = ResolvedAttachment(
        vm_name=VM_NAME,
        mode=mode,
        source_dir=str(host_src.resolve()),
        guest_dst=guest_dst,
        tag=tag,
    )
    return cfg, host_src, attachment


def _policy(
    *,
    ensure_firewall: bool = False,
    recreate: bool = False,
    dry_run: bool = False,
    yes: bool = True,
) -> ReconcilePolicy:
    """Build a :class:`ReconcilePolicy` with firewall reconcile off by default."""
    return ReconcilePolicy(
        ensure_firewall_opt=ensure_firewall,
        recreate_if_needed=recreate,
        dry_run=dry_run,
        yes=yes,
    )


def _active_net() -> FakeProc:
    """A ``virsh net-info`` reply reporting the network is active."""
    return FakeProc(0, 'Active:         yes\nAutostart:      yes\n')


def test_running_vm_with_present_share_makes_no_changes(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A running VM that already exports the share triggers no mutations.

    Only read probes (domstate/net-info/dumpxml) should run; no start,
    attach, recreate, or dominfo command is issued, and the domain XML is
    read exactly once thanks to the manager's probe cache.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(
                0,
                _domain_xml(
                    filesystems=((str(host_src.resolve()), PROJ_TAG),),
                    shared_memory=True,
                ),
            ),
        },
    )

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    assert result.attachment.tag == PROJ_TAG
    assert result.cached_ip is None
    assert result.cached_ssh_ok is False
    assert result.shared_root_host_side_ready is False
    assert not rec.ran('virsh', 'start')
    assert not rec.ran('virsh', 'attach-device')
    assert not rec.ran('virsh', 'dominfo')
    assert rec.count('virsh', 'dumpxml', VM_NAME) == 1


def test_stopped_vm_is_started_before_confirming_share(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A defined-but-stopped VM is started via the real create/start path.

    The reconcile must detect the VM is not running and drive
    ``create_or_start_vm``, whose start branch issues ``virsh start``.  The
    domain already exports the share, so once running no attach is needed.
    ``virsh start`` originates only from that start path, so its presence
    proves the "start a stopped VM" decision was taken.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    xml = _domain_xml(
        filesystems=((str(host_src.resolve()), PROJ_TAG),),
        shared_memory=True,
    )
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            # probe -> create's internal check -> post-start re-probe.
            'virsh domstate': _states('shut off', 'shut off', 'running'),
            'virsh dominfo': FakeProc(0, 'Name:           recon-vm\n'),
            'virsh net-info': _active_net(),
            'virsh start': FakeProc(0),
            'virsh dumpxml': FakeProc(0, xml),
        },
    )

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    assert rec.only('virsh', 'start', VM_NAME) == ['virsh', 'start', VM_NAME]
    assert not rec.ran('virsh', 'attach-device')
    assert result.attachment.tag == PROJ_TAG


def test_running_vm_attaches_missing_share_live(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A running VM missing the mapping gets a live virtiofs attach.

    The domain advertises shared-memory backing but not the requested
    source/tag, so the reconcile must call ``attach_vm_share`` against the
    live domain (``virsh attach-device ... --live --config``).
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, _domain_xml(shared_memory=True)),
            'virsh attach-device': FakeProc(0),
        },
    )

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    attach = rec.only('virsh', 'attach-device', VM_NAME)
    assert '--live' in attach
    assert '--config' in attach
    assert not rec.ran('virsh', 'start')
    assert result.shared_root_host_side_ready is False


def test_running_vm_live_attach_failure_raises_actionable_error(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A failed live attach is surfaced as an actionable AIVMError.

    The domain has shared-memory backing but the mapping is missing, so the
    reconcile attempts a live attach; when ``virsh attach-device`` fails it
    must wrap the failure with the requested mapping and next-step guidance
    rather than letting the raw command error escape.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, _domain_xml(shared_memory=True)),
            'virsh attach-device': FakeProc(
                1, '', 'error: internal error: device attach failed'
            ),
        },
    )

    with pytest.raises(AIVMError, match='live attach failed'):
        _reconcile_attached_vm(cfg, host_src, attachment, policy=_policy())

    assert rec.ran('virsh', 'attach-device', VM_NAME)


def test_running_vm_without_shared_memory_refuses_without_recreate(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Missing shared-memory backing with recreate off raises, not attaches.

    When the domain lacks memfd/shared backing a live attach cannot work, so
    the reconcile refuses with a clear error rather than issuing a doomed
    ``attach-device``.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, _domain_xml(shared_memory=False)),
        },
    )

    with pytest.raises(AIVMError, match='shared-memory'):
        _reconcile_attached_vm(cfg, host_src, attachment, policy=_policy())

    assert not rec.ran('virsh', 'attach-device')


def test_running_vm_missing_share_recreates_when_allowed(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """With ``recreate_if_needed`` the reconcile rebuilds instead of attaching.

    ``create_or_start_vm``'s recreate path issues the full
    fetch-image/virt-install surface, which cannot be practically scripted
    through ``subprocess.run``; it is stubbed here so the recreate *decision*
    and its share kwargs are the artifact under test.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, _domain_xml(shared_memory=True)),
        },
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        'aivm.attachments.session.create_or_start_vm',
        lambda _cfg, **k: calls.append(k) or None,
    )

    _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy(recreate=True)
    )

    assert len(calls) == 1
    assert calls[0]['recreate'] is True
    assert calls[0]['share_source_dir'] == str(host_src.resolve())
    assert calls[0]['share_tag'] == PROJ_TAG
    # The recreate decision replaces the live attach.
    assert not rec.ran('virsh', 'attach-device')


def test_stale_virtiofs_source_recreates_vm(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A stale virtiofs export error on start triggers a recreate.

    The first ``create_or_start_vm`` fails with libvirt's "virtiofs export
    directory ... does not exist"; the reconcile must recognise that, warn,
    and retry with ``recreate=True``.  Both calls are on the stubbed builder
    (its full build surface is impractical to script); the decision and the
    warning are the artifacts.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    xml = _domain_xml(
        filesystems=((str(host_src.resolve()), PROJ_TAG),),
        shared_memory=True,
    )
    command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': _states('shut off', 'running'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, xml),
        },
    )
    calls: list[dict[str, Any]] = []

    def fake_create(_cfg: Any, **k: Any) -> None:
        calls.append(k)
        if len(calls) == 1:
            raise RuntimeError(
                "internal error: virtiofs export directory "
                "'/stale/export' does not exist"
            )

    monkeypatch.setattr(
        'aivm.attachments.session.create_or_start_vm', fake_create
    )
    warnings = capture_logs(monkeypatch, 'aivm.attachments.session.log')

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    assert len(calls) == 2
    assert calls[0]['recreate'] is False
    assert calls[1]['recreate'] is True
    assert any('stale virtiofs source' in m for m in warnings)
    assert result.attachment.tag == PROJ_TAG


def test_firewall_reconciled_when_table_missing(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """``ensure_firewall_opt`` loads nftables when the table is absent.

    The read probe reports the managed table missing, so the reconcile must
    call ``apply_firewall``, which reloads the ruleset via ``nft -f -``.  That
    command originates only from ``apply_firewall``, so its presence proves
    the firewall reconcile ran.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    xml = _domain_xml(
        filesystems=((str(host_src.resolve()), PROJ_TAG),),
        shared_memory=True,
    )
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, xml),
            # apply_firewall reads live network metadata; falling back to
            # config keeps this test focused on the nft reload decision.
            'virsh net-dumpxml': FakeProc(1),
            'nft list table': FakeProc(1, '', 'No such file or directory'),
            'nft delete table': FakeProc(0),
            'nft -f': FakeProc(0),
        },
    )

    _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy(ensure_firewall=True)
    )

    assert rec.only('nft', '-f', '-') == ['nft', '-f', '-']
    assert rec.count('nft', 'list', 'table', 'inet', cfg.firewall.table) == 1


def test_firewall_skipped_and_warned_when_privilege_never(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Under privilege_mode=never the firewall reconcile is skipped with a warning.

    nftables needs root, so a never-sudo run must not probe or reload the
    firewall; it should emit a single guiding warning instead.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch, privilege_mode='never')
    xml = _domain_xml(
        filesystems=((str(host_src.resolve()), PROJ_TAG),),
        shared_memory=True,
    )
    rec = command_recorder(
        monkeypatch,
        {
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, xml),
        },
    )
    warnings = capture_logs(
        monkeypatch, 'aivm.attachments.session.log', levels=('warning',)
    )

    _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy(ensure_firewall=True)
    )

    assert not rec.ran('nft')
    assert any('privilege_mode = ' in m for m in warnings)


def test_inactive_network_is_defined_and_started(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A defined-but-inactive network drives ``ensure_network`` to (re)create it.

    The reconcile probe reports the network inactive; ``ensure_network`` then
    finds it undefined and issues net-define/net-autostart/net-start.  Those
    define/start commands originate only from ``ensure_network``.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    xml = _domain_xml(
        filesystems=((str(host_src.resolve()), PROJ_TAG),),
        shared_memory=True,
    )
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            # reconcile probe sees it inactive; ensure_network sees it undefined.
            'virsh net-info': _sequence(
                FakeProc(0, 'Active:         no\n'),
                FakeProc(1, '', 'error: network not found'),
            ),
            'ip -4 route show': FakeProc(0, ''),
            'virsh net-define': FakeProc(0),
            'virsh net-autostart': FakeProc(0),
            'virsh net-start': FakeProc(0),
            'virsh dumpxml': FakeProc(0, xml),
        },
    )

    _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    assert rec.ran('virsh', 'net-define')
    assert rec.only('virsh', 'net-start', cfg.network.name) == [
        'virsh',
        'net-start',
        cfg.network.name,
    ]


def test_permission_denied_probe_falls_back_to_ssh_readiness(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """An inconclusive (permission-denied) domstate is rescued by SSH readiness.

    ``_probe_vm_running_nonsudo`` returns ``None`` on permission-denied, and a
    reachable cached IP with a passing SSH probe must be enough to treat the
    VM as running -- so no create/attach path runs.  Were the probe to report
    ``False`` instead of ``None`` the reconcile would fall into the
    create path (issuing ``virsh dominfo``); asserting that never happens is
    what discriminates the ``None`` handling.
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    ip_file = _paths(cfg)['ip_file']
    ip_file.parent.mkdir(parents=True, exist_ok=True)
    ip_file.write_text('10.0.0.9', encoding='utf-8')
    xml = _domain_xml(
        filesystems=((str(host_src.resolve()), PROJ_TAG),),
        shared_memory=True,
    )
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'ssh': FakeProc(0),
            'virsh domstate': FakeProc(
                1, '', 'error: authentication failed: permission denied'
            ),
            'virsh net-info': _active_net(),
            'virsh dumpxml': FakeProc(0, xml),
        },
    )

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    assert result.cached_ip == '10.0.0.9'
    assert result.cached_ssh_ok is True
    assert not rec.ran('virsh', 'dominfo')
    assert not rec.ran('virsh', 'start')
    assert not rec.ran('virsh', 'attach-device')


def test_shared_root_missing_mapping_binds_host_and_attaches(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """Shared-root mode with a missing export binds the host folder and attaches.

    For a running VM lacking the shared-root virtiofs export, the reconcile
    must bind the requested folder under the shared-root target on the host
    (``mount --bind``) and attach the single shared-root virtiofs device to the
    domain (``virsh attach-device``), then report the host side ready.
    """
    cfg, host_src, attachment = _make_env(
        tmp_path,
        mode=AttachmentMode.SHARED_ROOT,
        tag='token-proj',
    )
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh domstate': FakeProc(0, 'running\n'),
            'virsh net-info': _active_net(),
            # No shared-root mapping present yet; backing is available.
            'virsh dumpxml': FakeProc(0, _domain_xml(shared_memory=True)),
            'findmnt': FakeProc(1),
            'mkdir -p': FakeProc(0),
            'mount --bind': FakeProc(0),
            'virsh attach-device': FakeProc(0),
        },
    )

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy()
    )

    target = str(_shared_root_host_target(cfg, 'token-proj'))
    assert rec.only('mount', '--bind') == [
        'mount',
        '--bind',
        str(host_src.resolve()),
        target,
    ]
    attach = rec.only('virsh', 'attach-device', VM_NAME)
    assert '--live' in attach
    # The shared-root export is the single virtiofs device rooted at the host
    # shared-root dir, so has_share was computed against that pair.
    assert str(_shared_root_host_dir(cfg)) == target.rsplit('/', 1)[0]
    assert result.shared_root_host_side_ready is True


def test_dry_run_plans_create_without_probing_shares(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A dry run plans a create and skips every VM-state/share probe.

    Under ``dry_run`` the reconcile does no cached-IP/domstate/dumpxml work;
    it only evaluates the network probe and hands ``create_or_start_vm`` a
    ``dry_run=True`` plan (stubbed, since its build surface is impractical to
    script).
    """
    cfg, host_src, attachment = _make_env(tmp_path)
    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            LIBVIRT_PROBE: FakeProc(0),
            'virsh net-info': _active_net(),
        },
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        'aivm.attachments.session.create_or_start_vm',
        lambda _cfg, **k: calls.append(k) or None,
    )

    result = _reconcile_attached_vm(
        cfg, host_src, attachment, policy=_policy(dry_run=True)
    )

    assert len(calls) == 1
    assert calls[0]['dry_run'] is True
    assert result.cached_ip is None
    assert result.cached_ssh_ok is False
    assert not rec.ran('virsh', 'domstate')
    assert not rec.ran('virsh', 'dumpxml')
