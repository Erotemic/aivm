"""VM attachment CLI command implementations.

This module owns both the kwconf CLI surface for ``aivm vm attach``,
``aivm vm detach``, and the persistent-host-replay commands, and the
business logic those commands invoke. kwconf classes are the
programmatic entry point as well — call ``VMAttachCLI.main(argv=False,
host_src=..., yes=True, ...)`` from Python instead of going through a
separate Request/Result layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import kwconf

from ..attachments.guest import _ensure_attachment_available_in_guest
from ..attachments.persistent import (
    _install_persistent_host_bind_replay,
    _prepare_persistent_attachment_host_and_vm,
    _reconcile_persistent_attachments_in_guest,
    _reconcile_persistent_host_binds,
    _sync_persistent_attachment_manifest_on_host,
)
from ..attachments.resolve import (
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT,
    _normalize_attachment_access,
    _normalize_attachment_mode,
    _resolve_attachment,
    logical_absolute_path,
)
from ..attachments.safety import (
    AttachmentSafetyReport,
    attachment_safety_preflight,
)
from ..attachments.session import (
    _record_attachment,
    _resolve_ip_for_ssh_ops,
)
from ..attachments.shared_root import (
    _detach_shared_root_guest_bind,
    _detach_shared_root_host_bind,
    _ensure_shared_root_host_bind,
    _ensure_shared_root_vm_mapping,
)
from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_store import (
    AttachmentEntry,
    Store,
    find_attachment_for_vm,
    load_store,
    remove_attachment,
    save_store,
)
from ..status import probe_vm_state
from ..vm import (
    attach_vm_share,
    detach_vm_share,
    refresh_cloud_init_seed_for_next_boot,
    vm_share_mappings,
)
from ..vm.drift import attachment_has_mapping as drift_attachment_has_mapping
from ..vm.share import ResolvedAttachment
from ..vm.share import (
    align_attachment_tag_with_mappings as drift_align_attachment_tag_with_mappings,
)
from ._common import (
    _BaseCommand,
    _load_cfg_with_path,
    _maybe_offer_create_ssh_identity,
    _record_vm,
    _resolve_cfg_for_code,
    log,
)


@dataclass(frozen=True)
class VMAttachRequest:
    """Inputs for attaching/registering a host directory to a VM."""

    config_opt: str | None
    vm_opt: str
    host_src: Path
    guest_dst: str = ''
    mode: str = ''
    access: str = ''
    dry_run: bool = False
    yes: bool = False


@dataclass(frozen=True)
class VMDetachRequest:
    """Inputs for detaching/unregistering a host directory from a VM."""

    config_opt: str | None
    vm_opt: str
    host_src: Path
    dry_run: bool = False
    yes: bool = False


@dataclass(frozen=True)
class VMPersistentHostReplayRequest:
    """Inputs for replaying host-side persistent bind mounts."""

    config_opt: str | None
    vm_opt: str
    dry_run: bool = False


@dataclass(frozen=True)
class VMInstallPersistentHostReplayServiceRequest:
    """Inputs for installing the persistent host replay systemd service."""

    config_opt: str | None
    vm_opt: str
    dry_run: bool = False


def _validate_host_directory(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        raise RuntimeError(f'host_src must be an existing directory: {path}')


def _resolve_attach_config(
    request: VMAttachRequest, host_src: Path
) -> tuple[AgentVMConfig, Path]:
    """Resolve the target VM config for an attach request.

    An explicit ``--config`` wins, then ``--vm``; otherwise fall back to the
    folder-oriented resolution used by ``aivm code`` (nearest saved
    attachment or the default VM for this host).
    """
    if request.config_opt:
        return _load_cfg_with_path(request.config_opt, vm_opt=request.vm_opt)
    if request.vm_opt:
        return _load_cfg_with_path(None, vm_opt=request.vm_opt)
    return _resolve_cfg_for_code(
        config_opt=None,
        vm_opt='',
        host_src=host_src,
    )


def _print_attach_refusal(
    report: AttachmentSafetyReport, host_src: Path, vm_name: str
) -> None:
    """Explain why the safety preflight declined the attachment."""
    if report.sensitive_hits:
        print(
            f'Aborted: declined to attach sensitive path {host_src} to VM {vm_name}.'
        )
    else:
        print(
            f'Aborted: declined to add overlapping attachment {host_src} to VM {vm_name}.'
        )


def _ensure_attachment_in_vm_definition(
    cfg: AgentVMConfig,
    attachment: ResolvedAttachment,
    host_src: Path,
    *,
    yes: bool,
) -> tuple[ResolvedAttachment, bool, bool]:
    """Expose the attachment in the VM definition when the VM exists.

    For ``shared`` mode this attaches the virtiofs mapping if it is missing.
    For ``shared-root``/``persistent`` modes on a stopped VM it prepares the
    host-side export and root mapping now so the next boot has it; when the
    VM is running that work happens during guest reconciliation instead.

    Returns the (possibly tag-realigned) attachment plus
    ``(vm_defined, vm_running)``.
    """
    # probe_vm_state escalates to sudo internally only when the unprivileged
    # read is inconclusive, so one call covers both cases.
    vm_out, vm_defined_probe = probe_vm_state(cfg, use_sudo=True)
    vm_defined = bool(vm_defined_probe)
    if not vm_defined:
        return attachment, False, False
    vm_running = vm_out.ok is True
    if attachment.mode == ATTACHMENT_MODE_SHARED:
        mappings = vm_share_mappings(cfg)
        attachment = drift_align_attachment_tag_with_mappings(
            attachment, host_src, mappings
        )
        if not drift_attachment_has_mapping(cfg, attachment, mappings):
            attach_vm_share(
                cfg,
                attachment.source_dir,
                attachment.tag,
                dry_run=False,
            )
    elif (
        attachment.mode
        in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}
        and not vm_running
    ):
        mgr = CommandManager.current()
        with mgr.intent(
            f'Attach and reconcile {attachment.mode.value!r} mapping',
            why='Ensure the requested host folder is exposed to the VM before the next guest session uses it.',
            role='modify',
        ):
            if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
                _prepare_persistent_attachment_host_and_vm(
                    cfg,
                    attachment,
                    dry_run=False,
                    vm_running=False,
                )
            else:
                _ensure_shared_root_host_bind(
                    cfg,
                    attachment,
                    yes=yes,
                    dry_run=False,
                )
                _ensure_shared_root_vm_mapping(
                    cfg,
                    yes=yes,
                    dry_run=False,
                    vm_running=False,
                )
    return attachment, vm_defined, vm_running


def _reconcile_attachment_in_running_guest(
    cfg: AgentVMConfig,
    cfg_path: Path,
    attachment: ResolvedAttachment,
    host_src: Path,
    *,
    yes: bool,
) -> None:
    """Reconcile a newly recorded attachment inside the running guest."""
    if _maybe_offer_create_ssh_identity(
        cfg,
        yes=yes,
        prompt_reason=(
            'Generate a dedicated SSH keypair so aivm can reconcile '
            'the running VM guest attachment state.'
        ),
    ):
        _record_vm(
            cfg,
            cfg_path,
            reason=(
                f'Persist newly generated SSH identity paths for VM '
                f'{cfg.vm.name} before guest attachment reconciliation.'
            ),
        )
    log.info(
        'VM {} is running; reconciling attachment in guest: {} (mode={} access={})',
        cfg.vm.name,
        attachment.guest_dst,
        attachment.mode,
        attachment.access,
    )
    ip = _resolve_ip_for_ssh_ops(
        cfg,
        yes=yes,
        purpose='Query VM networking state before reconciling attached folder.',
    )
    # Look up the persisted record (matched by resolved host_path) so
    # any aliases recorded earlier are also surfaced as guest symlinks.
    reg_for_aliases = load_store(cfg_path)
    saved = find_attachment_for_vm(reg_for_aliases, host_src, cfg.vm.name)
    aliases = list(saved.host_lexical_paths) if saved else []
    _ensure_attachment_available_in_guest(
        cfg,
        host_src,
        attachment,
        ip,
        yes=yes,
        dry_run=False,
        ensure_shared_root_host_side=(
            attachment.mode
            in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}
        ),
        mirror_home=bool(cfg.vm.mirror_shared_home_folders),
        host_lexical_paths=aliases,
    )
    if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
        _reconcile_persistent_attachments_in_guest(
            cfg,
            cfg_path,
            ip,
            dry_run=False,
        )


def _print_attach_result(
    cfg: AgentVMConfig,
    cfg_path: Path,
    reg_path: Path,
    attachment: ResolvedAttachment,
    host_src: Path,
    *,
    vm_defined: bool,
    vm_running: bool,
) -> None:
    """Summarize what the attach accomplished and what happens next."""
    mounted_modes = {
        ATTACHMENT_MODE_PERSISTENT,
        ATTACHMENT_MODE_SHARED,
        ATTACHMENT_MODE_SHARED_ROOT,
    }
    print(
        f'Attached {host_src} to VM {cfg.vm.name} ({attachment.mode} mode, access={attachment.access})'
    )
    if vm_running and attachment.mode in mounted_modes:
        print(f'Mounted in running VM at {attachment.guest_dst}')
    elif vm_running:
        print(f'Guest clone ready at {attachment.guest_dst}')
    elif vm_defined:
        if attachment.mode in mounted_modes:
            print(
                f'VM {cfg.vm.name} is not running; share will mount when VM is running and attach/ssh/code is used.'
            )
        else:
            print(
                f'VM {cfg.vm.name} is not running; guest clone will be created when VM is running and attach/ssh/code is used.'
            )
    print(f'Updated config store: {cfg_path}')
    print(f'Updated attachments: {reg_path}')


def run_vm_attach(request: VMAttachRequest) -> int:
    """Attach/register a host directory to an existing managed VM.

    Phases: resolve the target config and attachment, run the safety
    preflight, expose the mapping in the VM definition, record the
    attachment, then reconcile the running guest if there is one.
    """
    host_src = logical_absolute_path(request.host_src)
    _validate_host_directory(host_src)
    cfg, cfg_path = _resolve_attach_config(request, host_src)
    attachment = _resolve_attachment(
        cfg,
        cfg_path,
        host_src,
        request.guest_dst,
        request.mode,
        request.access,
    )

    existing_reg = load_store(cfg_path)
    ok, report = attachment_safety_preflight(
        host_src,
        existing_attachments=existing_reg.attachments,
        vm_name=cfg.vm.name,
        yes=bool(request.yes),
        dry_run=bool(request.dry_run),
    )
    if request.dry_run:
        print(
            f'DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {attachment.guest_dst} ({attachment.mode} mode, access={attachment.access})'
        )
        return 0
    if not ok:
        _print_attach_refusal(report, host_src, cfg.vm.name)
        return 2

    _record_vm(
        cfg,
        cfg_path,
        reason=(
            f'Persist resolved VM/network metadata before attaching '
            f'{host_src} to {cfg.vm.name}.'
        ),
    )
    attachment, vm_defined, vm_running = _ensure_attachment_in_vm_definition(
        cfg, attachment, host_src, yes=bool(request.yes)
    )
    reg_path = _record_attachment(
        cfg,
        cfg_path,
        host_src=host_src,
        mode=attachment.mode,
        access=attachment.access,
        guest_dst=attachment.guest_dst,
        tag=attachment.tag,
    )
    if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
        _sync_persistent_attachment_manifest_on_host(
            cfg,
            cfg_path,
            dry_run=False,
        )
        if vm_defined and not vm_running:
            refresh_cloud_init_seed_for_next_boot(cfg, dry_run=False)
    if vm_running:
        _reconcile_attachment_in_running_guest(
            cfg, cfg_path, attachment, host_src, yes=bool(request.yes)
        )
    _print_attach_result(
        cfg,
        cfg_path,
        reg_path,
        attachment,
        host_src,
        vm_defined=vm_defined,
        vm_running=vm_running,
    )
    return 0


def _detach_shared_root_attachment(
    cfg: AgentVMConfig,
    resolved: ResolvedAttachment,
    *,
    vm_running: bool,
    yes: bool,
) -> tuple[bool, bool, bool]:
    """Tear down guest and host bind mounts for a shared-root attachment.

    Both halves are attempted independently; failures are logged rather than
    raised so a partial detach keeps the store record and can be retried.

    Returns ``(guest_bind_detached, host_bind_detached, failed)``.
    """
    detached_guest = False
    detached_host = False
    failed = False
    if vm_running:
        try:
            ip = _resolve_ip_for_ssh_ops(
                cfg,
                yes=yes,
                purpose='Query VM networking state before detaching shared-root guest mount.',
            )
            _detach_shared_root_guest_bind(
                cfg,
                ip,
                resolved,
                dry_run=False,
            )
            detached_guest = True
        except Exception as ex:
            failed = True
            log.warning(
                'Could not detach shared-root guest bind mount for VM {} at {}: {}',
                cfg.vm.name,
                resolved.guest_dst,
                ex,
            )
    if resolved.tag:
        try:
            _detach_shared_root_host_bind(
                cfg,
                resolved,
                yes=yes,
                dry_run=False,
            )
            detached_host = True
        except Exception as ex:
            failed = True
            log.warning(
                'Could not detach shared-root host bind mount for VM {} source={} guest_dst={} token={}: {}',
                cfg.vm.name,
                resolved.source_dir,
                resolved.guest_dst,
                resolved.tag,
                ex,
            )
    else:
        failed = True
        log.warning(
            'Skipping shared-root host bind cleanup for VM {} source={} because attachment token is missing.',
            cfg.vm.name,
            resolved.source_dir,
        )
    return detached_guest, detached_host, failed


def _detach_persistent_attachment(
    cfg: AgentVMConfig,
    cfg_path: Path,
    reg: Store,
    host_src: Path,
    resolved: ResolvedAttachment,
    *,
    vm_running: bool,
    yes: bool,
) -> bool:
    """Drop a persistent attachment intent and reconcile guest state.

    The store record is removed up front — the synced manifest is what the
    guest replays — and guest reconciliation then prunes the now-unlisted
    mount. Returns True when cleanup was incomplete.
    """
    removed = remove_attachment(reg, host_path=host_src, vm_name=cfg.vm.name)
    if removed:
        save_store(
            reg,
            cfg_path,
            reason=(
                f'Remove persistent attachment record for {host_src} from VM '
                f'{cfg.vm.name}.'
            ),
        )
        _sync_persistent_attachment_manifest_on_host(
            cfg,
            cfg_path,
            dry_run=False,
        )
    if not vm_running:
        return False
    try:
        ip = _resolve_ip_for_ssh_ops(
            cfg,
            yes=yes,
            purpose='Query VM networking state before reconciling persistent attachment removal.',
        )
        _reconcile_persistent_attachments_in_guest(
            cfg,
            cfg_path,
            ip,
            dry_run=False,
        )
    except Exception as ex:
        log.warning(
            'Could not reconcile persistent attachment removal for VM {} source={} guest_dst={} token={}: {}',
            cfg.vm.name,
            resolved.source_dir,
            resolved.guest_dst,
            resolved.tag,
            ex,
        )
        return True
    return False


def _print_detach_result(
    cfg: AgentVMConfig,
    cfg_path: Path,
    att: AttachmentEntry,
    host_src: Path,
    mode: str,
    *,
    vm_defined: bool | None,
    vm_running: bool,
    detached_share: bool,
    detached_shared_root_host_bind: bool,
    detached_shared_root_guest_bind: bool,
) -> None:
    """Summarize what the detach accomplished per attachment mode."""
    print(f'Detached {host_src} from VM {cfg.vm.name} ({mode} mode)')
    if mode == ATTACHMENT_MODE_SHARED and vm_defined is True:
        if detached_share:
            print('Detached virtiofs mapping from VM definition.')
        elif att.tag:
            print(
                'No matching virtiofs mapping found in VM definition (already absent).'
            )
    if mode == ATTACHMENT_MODE_SHARED_ROOT:
        if detached_shared_root_host_bind:
            print('Detached shared-root host bind mount.')
        if vm_running and detached_shared_root_guest_bind:
            print('Detached shared-root guest bind mount.')
    if mode == ATTACHMENT_MODE_PERSISTENT:
        print(
            'Removed persistent attachment intent and refreshed the guest replay manifest.'
        )
    if vm_running and mode == ATTACHMENT_MODE_SHARED:
        print(
            f'If the guest still has {att.guest_dst or host_src} mounted, unmount it inside the VM manually.'
        )
    print(f'Updated config store: {cfg_path}')


def run_vm_detach(request: VMDetachRequest) -> int:
    """Detach/unregister a host directory from a managed VM.

    Phases: locate the saved attachment, probe VM state, run the
    mode-specific teardown, then remove the store record only when cleanup
    fully succeeded (persistent mode removes its record up front because the
    manifest drives guest replay).
    """
    host_src = logical_absolute_path(request.host_src)
    _validate_host_directory(host_src)

    cfg, cfg_path = _resolve_cfg_for_code(
        config_opt=request.config_opt,
        vm_opt=request.vm_opt,
        host_src=host_src,
    )
    reg = load_store(cfg_path)
    att = find_attachment_for_vm(reg, host_src, cfg.vm.name)
    if att is None:
        print(
            f'No attachment found for {host_src} on VM {cfg.vm.name}. '
            'Nothing to do.'
        )
        return 0
    if request.dry_run:
        print(
            f'DRYRUN: would detach {host_src} from VM {cfg.vm.name} ({att.mode} mode)'
        )
        return 0

    # probe_vm_state escalates to sudo internally only when the unprivileged
    # read is inconclusive, so one call covers both cases.
    vm_out, vm_defined = probe_vm_state(cfg, use_sudo=True)
    vm_running = bool(vm_out.ok)
    mode = _normalize_attachment_mode(att.mode)
    resolved = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=mode,
        access=_normalize_attachment_access(att.access),
        source_dir=str(host_src),
        guest_dst=att.guest_dst or str(host_src),
        tag=att.tag,
    )

    detached_share = False
    detached_shared_root_host_bind = False
    detached_shared_root_guest_bind = False
    detach_failed = False
    if mode == ATTACHMENT_MODE_SHARED and vm_defined is True and att.tag:
        detached_share = detach_vm_share(
            cfg, att.host_path, att.tag, dry_run=False
        )
    elif mode == ATTACHMENT_MODE_SHARED_ROOT:
        (
            detached_shared_root_guest_bind,
            detached_shared_root_host_bind,
            detach_failed,
        ) = _detach_shared_root_attachment(
            cfg, resolved, vm_running=vm_running, yes=bool(request.yes)
        )
    elif mode == ATTACHMENT_MODE_PERSISTENT:
        detach_failed = _detach_persistent_attachment(
            cfg,
            cfg_path,
            reg,
            host_src,
            resolved,
            vm_running=vm_running,
            yes=bool(request.yes),
        )

    if detach_failed:
        log.error(
            'Detach cleanup was incomplete for {} on VM {}; preserving config record so detach can be retried.',
            host_src,
            cfg.vm.name,
        )
        return 2

    if mode != ATTACHMENT_MODE_PERSISTENT:
        removed = remove_attachment(
            reg, host_path=host_src, vm_name=cfg.vm.name
        )
        if removed:
            save_store(
                reg,
                cfg_path,
                reason=(
                    f'Remove attachment record for {host_src} from VM '
                    f'{cfg.vm.name}.'
                ),
            )

    _print_detach_result(
        cfg,
        cfg_path,
        att,
        host_src,
        mode,
        vm_defined=vm_defined,
        vm_running=vm_running,
        detached_share=detached_share,
        detached_shared_root_host_bind=detached_shared_root_host_bind,
        detached_shared_root_guest_bind=detached_shared_root_guest_bind,
    )
    return 0


def run_persistent_host_replay(
    request: VMPersistentHostReplayRequest,
) -> int:
    """Replay host-side persistent bind mounts from the saved manifest."""
    cfg, cfg_path = _load_cfg_with_path(
        request.config_opt, vm_opt=request.vm_opt
    )
    _sync_persistent_attachment_manifest_on_host(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
    )
    _reconcile_persistent_host_binds(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
        vm_running=None,
    )
    if request.dry_run:
        print(
            f'DRYRUN: would replay host-side persistent bind mounts for VM {cfg.vm.name}'
        )
    else:
        print(
            f'Replayed host-side persistent bind mounts for VM {cfg.vm.name}'
        )
    return 0


def run_install_persistent_host_replay_service(
    request: VMInstallPersistentHostReplayServiceRequest,
) -> int:
    """Install and enable a host systemd service for persistent bind replay."""
    cfg, cfg_path = _load_cfg_with_path(
        request.config_opt, vm_opt=request.vm_opt
    )
    _sync_persistent_attachment_manifest_on_host(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
    )
    _install_persistent_host_bind_replay(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
    )
    if request.dry_run:
        print(
            f'DRYRUN: would install the persistent host replay service for VM {cfg.vm.name}'
        )
    else:
        print(
            f'Installed and enabled the persistent host replay service for VM {cfg.vm.name}'
        )
    return 0


class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    host_src: str = kwconf.Value(
        '.', position=1, help='Host directory to attach.'
    )
    guest_dst: str = kwconf.Value('', help='Guest mount path override.')
    mode: Literal['', 'shared', 'shared-root', 'persistent', 'git'] = kwconf.Value(
        '',
        help='Attachment mode: shared, shared-root, persistent, or git (default: saved mode or persistent; mode changes require detach+reattach).',
    )
    access: Literal['', 'rw', 'ro'] = kwconf.Value(
        '',
        help='Attachment access: rw or ro (default: saved access or rw). ro is supported for shared, shared-root, and persistent modes.',
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMAttachCLI.main host_src={} vm={} guest_dst={} mode={} access={} dry_run={} yes={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            args.mode,
            args.access,
            bool(args.dry_run),
            bool(args.yes),
        )
        return run_vm_attach(
            VMAttachRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src),
                guest_dst=args.guest_dst,
                mode=args.mode,
                access=args.access,
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        )


class VMDetachCLI(_BaseCommand):
    """Detach/unregister a host directory from a managed VM."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    host_src: str = kwconf.Value(
        '.', position=1, help='Host directory to detach.'
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_vm_detach(
            VMDetachRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src),
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
            )
        )


class VMPersistentHostReplayCLI(_BaseCommand):
    """Replay host-side persistent bind mounts from the saved manifest."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_persistent_host_replay(
            VMPersistentHostReplayRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                dry_run=bool(args.dry_run),
            )
        )


class VMInstallPersistentHostReplayServiceCLI(_BaseCommand):
    """Install and enable a host systemd service for persistent bind replay."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_install_persistent_host_replay_service(
            VMInstallPersistentHostReplayServiceRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                dry_run=bool(args.dry_run),
            )
        )
