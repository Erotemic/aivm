"""VM attachment CLI command implementations.

This module owns both the scriptconfig CLI surface for ``aivm vm attach``,
``aivm vm detach``, and the persistent-host-replay commands, and the
business logic those commands invoke. scriptconfig classes are the
programmatic entry point as well — call ``VMAttachCLI.main(argv=False,
host_src=..., yes=True, ...)`` from Python instead of going through a
separate Request/Result layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import scriptconfig as scfg

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
from ..attachments.safety import attachment_safety_preflight
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
from ..config_store import (
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


def run_vm_attach(request: VMAttachRequest) -> int:
    """Attach/register a host directory to an existing managed VM."""
    host_src = logical_absolute_path(request.host_src)
    _validate_host_directory(host_src)

    if request.config_opt:
        cfg, cfg_path = _load_cfg_with_path(
            request.config_opt, vm_opt=request.vm_opt
        )
    elif request.vm_opt:
        cfg, cfg_path = _load_cfg_with_path(None, vm_opt=request.vm_opt)
    else:
        cfg, cfg_path = _resolve_cfg_for_code(
            config_opt=None,
            vm_opt='',
            host_src=host_src,
        )

    attachment = _resolve_attachment(
        cfg,
        cfg_path,
        host_src,
        request.guest_dst,
        request.mode,
        request.access,
    )
    mirror_home = bool(cfg.vm.mirror_shared_home_folders)

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
        if report.sensitive_hits:
            print(
                f'Aborted: declined to attach sensitive path {host_src} to VM {cfg.vm.name}.'
            )
        else:
            print(
                f'Aborted: declined to add overlapping attachment {host_src} to VM {cfg.vm.name}.'
            )
        return 2

    _record_vm(
        cfg,
        cfg_path,
        reason=(
            f'Persist resolved VM/network metadata before attaching '
            f'{host_src} to {cfg.vm.name}.'
        ),
    )
    vm_running = False
    vm_defined = False
    sudo_confirmed = False
    vm_out, vm_defined_probe = probe_vm_state(cfg, use_sudo=False)
    vm_running_probe = bool(vm_out.ok)
    vm_defined = bool(vm_defined_probe)
    if not vm_defined:
        sudo_confirmed = True
        vm_out, vm_defined_probe = probe_vm_state(cfg, use_sudo=True)
        vm_running_probe = bool(vm_out.ok)
        vm_defined = bool(vm_defined_probe)
    if vm_defined:
        vm_running = vm_running_probe is True
        if attachment.mode == ATTACHMENT_MODE_SHARED:
            if not sudo_confirmed:
                sudo_confirmed = True
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
        elif attachment.mode in {
            ATTACHMENT_MODE_SHARED_ROOT,
            ATTACHMENT_MODE_PERSISTENT,
        }:
            if not vm_running:
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
                            yes=bool(request.yes),
                            dry_run=False,
                        )
                        _ensure_shared_root_vm_mapping(
                            cfg,
                            yes=bool(request.yes),
                            dry_run=False,
                            vm_running=False,
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
        if _maybe_offer_create_ssh_identity(
            cfg,
            yes=bool(request.yes),
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
            yes=bool(request.yes),
            purpose='Query VM networking state before reconciling attached folder.',
        )
        # Look up the persisted record (matched by resolved host_path) so
        # any aliases recorded earlier are also surfaced as guest symlinks.
        _reg_for_aliases = load_store(cfg_path)
        _saved = find_attachment_for_vm(
            _reg_for_aliases, host_src, cfg.vm.name
        )
        _aliases = list(_saved.host_lexical_paths) if _saved else []
        _ensure_attachment_available_in_guest(
            cfg,
            host_src,
            attachment,
            ip,
            yes=bool(request.yes),
            dry_run=False,
            ensure_shared_root_host_side=(
                attachment.mode
                in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}
            ),
            mirror_home=mirror_home,
            host_lexical_paths=_aliases,
        )
        if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
            _reconcile_persistent_attachments_in_guest(
                cfg,
                cfg_path,
                ip,
                dry_run=False,
            )
    print(
        f'Attached {host_src} to VM {cfg.vm.name} ({attachment.mode} mode, access={attachment.access})'
    )
    if vm_running and attachment.mode in {
        ATTACHMENT_MODE_PERSISTENT,
        ATTACHMENT_MODE_SHARED,
        ATTACHMENT_MODE_SHARED_ROOT,
    }:
        print(f'Mounted in running VM at {attachment.guest_dst}')
    elif vm_running:
        print(f'Guest clone ready at {attachment.guest_dst}')
    elif vm_defined:
        if attachment.mode in {
            ATTACHMENT_MODE_PERSISTENT,
            ATTACHMENT_MODE_SHARED,
            ATTACHMENT_MODE_SHARED_ROOT,
        }:
            print(
                f'VM {cfg.vm.name} is not running; share will mount when VM is running and attach/ssh/code is used.'
            )
        else:
            print(
                f'VM {cfg.vm.name} is not running; guest clone will be created when VM is running and attach/ssh/code is used.'
            )
    print(f'Updated config store: {cfg_path}')
    print(f'Updated attachments: {reg_path}')
    return 0


def run_vm_detach(request: VMDetachRequest) -> int:
    """Detach/unregister a host directory from a managed VM."""
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

    vm_out, vm_defined = probe_vm_state(cfg, use_sudo=False)
    vm_defined_probe = vm_defined
    if vm_defined_probe is False:
        vm_out, vm_defined = probe_vm_state(cfg, use_sudo=True)
        vm_defined_probe = vm_defined
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

    if (
        mode == ATTACHMENT_MODE_SHARED
        and vm_defined_probe is True
        and att.tag
    ):
        detached_share = detach_vm_share(
            cfg, att.host_path, att.tag, dry_run=False
        )

    if mode == ATTACHMENT_MODE_SHARED_ROOT:
        if vm_running:
            try:
                ip = _resolve_ip_for_ssh_ops(
                    cfg,
                    yes=bool(request.yes),
                    purpose='Query VM networking state before detaching shared-root guest mount.',
                )
                _detach_shared_root_guest_bind(
                    cfg,
                    ip,
                    resolved,
                    dry_run=False,
                )
                detached_shared_root_guest_bind = True
            except Exception as ex:
                detach_failed = True
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
                    yes=bool(request.yes),
                    dry_run=False,
                )
                detached_shared_root_host_bind = True
            except Exception as ex:
                detach_failed = True
                log.warning(
                    'Could not detach shared-root host bind mount for VM {} source={} guest_dst={} token={}: {}',
                    cfg.vm.name,
                    resolved.source_dir,
                    resolved.guest_dst,
                    resolved.tag,
                    ex,
                )
        else:
            detach_failed = True
            log.warning(
                'Skipping shared-root host bind cleanup for VM {} source={} because attachment token is missing.',
                cfg.vm.name,
                resolved.source_dir,
            )
    elif mode == ATTACHMENT_MODE_PERSISTENT:
        removed = remove_attachment(
            reg, host_path=host_src, vm_name=cfg.vm.name
        )
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
        if vm_running:
            try:
                ip = _resolve_ip_for_ssh_ops(
                    cfg,
                    yes=bool(request.yes),
                    purpose='Query VM networking state before reconciling persistent attachment removal.',
                )
                _reconcile_persistent_attachments_in_guest(
                    cfg,
                    cfg_path,
                    ip,
                    dry_run=False,
                )
            except Exception as ex:
                detach_failed = True
                log.warning(
                    'Could not reconcile persistent attachment removal for VM {} source={} guest_dst={} token={}: {}',
                    cfg.vm.name,
                    resolved.source_dir,
                    resolved.guest_dst,
                    resolved.tag,
                    ex,
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

    print(f'Detached {host_src} from VM {cfg.vm.name} ({mode} mode)')
    if mode == ATTACHMENT_MODE_SHARED and vm_defined_probe is True:
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

    vm: Any = scfg.Value('', help='Optional VM name override.')
    host_src: Any = scfg.Value(
        '.', position=1, help='Host directory to attach.'
    )
    guest_dst: Any = scfg.Value('', help='Guest mount path override.')
    mode: Any = scfg.Value(
        '',
        help='Attachment mode: shared, shared-root, persistent, or git (default: saved mode or persistent; mode changes require detach+reattach).',
    )
    access: Any = scfg.Value(
        '',
        help='Attachment access: rw or ro (default: saved access or rw). ro is supported for shared, shared-root, and persistent modes.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
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

    vm: Any = scfg.Value('', help='Optional VM name override.')
    host_src: Any = scfg.Value(
        '.', position=1, help='Host directory to detach.'
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
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

    vm: Any = scfg.Value('', help='Optional VM name override.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
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

    vm: Any = scfg.Value('', help='Optional VM name override.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
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
