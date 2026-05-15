"""Focused VM CLI command implementations.

This module is split out of :mod:`aivm.cli.vm`.  Private helper
dependencies are resolved through the legacy facade so existing tests
that monkeypatch ``aivm.cli.vm.<helper>`` continue to exercise the
same code paths during this compatibility phase.
"""

from __future__ import annotations

import os
import shlex
import socket
from pathlib import Path
from typing import Any

import scriptconfig as scfg

from ..attachments.resolve import (
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT,
)
from ..commands import CommandManager
from ..vm.share import ResolvedAttachment
from ..vm.update_ops import RestartKind
from ._common import _BaseCommand
from ._vm_compat import legacy as _legacy


_ensure_attachment_available_in_guest = _legacy('_ensure_attachment_available_in_guest')
_upsert_ssh_config_entry = _legacy('_upsert_ssh_config_entry')
_install_persistent_host_bind_replay = _legacy('_install_persistent_host_bind_replay')
_prepare_persistent_attachment_host_and_vm = _legacy('_prepare_persistent_attachment_host_and_vm')
_reconcile_persistent_attachments_in_guest = _legacy('_reconcile_persistent_attachments_in_guest')
_reconcile_persistent_host_binds = _legacy('_reconcile_persistent_host_binds')
_sync_persistent_attachment_manifest_on_host = _legacy('_sync_persistent_attachment_manifest_on_host')
_normalize_attachment_access = _legacy('_normalize_attachment_access')
_normalize_attachment_mode = _legacy('_normalize_attachment_mode')
_resolve_attachment = _legacy('_resolve_attachment')
_maybe_warn_hardware_drift = _legacy('_maybe_warn_hardware_drift')
_prepare_attached_session = _legacy('_prepare_attached_session')
_record_attachment = _legacy('_record_attachment')
_resolve_ip_for_ssh_ops = _legacy('_resolve_ip_for_ssh_ops')
_detach_shared_root_guest_bind = _legacy('_detach_shared_root_guest_bind')
_detach_shared_root_host_bind = _legacy('_detach_shared_root_host_bind')
_ensure_shared_root_host_bind = _legacy('_ensure_shared_root_host_bind')
_ensure_shared_root_vm_mapping = _legacy('_ensure_shared_root_vm_mapping')
_cfg_path = _legacy('_cfg_path')
_load_cfg = _legacy('_load_cfg')
_load_cfg_with_path = _legacy('_load_cfg_with_path')
_maybe_install_missing_host_deps = _legacy('_maybe_install_missing_host_deps')
_maybe_offer_create_ssh_identity = _legacy('_maybe_offer_create_ssh_identity')
_record_vm = _legacy('_record_vm')
_resolve_cfg_for_code = _legacy('_resolve_cfg_for_code')
_edit_path = _legacy('_edit_path')
_resolve_config_edit_target = _legacy('_resolve_config_edit_target')
attach_vm_share = _legacy('attach_vm_share')
create_or_start_vm = _legacy('create_or_start_vm')
destroy_vm = _legacy('destroy_vm')
detach_vm_share = _legacy('detach_vm_share')
find_attachment_for_vm = _legacy('find_attachment_for_vm')
find_network = _legacy('find_network')
load_config_document = _legacy('load_config_document')
load_store = _legacy('load_store')
log = _legacy('log')
mk_ssh_config = _legacy('mk_ssh_config')
network_users = _legacy('network_users')
probe_vm_state = _legacy('probe_vm_state')
provision = _legacy('provision')
refresh_cloud_init_seed_for_next_boot = _legacy('refresh_cloud_init_seed_for_next_boot')
remove_attachment = _legacy('remove_attachment')
remove_vm = _legacy('remove_vm')
require_ssh_identity = _legacy('require_ssh_identity')
restart_vm = _legacy('restart_vm')
save_store = _legacy('save_store')
shutdown_vm = _legacy('shutdown_vm')
ssh_base_args = _legacy('ssh_base_args')
vm_share_mappings = _legacy('vm_share_mappings')
vm_status = _legacy('vm_status')
wait_for_ip = _legacy('wait_for_ip')
which = _legacy('which')
create_vm_from_defaults = _legacy('create_vm_from_defaults')
drift_attachment_has_mapping = _legacy('drift_attachment_has_mapping')
drift_align_attachment_tag_with_mappings = _legacy('drift_align_attachment_tag_with_mappings')
_apply_vm_update = _legacy('_apply_vm_update')
_maybe_restart_vm_after_update = _legacy('_maybe_restart_vm_after_update')
_print_vm_update_plan = _legacy('_print_vm_update_plan')
_vm_update_drift = _legacy('_vm_update_drift')


class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    host_src: Any = scfg.Value(
        '.', position=1, help='Host directory to attach.'
    )
    guest_dst: Any = scfg.Value('', help='Guest mount path override.')
    mode: Any = scfg.Value(
        '',
        help='Attachment mode: shared, shared-root, persistent, or git (default: saved mode (TODO: programatic documentation of default); mode changes require detach+reattach).',
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
        host_src = Path(args.host_src).expanduser().absolute()
        if not host_src.exists() or not host_src.is_dir():
            raise RuntimeError(
                f'host_src must be an existing directory: {host_src}'
            )

        if args.config:
            cfg, cfg_path = _load_cfg_with_path(args.config, vm_opt=args.vm)
        elif args.vm:
            cfg, cfg_path = _load_cfg_with_path(None, vm_opt=args.vm)
        else:
            cfg, cfg_path = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt='',
                host_src=host_src,
            )

        attachment = _resolve_attachment(
            cfg, cfg_path, host_src, args.guest_dst, args.mode, args.access
        )
        reg = load_store(cfg_path)
        mirror_home = bool(reg.behavior.mirror_shared_home_folders)

        if args.dry_run:
            print(
                f'DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {attachment.guest_dst} ({attachment.mode} mode, access={attachment.access})'
            )
            return 0

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
                                yes=bool(args.yes),
                                dry_run=False,
                            )
                            _ensure_shared_root_vm_mapping(
                                cfg,
                                yes=bool(args.yes),
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
                yes=bool(args.yes),
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
                yes=bool(args.yes),
                purpose='Query VM networking state before reconciling attached folder.',
            )
            _ensure_attachment_available_in_guest(
                cfg,
                host_src,
                attachment,
                ip,
                yes=bool(args.yes),
                dry_run=False,
                ensure_shared_root_host_side=(
                    attachment.mode
                    in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}
                ),
                mirror_home=mirror_home,
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
        host_src = Path(args.host_src).resolve()
        if not host_src.exists() or not host_src.is_dir():
            raise RuntimeError(
                f'host_src must be an existing directory: {host_src}'
            )
        cfg, cfg_path = _resolve_cfg_for_code(
            config_opt=args.config,
            vm_opt=args.vm,
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
        if args.dry_run:
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
                        yes=bool(args.yes),
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
                        yes=bool(args.yes),
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
                        yes=bool(args.yes),
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


class VMPersistentHostReplayCLI(_BaseCommand):
    """Replay host-side persistent bind mounts from the saved manifest."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config, vm_opt=args.vm)
        _sync_persistent_attachment_manifest_on_host(
            cfg,
            cfg_path,
            dry_run=bool(args.dry_run),
        )
        _reconcile_persistent_host_binds(
            cfg,
            cfg_path,
            dry_run=bool(args.dry_run),
            vm_running=None,
        )
        if args.dry_run:
            print(
                f'DRYRUN: would replay host-side persistent bind mounts for VM {cfg.vm.name}'
            )
        else:
            print(
                f'Replayed host-side persistent bind mounts for VM {cfg.vm.name}'
            )
        return 0


class VMInstallPersistentHostReplayServiceCLI(_BaseCommand):
    """Install and enable a host systemd service for persistent bind replay."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config, vm_opt=args.vm)
        _sync_persistent_attachment_manifest_on_host(
            cfg,
            cfg_path,
            dry_run=bool(args.dry_run),
        )
        _install_persistent_host_bind_replay(
            cfg,
            cfg_path,
            dry_run=bool(args.dry_run),
        )
        if args.dry_run:
            print(
                f'DRYRUN: would install the persistent host replay service for VM {cfg.vm.name}'
            )
        else:
            print(
                f'Installed and enabled the persistent host replay service for VM {cfg.vm.name}'
            )
        return 0
