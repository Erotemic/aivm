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


class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate: Any = scfg.Value(
        False, isflag=True, help='Destroy and recreate if it exists.'
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        _maybe_install_missing_host_deps(
            yes=bool(args.yes), dry_run=bool(args.dry_run)
        )
        mgr = CommandManager.current()
        with mgr.intent(
            f'Create/start VM {cfg.vm.name}',
            why='Ensure the managed VM exists and is running with the configured resources.',
            role='modify',
        ):
            create_or_start_vm(
                cfg, dry_run=args.dry_run, recreate=args.recreate
            )
        if not args.dry_run and not args.recreate:
            _maybe_warn_hardware_drift(cfg)
        if not args.dry_run:
            _sync_persistent_attachment_manifest_on_host(
                cfg,
                cfg_path,
                dry_run=False,
            )
            _reconcile_persistent_host_binds(
                cfg,
                cfg_path,
                dry_run=False,
                vm_running=True,
            )
            _record_vm(cfg, cfg_path)
        return 0


class VMDownCLI(_BaseCommand):
    """Gracefully shut down the VM."""

    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Shut down VM {cfg.vm.name}',
            why='Gracefully stop the VM by sending an ACPI shutdown signal to the guest OS.',
            role='modify',
        ):
            shutdown_vm(cfg, dry_run=args.dry_run)
        return 0


class VMRestartCLI(_BaseCommand):
    """Gracefully restart the VM (shutdown then start)."""

    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Restart VM {cfg.vm.name}',
            why='Gracefully stop and then start the VM to apply changes or recover from transient issues.',
            role='modify',
        ):
            restart_vm(cfg, dry_run=args.dry_run)
        return 0


class VMCreateCLI(_BaseCommand):
    """Create a managed VM from config-store defaults and start it."""

    vm: Any = scfg.Value('', help='Optional VM name override.')
    set_default: Any = scfg.Value(
        False,
        isflag=True,
        help='Set the created VM as the active default VM.',
    )
    force: Any = scfg.Value(
        False,
        isflag=True,
        help='Overwrite existing VM entry and recreate VM definition if present.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMCreateCLI.main vm={} set_default={} force={} dry_run={} yes={}',
            args.vm,
            bool(args.set_default),
            bool(args.force),
            bool(args.dry_run),
            bool(args.yes),
        )
        cfg_path = _cfg_path(args.config)
        return create_vm_from_defaults(
            cfg_path,
            vm_override=args.vm if args.vm else None,
            set_default=bool(args.set_default),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )


class VMStatusCLI(_BaseCommand):
    """Show VM lifecycle status and cached IP information."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Inspect VM {cfg.vm.name}',
            why='Read the live libvirt state and cached IP for this managed VM.',
            role='read',
        ):
            print(vm_status(cfg))
        return 0


class VMDestroyCLI(_BaseCommand):
    """Destroy and undefine the VM (shared host directories are not deleted)."""

    vm: Any = scfg.Value(
        '',
        position=1,
        help='Optional VM name override (positional).',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config, vm_opt=args.vm)
        mgr = CommandManager.current()
        with mgr.intent(
            f'Destroy VM {cfg.vm.name}',
            why=(
                'Remove the managed VM domain while leaving host project directories intact.'
            ),
            role='modify',
        ):
            destroy_vm(cfg, dry_run=args.dry_run)
        if not args.dry_run:
            reg = load_store(cfg_path)
            remove_vm(reg, cfg.vm.name, remove_attachments=True)
            save_store(
                reg,
                cfg_path,
                reason=(
                    f'Remove VM record for {cfg.vm.name} after destroying the '
                    'managed libvirt domain.'
                ),
            )
            net_name = (cfg.network.name or '').strip()
            if net_name:
                net = find_network(reg, net_name)
                if net is not None and not network_users(reg, net_name):
                    log.warning(
                        "Network '{}' now has no VM users and remains defined. "
                        'Destroy it explicitly if no longer needed: aivm host net destroy {}',
                        net_name,
                        net_name,
                    )
        return 0


class VMProvisionCLI(_BaseCommand):
    """Provision the VM with optional developer packages."""

    vm: Any = scfg.Value(
        '',
        help='Optional VM name override.',
    )
    dry_run: Any = scfg.Value(
        False, isflag=True, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.config is not None or _cfg_path(None).exists():
            cfg = _load_cfg(args.config)
        else:
            cfg, _ = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt=args.vm,
                host_src=Path.cwd(),
            )
        if not args.dry_run:
            _resolve_ip_for_ssh_ops(
                cfg,
                yes=bool(args.yes),
                purpose='Query VM networking state before SSH provisioning.',
            )
        provision(cfg, dry_run=args.dry_run)
        return 0


class VMListCLI(_BaseCommand):
    """List managed VM records (VM-focused view)."""

    section = scfg.Value(
        'vms',
        help='One of: all, vms, networks, folders (default: vms).',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        from .main import ListCLI

        return ListCLI.main(
            argv=False, section=args.section, config=args.config
        )
