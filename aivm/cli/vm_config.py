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


class VMConfigPathCLI(_BaseCommand):
    """Show the physical config source for a managed VM."""

    vm: Any = scfg.Value('', help='VM name override.', position=1)

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg_path = _cfg_path(args.config)
        loaded = load_config_document(cfg_path)
        vm_name = str(args.vm or '').strip() or loaded.store.active_vm
        if not vm_name:
            raise RuntimeError('No VM specified and active_vm is unset.')
        src = loaded.vm_sources.get(vm_name)
        if src is None:
            rec_names = sorted(v.name for v in loaded.store.vms)
            if vm_name not in rec_names:
                raise RuntimeError(f'VM not found in config: {vm_name}')
            # Monolithic configs may not have per-source VM metadata when the
            # file was missing and defaulted.  Fall back to the root path.
            src = cfg_path
        print(src)
        return 0


class VMEditCLI(_BaseCommand):
    """Edit the active or named VM config fragment in $EDITOR."""

    vm: Any = scfg.Value('', help='VM name override.', position=1)
    editor: Any = scfg.Value(
        '',
        help='Editor command override (default: $EDITOR/$VISUAL, then nano/vi).',
    )
    visual: Any = scfg.Value(
        '',
        help='If true, then prefer $VISUAL over $EDITOR.',
        isflag=True,
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _resolve_config_edit_target(
            config_opt=args.config,
            target='vm',
            name=str(args.vm or ''),
        )
        _edit_path(path, args)
        return 0
