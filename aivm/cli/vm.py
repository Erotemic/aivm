"""CLI commands for VM lifecycle, attach/code/ssh workflows, and provision."""

from __future__ import annotations

import os
import shlex
import socket
from pathlib import Path
from typing import Any

import scriptconfig as scfg

from ..attachments.guest import (
    _ensure_attachment_available_in_guest,
    _upsert_ssh_config_entry,
)
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
)
from ..attachments.session import (
    _maybe_warn_hardware_drift,
    _prepare_attached_session,
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
from ..runtime import require_ssh_identity, ssh_base_args
from ..status import (
    probe_vm_state,
)
from ..store import (
    find_attachment_for_vm,
    find_network,
    load_config_document,
    load_store,
    network_users,
    remove_attachment,
    remove_vm,
    save_store,
)
from ..util import which
from ..vm import (
    attach_vm_share,
    create_or_start_vm,
    destroy_vm,
    detach_vm_share,
    provision,
    refresh_cloud_init_seed_for_next_boot,
    restart_vm,
    shutdown_vm,
    vm_share_mappings,
    vm_status,
    wait_for_ip,
)
from ..vm import (
    ssh_config as mk_ssh_config,
)
from ..vm.create_ops import (
    create_vm_from_defaults,
)
from ..vm.drift import (
    attachment_has_mapping as drift_attachment_has_mapping,
)
from ..vm.share import (
    ResolvedAttachment,
)
from ..vm.share import (
    align_attachment_tag_with_mappings as drift_align_attachment_tag_with_mappings,
)
from ..vm.update_ops import (
    RestartKind,
    _apply_vm_update,
    _maybe_restart_vm_after_update,
    _print_vm_update_plan,
    _vm_update_drift,
)
from ._common import (
    _BaseCommand,
    _cfg_path,
    _load_cfg,
    _load_cfg_with_path,
    _maybe_install_missing_host_deps,
    _maybe_offer_create_ssh_identity,
    _record_vm,
    _resolve_cfg_for_code,
    log,
)
from .config import _edit_path, _resolve_config_edit_target

from .vm_lifecycle import (
    VMCreateCLI,
    VMDownCLI,
    VMDestroyCLI,
    VMListCLI,
    VMProvisionCLI,
    VMRestartCLI,
    VMStatusCLI,
    VMUpCLI,
)
from .vm_connect import (
    VMCodeCLI,
    VMSSHCLI,
    VMSshConfigCLI,
    VMWaitIPCLI,
    _print_remote_session_recipe,
    _remote_tunnel_name,
    _vscode_can_open_locally,
)
from .vm_attach import (
    VMAttachCLI,
    VMDetachCLI,
    VMInstallPersistentHostReplayServiceCLI,
    VMPersistentHostReplayCLI,
)
from .vm_config import VMConfigPathCLI, VMEditCLI
from .vm_update import VMUpdateCLI


class VMModalCLI(scfg.ModalCLI):
    """VM lifecycle subcommands."""

    list = VMListCLI
    create = VMCreateCLI
    up = VMUpCLI
    down = VMDownCLI
    restart = VMRestartCLI
    wait_ip = VMWaitIPCLI
    status = VMStatusCLI
    update = VMUpdateCLI
    config_path = VMConfigPathCLI
    edit = VMEditCLI
    destroy = VMDestroyCLI
    ssh_config = VMSshConfigCLI
    provision = VMProvisionCLI
    ssh = VMSSHCLI
    attach = VMAttachCLI
    detach = VMDetachCLI
    persistent_host_replay = VMPersistentHostReplayCLI
    install_persistent_host_replay_service = (
        VMInstallPersistentHostReplayServiceCLI
    )
    code = VMCodeCLI

__all__ = [
    'VMModalCLI',
    'VMUpCLI',
    'VMDownCLI',
    'VMRestartCLI',
    'VMCreateCLI',
    'VMWaitIPCLI',
    'VMStatusCLI',
    'VMDestroyCLI',
    'VMSshConfigCLI',
    'VMProvisionCLI',
    'VMCodeCLI',
    'VMSSHCLI',
    'VMAttachCLI',
    'VMDetachCLI',
    'VMPersistentHostReplayCLI',
    'VMInstallPersistentHostReplayServiceCLI',
    'VMListCLI',
    'VMConfigPathCLI',
    'VMEditCLI',
    'VMUpdateCLI',
    '_vscode_can_open_locally',
    '_remote_tunnel_name',
    '_print_remote_session_recipe',
]
