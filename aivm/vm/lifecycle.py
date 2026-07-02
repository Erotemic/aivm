"""Compatibility facade for VM lifecycle primitives.

The implementation is split across focused modules under :mod:`aivm.vm`.
This module intentionally re-exports the historical lifecycle symbols so
existing callers can migrate incrementally while imports remain stable.
"""

from __future__ import annotations

# Compatibility imports for callers/tests that referenced these names through
# ``aivm.vm.lifecycle`` before the lifecycle refactor.
import shlex
import textwrap
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

from loguru import logger

from ..commands import CommandManager
from ..config import (
    DEFAULT_UBUNTU_NOBLE_IMG_URL,
    SUPPORTED_IMAGE_SHA256,
    AgentVMConfig,
)
from ..persistent_replay import (
    PERSISTENT_ATTACHMENT_REPLAY_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    persistent_replay_python,
    persistent_replay_service_unit,
)
from ..runtime import require_ssh_identity, ssh_base_args
from ..util import CmdError, ensure_dir
from . import cloudinit as _cloudinit
from .cloudinit import (
    _cloud_init_instance_id,
    _cloud_init_instance_id_token_path,
    _write_cloud_init,
    refresh_cloud_init_seed_for_next_boot,
)
from .connectivity import (
    _is_ssh_host_key_mismatch,
    _mac_for_vm,
    _ssh_host_key_mismatch_message,
    get_ip_cached,
    ssh_config,
    ssh_port_for,
    wait_for_ip,
    wait_for_ssh,
)
from .create import (
    _failed_command_name,
    _is_guest_memory_allocation_error,
    _is_missing_command_error,
    _is_missing_uefi_firmware_error,
    _is_missing_virtiofsd_error,
    _memory_allocation_failure_message,
    _virtiofsd_failure_message,
    create_or_start_vm,
)
from .disk import _ensure_disk
from .domain import (
    _destroy_and_undefine_vm,
    _get_vm_state,
    _is_vm_active,
    _start_vm,
    _vm_defined,
    _wait_for_vm_not_state,
    _wait_for_vm_state,
    destroy_vm,
    restart_vm,
    shutdown_vm,
    vm_exists,
    vm_status,
)
from .guest_tools import (
    _guest_ensure_code_script,
    _guest_ensure_rust_script,
    _guest_ensure_uv_script,
    _guest_tool_code_enabled,
    _guest_tool_code_spec,
    _guest_tool_enabled,
    _guest_tool_rust_enabled,
    _guest_tool_rust_spec,
    _guest_tool_spec,
    _guest_tool_uv_enabled,
    _guest_tool_uv_spec,
    _uv_installer_url,
)
from .host_access import (
    _ensure_qemu_access,
    _sudo_file_exists,
    _sudo_path_exists,
    _submit_qemu_dir_prepare,
)
from .images import (
    _resolve_expected_image_sha256,
    _verify_image_sha256,
    fetch_image,
)
from .paths import _paths
from .provision import provision

log = logger

def detect_host_timezone() -> str:
    """Return the host timezone via the cloud-init module compatibility path.

    Historically tests and callers imported this helper from
    ``aivm.vm.lifecycle`` even though cloud-init generation owns the fallback
    behavior.  Delegate dynamically so monkeypatching
    ``aivm.vm.cloudinit.detect_host_timezone`` still affects the lifecycle
    compatibility facade.
    """
    return _cloudinit.detect_host_timezone()


__all__ = [
    'AgentVMConfig',
    'CmdError',
    'CommandManager',
    'DEFAULT_UBUNTU_NOBLE_IMG_URL',
    'SUPPORTED_IMAGE_SHA256',
    'create_or_start_vm',
    'destroy_vm',
    'detect_host_timezone',
    'fetch_image',
    'get_ip_cached',
    'ssh_port_for',
    'provision',
    'refresh_cloud_init_seed_for_next_boot',
    'restart_vm',
    'shutdown_vm',
    'ssh_config',
    'vm_exists',
    'vm_status',
    'wait_for_ip',
    'wait_for_ssh',
    '_cloud_init_instance_id',
    '_cloud_init_instance_id_token_path',
    '_destroy_and_undefine_vm',
    '_ensure_disk',
    '_ensure_qemu_access',
    '_failed_command_name',
    '_get_vm_state',
    '_guest_ensure_code_script',
    '_guest_ensure_rust_script',
    '_guest_ensure_uv_script',
    '_guest_tool_code_enabled',
    '_guest_tool_code_spec',
    '_guest_tool_enabled',
    '_guest_tool_rust_enabled',
    '_guest_tool_rust_spec',
    '_guest_tool_spec',
    '_guest_tool_uv_enabled',
    '_guest_tool_uv_spec',
    '_is_guest_memory_allocation_error',
    '_is_missing_command_error',
    '_is_missing_uefi_firmware_error',
    '_is_missing_virtiofsd_error',
    '_is_ssh_host_key_mismatch',
    '_is_vm_active',
    '_mac_for_vm',
    '_memory_allocation_failure_message',
    '_paths',
    '_resolve_expected_image_sha256',
    '_ssh_host_key_mismatch_message',
    '_start_vm',
    '_sudo_file_exists',
    '_sudo_path_exists',
    '_submit_qemu_dir_prepare',
    '_uv_installer_url',
    '_verify_image_sha256',
    '_virtiofsd_failure_message',
    '_vm_defined',
    '_wait_for_vm_not_state',
    '_wait_for_vm_state',
    '_write_cloud_init',
]
