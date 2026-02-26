"""Compatibility facade for VM operations.

Implementation is split across focused modules:
- vm_lifecycle: image/bootstrap/lifecycle/ssh readiness/provisioning
- vm_share: virtiofs share discovery/attach/mount
- vm_sync: host settings synchronization into guest
"""

from __future__ import annotations

from .vm_lifecycle import (  # noqa: F401
    _ensure_disk,
    _ensure_qemu_access,
    _mac_for_vm,
    _paths,
    _sudo_file_exists,
    _sudo_path_exists,
    _write_cloud_init,
    create_or_start_vm,
    destroy_vm,
    fetch_image,
    get_ip_cached,
    provision,
    ssh_config,
    vm_exists,
    vm_status,
    wait_for_ip,
    wait_for_ssh,
)
from .vm_share import (  # noqa: F401
    attach_vm_share,
    ensure_share_mounted,
    vm_has_share,
    vm_share_mappings,
)
from .vm_sync import sync_settings  # noqa: F401

__all__ = [
    "_ensure_disk",
    "_ensure_qemu_access",
    "_mac_for_vm",
    "_paths",
    "_sudo_file_exists",
    "_sudo_path_exists",
    "_write_cloud_init",
    "attach_vm_share",
    "create_or_start_vm",
    "destroy_vm",
    "ensure_share_mounted",
    "fetch_image",
    "get_ip_cached",
    "provision",
    "ssh_config",
    "sync_settings",
    "vm_exists",
    "vm_has_share",
    "vm_share_mappings",
    "vm_status",
    "wait_for_ip",
    "wait_for_ssh",
]
