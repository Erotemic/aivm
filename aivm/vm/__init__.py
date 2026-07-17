"""VM operation exports for lifecycle and share helpers.

Public surface re-exported below is intentionally limited to the names
imported by callers outside this subpackage. Private helpers (leading
underscore) live in the submodules that own them and should be imported
directly from those submodules (e.g. ``aivm.vm.host_access``,
``aivm.vm.cloudinit``).
"""

from __future__ import annotations

from . import drift
from .lifecycle import (
    create_or_start_vm,
    destroy_vm,
    fetch_image,
    get_ip_cached,
    provision,
    refresh_cloud_init_seed_for_next_boot,
    restart_vm,
    shutdown_vm,
    ssh_config,
    vm_exists,
    vm_status,
    wait_for_ip,
    wait_for_ssh,
)
from .share import (
    SHARED_ROOT_VIRTIOFS_TAG,
    AttachmentAccess,
    AttachmentMode,
    ResolvedAttachment,
    attach_vm_share,
    detach_vm_share,
    ensure_share_mounted,
    vm_has_share,
    vm_has_virtiofs_shared_memory,
    vm_share_mappings,
    vm_share_mappings_detailed,
)

__all__ = [
    'AttachmentAccess',
    'AttachmentMode',
    'ResolvedAttachment',
    'SHARED_ROOT_VIRTIOFS_TAG',
    'attach_vm_share',
    'create_or_start_vm',
    'destroy_vm',
    'detach_vm_share',
    'drift',
    'ensure_share_mounted',
    'fetch_image',
    'get_ip_cached',
    'provision',
    'refresh_cloud_init_seed_for_next_boot',
    'restart_vm',
    'shutdown_vm',
    'ssh_config',
    'vm_exists',
    'vm_has_share',
    'vm_has_virtiofs_shared_memory',
    'vm_share_mappings',
    'vm_share_mappings_detailed',
    'vm_status',
    'wait_for_ip',
    'wait_for_ssh',
]
