"""VM update package.

This package keeps drift detection, plan rendering, apply logic, and restart
handling separate so future runtime/backend work can modify one concern at a
time.
"""

from .apply import _apply_vm_update
from .detect import (
    _qemu_img_virtual_size_bytes,
    _resolve_vm_disk_path,
    _virsh_domblk_capacity_bytes,
    _vm_update_drift,
)
from .models import (
    RestartKind,
    VirtiofsBinaryDrift,
    VMUpdateDrift,
    _escalate,
)
from .render import _print_vm_update_plan
from .restart import _maybe_restart_vm_after_update
from .util import (
    _bytes_to_gib,
    _parse_domblkinfo_capacity,
    _parse_qemu_img_virtual_size,
    _parse_vm_disk_path_from_dumpxml,
    _parse_vm_network_from_dumpxml,
)
from .virtiofs import _apply_virtiofs_binary_drift, _virtiofs_binary_drift

__all__ = [
    'RestartKind',
    'VirtiofsBinaryDrift',
    'VMUpdateDrift',
    '_apply_virtiofs_binary_drift',
    '_apply_vm_update',
    '_bytes_to_gib',
    '_escalate',
    '_maybe_restart_vm_after_update',
    '_parse_domblkinfo_capacity',
    '_parse_qemu_img_virtual_size',
    '_parse_vm_disk_path_from_dumpxml',
    '_parse_vm_network_from_dumpxml',
    '_print_vm_update_plan',
    '_qemu_img_virtual_size_bytes',
    '_resolve_vm_disk_path',
    '_virsh_domblk_capacity_bytes',
    '_virtiofs_binary_drift',
    '_vm_update_drift',
]
