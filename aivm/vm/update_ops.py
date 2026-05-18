"""Compatibility facade for VM update helpers.

The implementation now lives under :mod:`aivm.vm.update`:

- ``models`` for drift/restart dataclasses and enums
- ``detect`` for desired-vs-libvirt drift detection
- ``render`` for plan printing
- ``apply`` for applying drift
- ``restart`` for post-update restart decisions
- ``virtiofs`` for virtiofs XML cleanup

This module intentionally re-exports the historical private helper names while
callers migrate to the focused modules.
"""

from __future__ import annotations

from .update.apply import _apply_vm_update
from .update.detect import (
    _qemu_img_virtual_size_bytes,
    _resolve_vm_disk_path,
    _virsh_domblk_capacity_bytes,
    _vm_update_drift,
)
from .update.models import (
    RestartKind,
    VirtiofsBinaryDrift,
    VMUpdateDrift,
    _escalate,
)
from .update.render import _print_vm_update_plan
from .update.restart import _maybe_restart_vm_after_update
from .update.util import (
    _bytes_to_gib,
    _parse_domblkinfo_capacity,
    _parse_qemu_img_virtual_size,
    _parse_vm_disk_path_from_dumpxml,
    _parse_vm_network_from_dumpxml,
)
from .update.virtiofs import _apply_virtiofs_binary_drift, _virtiofs_binary_drift

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
