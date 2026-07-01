"""Plan rendering for VM update operations."""

from __future__ import annotations

from ...config import AgentVMConfig
from .models import VMUpdateDrift
from .util import _bytes_to_gib


def _print_vm_update_plan(cfg: AgentVMConfig, drift: VMUpdateDrift) -> None:
    print(f'Planned VM update for {cfg.vm.name}:')
    if drift.cpus is not None:
        cur, want = drift.cpus
        print(f'  - cpus: {cur} -> {want}')
    if drift.ram_mb is not None:
        cur, want = drift.ram_mb
        print(f'  - ram_mb: {cur} -> {want}')
    if drift.disk_bytes is not None:
        cur, want = drift.disk_bytes
        print(
            f'  - disk_gb: {_bytes_to_gib(cur):.2f} GiB -> {_bytes_to_gib(want):.2f} GiB ({drift.disk_path})'
        )
    if drift.virtiofs_binary:
        mode_label = drift.virtiofsd_mode or 'disabled'
        print(
            f'  - virtiofsd binary path (inode-file-handles={mode_label}): '
            f'{len(drift.virtiofs_binary)} <filesystem> device(s) to update'
        )
        for d in drift.virtiofs_binary:
            cur_path = d.current or '(default)'
            new_path = d.desired or '(default)'
            print(f'      tag={d.tag}: {cur_path} -> {new_path}')
