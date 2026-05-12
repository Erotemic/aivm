"""Filesystem path helpers for VM lifecycle operations."""

from __future__ import annotations

from pathlib import Path

from ..config import AgentVMConfig

def _paths(cfg: AgentVMConfig, *, dry_run: bool = False) -> dict[str, Path]:
    cfg = cfg.expanded_paths()
    base_dir = Path(cfg.paths.base_dir) / cfg.vm.name
    img_dir = base_dir / 'images'
    ci_dir = base_dir / 'cloud-init'
    state_dir = Path(cfg.paths.state_dir) / cfg.vm.name
    return {
        'base_dir': base_dir,
        'img_dir': img_dir,
        'ci_dir': ci_dir,
        'state_dir': state_dir,
        'ip_file': state_dir / f'{cfg.vm.name}.ip',
        'known_hosts': state_dir / 'known_hosts',
    }
