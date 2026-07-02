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

def shared_root_host_dir(cfg: AgentVMConfig) -> Path:
    """Host-side export directory backing shared-root attachments for this VM.

    This is a pure path computation from config, not a libvirt query. It is
    the single source of truth for the shared-root layout used by drift
    detection, attachment reconciliation, and VM creation.
    """
    return Path(cfg.paths.base_dir) / cfg.vm.name / 'shared-root'

def persistent_root_host_dir(cfg: AgentVMConfig) -> Path:
    """Host-side export directory backing persistent attachments for this VM.

    See :func:`shared_root_host_dir`; this is the persistent-mode analogue.
    """
    return Path(cfg.paths.base_dir) / cfg.vm.name / 'persistent-root'
