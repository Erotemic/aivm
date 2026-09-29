"""Runtime adapter for one released pre-0.6 per-user VM config."""

from __future__ import annotations

import getpass
import os

from ...attachment_schema import MIRROR_HOME_AUTO
from ...config import AgentVMConfig, BehaviorConfig
from ...config_scopes import (
    ResolvedVMContext,
    UserProfile,
    VMPrincipal,
    machine_config_from_effective,
)


def _host_uid() -> int:
    getter = getattr(os, 'getuid', None)
    return int(getter()) if getter is not None else -1


def _host_gid() -> int:
    getter = getattr(os, 'getgid', None)
    return int(getter()) if getter is not None else -1


def resolve_pre_0_6_0_vm_context(
    cfg: AgentVMConfig,
    *,
    host_user: str | None = None,
    host_uid: int | None = None,
    host_gid: int | None = None,
) -> ResolvedVMContext:
    """Translate a released aggregate config into the 0.6 runtime model.

    ``cfg.vm.user`` becomes a synthetic access identity and caller-owned paths
    become a synthetic profile.  This adapter is the only supported bridge
    from a pre-0.6 aggregate config to :class:`ResolvedVMContext`.
    """
    resolved_host_user = host_user or getpass.getuser()
    resolved_uid = _host_uid() if host_uid is None else int(host_uid)
    resolved_gid = _host_gid() if host_gid is None else int(host_gid)

    machine = machine_config_from_effective(cfg)
    principal = VMPrincipal(
        id=f'legacy:{cfg.vm.name}:{resolved_host_user}',
        host_user=resolved_host_user,
        host_uid=resolved_uid,
        host_gid=resolved_gid,
        guest_user=cfg.vm.user,
        state='legacy',
    )
    profile = UserProfile(
        active_vm=cfg.vm.name,
        behavior=BehaviorConfig(verbose=cfg.verbosity),
        ssh_identity_file=cfg.paths.ssh_identity_file,
        ssh_pubkey_path=cfg.paths.ssh_pubkey_path,
        state_dir=cfg.paths.state_dir,
        mirror_shared_home_folders=MIRROR_HOME_AUTO,
        credential_backend='auto',
    )
    return ResolvedVMContext(
        machine=machine,
        principal=principal,
        profile=profile,
        effective_cfg=cfg,
    )
