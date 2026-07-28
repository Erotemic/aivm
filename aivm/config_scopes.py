"""Runtime configuration boundaries for the shared-machine architecture.

The released on-disk schema still stores machine settings, the original guest
login, and caller-owned SSH paths in one :class:`AgentVMConfig`.  Version 0.6
starts separating those concepts in runtime code before changing persistence.
This module is the compatibility seam: callers resolve one
:class:`ResolvedVMContext` and stop treating ``vm.user`` as a machine field.

The types intentionally snapshot the legacy config instead of mutating it.
Later work can populate the same context from a machine-global store plus a
per-user profile without another application-wide SSH/guest refactor.
"""

from __future__ import annotations

import getpass
import os
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .config import (
    AgentVMConfig,
    BehaviorConfig,
    FirewallConfig,
    ImageConfig,
    NetworkConfig,
    ProvisionConfig,
    ToolsConfig,
    VirtiofsConfig,
)
from .config_store.models import PrincipalEntry
from .profile_store import UserProfileStore


@dataclass(frozen=True)
class MachineVMConfig:
    """Machine-owned VM settings, excluding creator/principal identity."""

    name: str
    cpus: int
    ram_mb: int
    disk_gb: int
    timezone: str
    mirror_shared_home_folders: bool


@dataclass(frozen=True)
class MachineConfig:
    """Machine-global desired state represented by the legacy schema."""

    vm: MachineVMConfig
    network: NetworkConfig
    firewall: FirewallConfig
    image: ImageConfig
    provision: ProvisionConfig
    tools: ToolsConfig
    virtiofs: VirtiofsConfig
    base_dir: str


@dataclass(frozen=True)
class VMPrincipal:
    """Identity used by one host user inside a shared VM."""

    id: str
    host_user: str
    host_uid: int
    host_gid: int
    guest_user: str
    ssh_public_key: str = ''
    state: str = 'legacy'


@dataclass(frozen=True)
class UserProfile:
    """Caller-owned interaction and SSH state."""

    active_vm: str
    behavior: BehaviorConfig
    ssh_identity_file: str
    ssh_pubkey_path: str
    state_dir: str


@dataclass(frozen=True)
class ResolvedVMContext:
    """Machine, principal, and profile selected for one VM operation."""

    machine: MachineConfig
    principal: VMPrincipal
    profile: UserProfile
    # Transitional escape hatch for machine operations not migrated yet.  It is
    # excluded from equality so caller-specific legacy fields cannot make two
    # views of the same machine compare unequal.
    legacy_cfg: AgentVMConfig = field(repr=False, compare=False)

    @property
    def guest_user(self) -> str:
        return self.principal.guest_user

    @property
    def guest_home(self) -> PurePosixPath:
        return PurePosixPath('/home') / self.guest_user

    def ssh_target(self, host: str) -> str:
        return f'{self.guest_user}@{host}'


def _host_uid() -> int:
    getter = getattr(os, 'getuid', None)
    return int(getter()) if getter is not None else -1


def _host_gid() -> int:
    getter = getattr(os, 'getgid', None)
    return int(getter()) if getter is not None else -1


def machine_config_from_effective(cfg: AgentVMConfig) -> MachineConfig:
    """Snapshot only the machine-owned portion of an effective config."""
    return MachineConfig(
        vm=MachineVMConfig(
            name=cfg.vm.name,
            cpus=cfg.vm.cpus,
            ram_mb=cfg.vm.ram_mb,
            disk_gb=cfg.vm.disk_gb,
            timezone=cfg.vm.timezone,
            mirror_shared_home_folders=cfg.vm.mirror_shared_home_folders,
        ),
        network=deepcopy(cfg.network),
        firewall=deepcopy(cfg.firewall),
        image=deepcopy(cfg.image),
        provision=deepcopy(cfg.provision),
        tools=deepcopy(cfg.tools),
        virtiofs=deepcopy(cfg.virtiofs),
        base_dir=cfg.paths.base_dir,
    )


def resolve_persisted_vm_context(
    cfg: AgentVMConfig,
    *,
    principal_entry: PrincipalEntry,
    profile_store: UserProfileStore,
) -> ResolvedVMContext:
    """Build runtime context from machine state plus the caller's profile."""
    principal = VMPrincipal(
        id=principal_entry.id,
        host_user=principal_entry.host_user,
        host_uid=principal_entry.host_uid,
        host_gid=principal_entry.host_gid,
        guest_user=principal_entry.guest_user,
        ssh_public_key=principal_entry.ssh_public_key,
        state=principal_entry.state,
    )
    profile = UserProfile(
        active_vm=profile_store.active_vm,
        behavior=deepcopy(profile_store.behavior),
        ssh_identity_file=profile_store.ssh_identity_file,
        ssh_pubkey_path=profile_store.ssh_pubkey_path,
        state_dir=profile_store.state_dir,
    )
    return ResolvedVMContext(
        machine=machine_config_from_effective(cfg),
        principal=principal,
        profile=profile,
        legacy_cfg=cfg,
    )


def resolve_legacy_vm_context(
    cfg: AgentVMConfig,
    *,
    host_user: str | None = None,
    host_uid: int | None = None,
    host_gid: int | None = None,
) -> ResolvedVMContext:
    """Translate one legacy config into the new runtime scope model.

    This is intentionally serialization-neutral.  ``cfg.vm.user`` becomes a
    synthetic compatibility principal and the caller-owned paths become a
    synthetic profile.  The machine snapshot excludes those values, proving
    that two users may select different principals without redefining the VM.
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
    )
    behavior = BehaviorConfig(verbose=cfg.verbosity)
    profile = UserProfile(
        active_vm=cfg.vm.name,
        behavior=behavior,
        ssh_identity_file=cfg.paths.ssh_identity_file,
        ssh_pubkey_path=cfg.paths.ssh_pubkey_path,
        state_dir=cfg.paths.state_dir,
    )
    return ResolvedVMContext(
        machine=machine,
        principal=principal,
        profile=profile,
        legacy_cfg=cfg,
    )
