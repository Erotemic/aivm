"""Canonical runtime configuration boundaries for shared-machine AIVM.

Persistence adapters resolve one :class:`ResolvedVMContext` so ordinary
runtime code consumes machine state, one access identity, one user profile,
and an effective aggregate config without knowing which on-disk generation
produced them.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .attachment_schema import MIRROR_HOME_AUTO
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
    """Machine-global desired state for one effective VM."""

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
    state: str = 'active'


@dataclass(frozen=True)
class UserProfile:
    """Caller-owned interaction and SSH state."""

    active_vm: str
    behavior: BehaviorConfig
    ssh_identity_file: str
    ssh_pubkey_path: str
    state_dir: str
    mirror_shared_home_folders: str = MIRROR_HOME_AUTO


@dataclass(frozen=True)
class GuestTransportContext:
    """Narrow SSH/guest addressing data needed by runtime helpers.

    This deliberately carries no principal id, ownership, or authorization
    state. Canonical runtime helpers that only need to reach the guest should
    not fabricate a legacy :class:`ResolvedVMContext`.
    """

    guest_user: str
    ssh_identity_file: str
    ssh_pubkey_path: str
    state_dir: str

    @property
    def guest_home(self) -> PurePosixPath:
        return PurePosixPath('/home') / self.guest_user

    def ssh_target(self, host: str) -> str:
        return f'{self.guest_user}@{host}'


def guest_transport_from_effective_cfg(
    cfg: AgentVMConfig,
) -> GuestTransportContext:
    """Extract transport-only guest data from an effective runtime config."""
    return GuestTransportContext(
        guest_user=cfg.vm.user,
        ssh_identity_file=cfg.paths.ssh_identity_file,
        ssh_pubkey_path=cfg.paths.ssh_pubkey_path,
        state_dir=cfg.paths.state_dir,
    )


@dataclass(frozen=True)
class ResolvedVMContext:
    """Machine, principal, and profile selected for one VM operation."""

    machine: MachineConfig
    principal: VMPrincipal
    profile: UserProfile
    # Effective aggregate config used by runtime code that still consumes the
    # historical AgentVMConfig shape. It is excluded from equality because
    # caller-owned profile fields do not redefine machine identity.
    effective_cfg: AgentVMConfig = field(repr=False, compare=False)

    @property
    def guest_user(self) -> str:
        return self.principal.guest_user

    @property
    def guest_home(self) -> PurePosixPath:
        return PurePosixPath('/home') / self.guest_user

    def ssh_target(self, host: str) -> str:
        return f'{self.guest_user}@{host}'


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
        mirror_shared_home_folders=profile_store.mirror_shared_home_folders,
    )
    return ResolvedVMContext(
        machine=machine_config_from_effective(cfg),
        principal=principal,
        profile=profile,
        effective_cfg=cfg,
    )
