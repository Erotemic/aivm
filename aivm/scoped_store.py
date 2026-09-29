"""Routing and materialization for machine-global plus per-user state.

AIVM 0.6 supports two persistence modes during migration:

* ``legacy``: the released per-user :class:`aivm.config_store.Store`;
* ``machine``: one host-wide machine store plus one private user profile.

Explicit ``--config`` paths always select legacy semantics. Implicit commands
prefer an existing machine store, fall back to an existing legacy store, and
choose the machine store for a brand-new installation.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from .config import AgentVMConfig
from .config_scopes import (
    ResolvedVMContext,
    resolve_persisted_vm_context,
)
from .config_store import (
    PrincipalEntry,
    Store,
    find_principal_for_host_identity,
    load_store,
    materialize_vm_cfg,
    save_store_split,
    split_source_paths,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from .errors import AIVMError
from .host_identity import HostIdentity, current_host_identity
from .legacy.pre_0_6_0 import compatibility_surface
from .legacy.pre_0_6_0.selection import selected_store_path
from .machine_store import (
    MachineStoreAccessError,
    MachineStoreLayout,
    current_machine_group_gid,
    current_machine_group_name,
    current_machine_store_policy,
    ensure_machine_store_layout,
    machine_store_layout,
)
from .profile_store import (
    UserProfileStore,
    load_user_profile,
    profile_store_path,
    save_user_profile,
)


@dataclass(frozen=True)
class StoreScope:
    """Physical stores selected for one command invocation."""

    mode: str
    store_path: Path
    profile_path: Path | None = None
    machine_layout: MachineStoreLayout | None = None

    @property
    def is_machine(self) -> bool:
        return self.mode == 'machine'


@compatibility_surface
def resolve_store_scope(
    config_opt: str | None,
    *,
    for_init: bool = False,
) -> StoreScope:
    """Choose legacy or machine persistence without silently migrating data."""
    layout = machine_store_layout()
    legacy_path = selected_store_path(
        config_opt,
        machine_store_path=layout.config_path,
    )
    if config_opt and legacy_path is not None:
        return StoreScope(mode='legacy', store_path=legacy_path)
    if config_opt:
        return StoreScope(
            mode='machine',
            store_path=layout.config_path,
            profile_path=profile_store_path(),
            machine_layout=layout,
        )

    machine_exists = bool(split_source_paths(layout.config_path))
    if machine_exists:
        return StoreScope(
            mode='machine',
            store_path=layout.config_path,
            profile_path=profile_store_path(),
            machine_layout=layout,
        )
    if legacy_path is not None:
        return StoreScope(mode='legacy', store_path=legacy_path)

    # A brand-new implicit install starts in the new architecture. ``for_init``
    # documents caller intent but deliberately does not alter the selection.
    del for_init
    return StoreScope(
        mode='machine',
        store_path=layout.config_path,
        profile_path=profile_store_path(),
        machine_layout=layout,
    )


def ensure_machine_scope_ready(scope: StoreScope) -> None:
    """Create the configured machine layout or raise actionable diagnostics."""
    if not scope.is_machine:
        return
    assert scope.machine_layout is not None
    try:
        ensure_machine_store_layout(
            scope.machine_layout,
            group_gid=current_machine_group_gid(scope.machine_layout),
        )
    except MachineStoreAccessError:
        # Already the precise, actionable diagnosis. Re-wrapping it would bury
        # the reason under a generic "could not initialize" preamble.
        raise
    except Exception as ex:
        root = scope.machine_layout.root
        if not scope.machine_layout.shared:
            raise AIVMError(
                f'Could not initialize your AIVM machine store at {root}: '
                f'{ex}\n'
                'This store is owned by you alone and needs no group or '
                'privileged step, so this is an ordinary filesystem problem '
                '-- check that the path is writable and is not a symlink.'
            ) from ex
        group = current_machine_group_name()
        raise AIVMError(
            f'Could not initialize the shared AIVM machine store at {root}: {ex}\n'
            f'The store is owned by root and writable by the {group!r} group, '
            'which is the same membership that reaches qemu:///system without '
            'sudo. Run `aivm host permissions setup`, or do it by hand:\n'
            f'  sudo usermod -aG {group} "$USER"\n'
            f'  sudo install -d -o root -g {group} -m 2770 {root}\n'
            'Log out and back in after changing group membership.'
        ) from ex


@compatibility_surface
def load_scope_store(scope: StoreScope) -> Store:
    """Load the selected machine or legacy desired-state document."""
    if scope.is_machine:
        policy = current_machine_store_policy(scope.machine_layout)
        reg = load_store(scope.store_path, io_policy=policy)
        if reg.store_kind not in {'legacy', 'machine'}:
            raise AIVMError(
                f'Unsupported machine store kind: {reg.store_kind!r}'
            )
        if reg.store_kind == 'legacy' and bool(
            split_source_paths(scope.store_path)
        ):
            raise AIVMError(
                f'The machine-store path {scope.store_path} contains a legacy '
                'per-user document. Move it aside or run the future migration '
                'command; AIVM will not silently reinterpret it.'
            )
        if reg.store_kind == 'legacy':
            reg.store_kind = 'machine'
            reg.schema_version = max(reg.schema_version, 9)
        return reg
    return load_store(scope.store_path)


@compatibility_surface
def save_scope_store(
    scope: StoreScope,
    reg: Store,
    *,
    reason: str,
) -> Path:
    """Save the selected store using the correct physical policy."""
    if scope.is_machine:
        ensure_machine_scope_ready(scope)
        reg.store_kind = 'machine'
        reg.schema_version = max(reg.schema_version, 9)
        save_store_split(
            reg,
            scope.store_path,
            reason=reason,
            io_policy=current_machine_store_policy(scope.machine_layout),
        )
        return scope.store_path
    from .config_store import save_store

    return save_store(reg, scope.store_path, reason=reason)


def load_scope_profile(scope: StoreScope) -> UserProfileStore:
    """Load the private profile associated with a machine scope."""
    if not scope.is_machine:
        raise ValueError('Legacy stores do not have a separate user profile')
    assert scope.profile_path is not None
    return load_user_profile(scope.profile_path)


def _read_public_key(path: str) -> str:
    raw = str(path or '').strip()
    if not raw:
        return ''
    key_path = Path(raw).expanduser()
    try:
        text = key_path.read_text(encoding='utf-8').strip()
    except OSError:
        return ''
    return text


def stable_principal_id(vm_name: str, host_user: str) -> str:
    """Return a deterministic, readable creator/enrollment principal id."""
    digest = hashlib.sha256(
        f'{vm_name}\0{host_user}'.encode('utf-8')
    ).hexdigest()[:16]
    return f'principal-{digest}'


def _current_host_user() -> str:
    """Return the kernel-derived host login through a patchable test seam."""
    return current_host_identity().username


def _current_host_uid() -> int:
    """Return the invoking kernel UID through a patchable test seam."""
    return current_host_identity().uid


def _current_host_gid() -> int:
    """Return the invoking kernel GID through a patchable test seam."""
    return current_host_identity().gid


def current_principal_entry(
    cfg: AgentVMConfig,
    *,
    state: str = 'active',
    host_user: str | None = None,
    host_uid: int | None = None,
    host_gid: int | None = None,
) -> PrincipalEntry:
    """Build the persisted identity for the invoking host user."""
    user = host_user or _current_host_user()
    uid = _current_host_uid() if host_uid is None else int(host_uid)
    gid = _current_host_gid() if host_gid is None else int(host_gid)
    return PrincipalEntry(
        id=stable_principal_id(cfg.vm.name, user),
        vm_name=cfg.vm.name,
        host_user=user,
        host_uid=uid,
        host_gid=gid,
        guest_user=cfg.vm.user,
        ssh_public_key=_read_public_key(cfg.paths.ssh_pubkey_path),
        state=state,
    )


def profile_from_effective_cfg(
    cfg: AgentVMConfig,
    *,
    existing: UserProfileStore | None = None,
) -> UserProfileStore:
    """Update user-owned values without copying machine configuration."""
    profile = deepcopy(existing) if existing is not None else UserProfileStore()
    profile.ssh_identity_file = cfg.paths.ssh_identity_file
    profile.ssh_pubkey_path = cfg.paths.ssh_pubkey_path
    profile.state_dir = cfg.paths.state_dir
    profile.default_guest_user = cfg.vm.user or profile.default_guest_user
    profile.behavior.verbose = int(cfg.verbosity)
    return profile


def materialize_machine_cfg(
    reg: Store,
    vm_name: str,
    *,
    profile: UserProfileStore,
    principal: PrincipalEntry,
) -> AgentVMConfig:
    """Join machine config with the selected principal and user profile."""
    cfg = materialize_vm_cfg(reg, vm_name)
    cfg.vm.user = principal.guest_user
    cfg.paths.ssh_identity_file = profile.ssh_identity_file
    cfg.paths.ssh_pubkey_path = profile.ssh_pubkey_path
    cfg.paths.state_dir = profile.state_dir
    cfg.verbosity = int(profile.behavior.verbose)
    return cfg


def resolve_machine_context(
    reg: Store,
    vm_name: str,
    *,
    profile: UserProfileStore,
    identity: HostIdentity | None = None,
) -> ResolvedVMContext:
    """Resolve the kernel caller identity to one active persisted principal."""
    if identity is None:
        identity = current_host_identity()
    principal = find_principal_for_host_identity(
        reg, vm_name=vm_name, identity=identity
    )
    if principal is None:
        raise AIVMError(
            f'Host user {identity.username!r} (uid {identity.uid}) is not '
            f'enrolled for managed VM {vm_name!r}. Run '
            f'`aivm vm access reconcile --vm {vm_name}` after creating this '
            "user's AIVM SSH identity."
        )
    if principal.state not in {'active', 'legacy'}:
        raise AIVMError(
            f'Principal {principal.id!r} for VM {vm_name!r} is '
            f'{principal.state!r}, not active. Run '
            f'`aivm vm access reconcile --vm {vm_name}` to retry or repair '
            'the enrollment.'
        )
    cfg = materialize_machine_cfg(
        reg,
        vm_name,
        profile=profile,
        principal=principal,
    )
    return resolve_persisted_vm_context(
        cfg,
        principal_entry=principal,
        profile_store=profile,
    )


def persist_creator_vm(
    scope: StoreScope,
    reg: Store,
    cfg: AgentVMConfig,
    *,
    set_active: bool,
    reason: str,
) -> tuple[PrincipalEntry, UserProfileStore]:
    """Persist a machine VM, its creator principal, and the caller profile."""
    if not scope.is_machine:
        raise ValueError('Creator persistence requires a machine scope')
    reg.store_kind = 'machine'
    reg.schema_version = max(reg.schema_version, 9)
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    principal = current_principal_entry(cfg, state='active')
    upsert_principal(reg, principal)
    save_scope_store(scope, reg, reason=reason)

    profile = profile_from_effective_cfg(
        cfg,
        existing=load_scope_profile(scope),
    )
    if set_active or not profile.active_vm:
        profile.active_vm = cfg.vm.name
    assert scope.profile_path is not None
    save_user_profile(profile, scope.profile_path)
    return principal, profile
