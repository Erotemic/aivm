"""Routing and materialization for machine-global plus per-user state.

AIVM 0.6 supports two persistence modes during migration:

* ``legacy``: the released per-user :class:`aivm.config_store.Store`;
* ``machine``: one host-wide machine store plus one private user profile.

Explicit ``--config`` paths always select legacy semantics. Implicit commands
prefer an existing machine store, fall back to an existing legacy store, and
choose the machine store for a brand-new installation.
"""

from __future__ import annotations

import getpass
import hashlib
import os
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
    find_principal_for_host,
    load_store,
    materialize_vm_cfg,
    save_store_split,
    split_source_paths,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from .config_store.paths import store_path as legacy_store_path
from .errors import AIVMError
from .machine_store import (
    MachineStoreLayout,
    current_machine_group_gid,
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


def _store_exists(path: Path) -> bool:
    return bool(split_source_paths(path))


def resolve_store_scope(
    config_opt: str | None,
    *,
    for_init: bool = False,
) -> StoreScope:
    """Choose legacy or machine persistence without silently migrating data."""
    if config_opt:
        explicit = Path(config_opt).expanduser().resolve()
        layout = machine_store_layout()
        if explicit == layout.config_path:
            return StoreScope(
                mode='machine',
                store_path=layout.config_path,
                profile_path=profile_store_path(),
                machine_layout=layout,
            )
        return StoreScope(
            mode='legacy',
            store_path=explicit,
        )

    layout = machine_store_layout()
    machine_exists = _store_exists(layout.config_path)
    legacy_path = legacy_store_path().expanduser().resolve()
    legacy_exists = _store_exists(legacy_path)

    if machine_exists:
        return StoreScope(
            mode='machine',
            store_path=layout.config_path,
            profile_path=profile_store_path(),
            machine_layout=layout,
        )
    if legacy_exists:
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
            group_gid=current_machine_group_gid(),
        )
    except Exception as ex:
        root = scope.machine_layout.root
        raise AIVMError(
            f'Could not initialize the shared AIVM machine store at {root}: {ex}\n'
            'The default installation requires a trusted host group named '
            '`aivm` and a group-writable setgid store root. Suggested setup:\n'
            '  sudo groupadd --system aivm  # only if the group is absent\n'
            '  sudo usermod -aG aivm "$USER"\n'
            f'  sudo install -d -o root -g aivm -m 2775 {root}\n'
            'Log out and back in after changing group membership.'
        ) from ex


def load_scope_store(scope: StoreScope) -> Store:
    """Load the selected machine or legacy desired-state document."""
    if scope.is_machine:
        policy = current_machine_store_policy(scope.machine_layout)
        reg = load_store(scope.store_path, io_policy=policy)
        if reg.store_kind not in {'legacy', 'machine'}:
            raise AIVMError(
                f'Unsupported machine store kind: {reg.store_kind!r}'
            )
        if reg.store_kind == 'legacy' and _store_exists(scope.store_path):
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
    """Return the invoking host login through a patchable test seam."""
    return getpass.getuser()


def _current_host_uid() -> int:
    """Return the invoking host UID, or -1 on platforms without POSIX UIDs."""
    getter = getattr(os, 'getuid', None)
    return int(getter()) if getter is not None else -1


def _current_host_gid() -> int:
    """Return the invoking host GID, or -1 on platforms without POSIX GIDs."""
    getter = getattr(os, 'getgid', None)
    return int(getter()) if getter is not None else -1


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
    host_user: str | None = None,
) -> ResolvedVMContext:
    """Resolve the current host user to one active persisted principal."""
    user = host_user or _current_host_user()
    principal = find_principal_for_host(
        reg,
        vm_name=vm_name,
        host_user=user,
    )
    if principal is None:
        raise AIVMError(
            f'Host user {user!r} is not enrolled for managed VM {vm_name!r}. '
            'Automatic enrollment is the next implementation stage.'
        )
    if principal.state not in {'active', 'legacy'}:
        raise AIVMError(
            f'Principal {principal.id!r} for VM {vm_name!r} is '
            f'{principal.state!r}, not active. Run the future access '
            'reconciliation command after enrollment support lands.'
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
