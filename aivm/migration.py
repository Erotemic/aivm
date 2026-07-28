"""Read-only planning for released-store migration.

The planner translates one or more released per-user stores into the machine,
profile, and access-identity records that a later apply phase will write.  It
never mutates an input, the target machine store, libvirt, or guest state.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import pwd
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, cast

from .commands import CommandManager
from .config import AgentVMConfig
from .config_store import (
    AttachmentEntry,
    NetworkEntry,
    PrincipalEntry,
    Store,
    VMEntry,
    load_config_document,
    load_store,
    parse_store_toml,
    render_store_toml,
    split_source_paths,
    upsert_attachment,
    upsert_credential,
    upsert_network,
    upsert_principal,
    upsert_vm_with_network,
)
from .credentials.validation import credential_id, validate_repository_identity
from .machine_store import MachineStoreLayout, machine_store_layout
from .runtime import virsh_cmd
from .scoped_store import stable_principal_id

MIGRATION_PLAN_SCHEMA_VERSION = 1
TARGET_MACHINE_SCHEMA_VERSION = 11


@dataclass(frozen=True)
class LegacyStoreSource:
    """One released per-user store and the host identity that owns it."""

    path: Path
    host_user: str
    host_uid: int
    host_gid: int
    home: Path


@dataclass(frozen=True)
class MigrationIssue:
    """One deterministic blocker or advisory emitted by the planner."""

    code: str
    message: str
    vm_name: str = ''
    sources: tuple[str, ...] = ()
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            'code': self.code,
            'message': self.message,
        }
        if self.vm_name:
            result['vm_name'] = self.vm_name
        if self.sources:
            result['sources'] = list(self.sources)
        if self.details:
            result['details'] = self.details
        return result


@dataclass
class RuntimeInventory:
    """Best-effort read-only libvirt inventory used by a migration plan."""

    checked: bool = False
    domains: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    unmanaged_domains: list[str] = field(default_factory=list)
    unmanaged_networks: list[str] = field(default_factory=list)
    missing_domains: list[str] = field(default_factory=list)
    error: str = ''

    def to_dict(self) -> dict[str, object]:
        return {
            'checked': self.checked,
            'domains': self.domains,
            'networks': self.networks,
            'unmanaged_domains': self.unmanaged_domains,
            'unmanaged_networks': self.unmanaged_networks,
            'missing_domains': self.missing_domains,
            'error': self.error,
        }


@dataclass
class MigrationPlan:
    """Complete, serializable, non-mutating migration proposal."""

    target_machine_store: Path
    sources: list[dict[str, object]]
    machine: dict[str, object]
    profiles: list[dict[str, object]]
    persistent_state_moves: list[dict[str, object]]
    credential_material_moves: list[dict[str, object]]
    runtime: RuntimeInventory
    conflicts: list[MigrationIssue] = field(default_factory=list)
    warnings: list[MigrationIssue] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.conflicts)

    def to_dict(self) -> dict[str, object]:
        return {
            'plan_schema_version': MIGRATION_PLAN_SCHEMA_VERSION,
            'mode': 'dry-run',
            'status': 'blocked' if self.blocked else 'ready',
            'target_machine_store': str(self.target_machine_store),
            'sources': self.sources,
            'proposed': {
                'machine': self.machine,
                'profiles': self.profiles,
                'persistent_state_moves': self.persistent_state_moves,
                'credential_material_moves': self.credential_material_moves,
            },
            'runtime': self.runtime.to_dict(),
            'conflicts': [item.to_dict() for item in self.conflicts],
            'warnings': [item.to_dict() for item in self.warnings],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + '\n'

    def render_text(self) -> str:
        proposed = self.machine
        lines = [
            'AIVM released-store migration plan (dry-run; no state changed)',
            f'Status: {"BLOCKED" if self.blocked else "READY"}',
            f'Target machine store: {self.target_machine_store}',
            f'Sources: {len(self.sources)}',
        ]
        for source in self.sources:
            lines.append(
                '  - {host_user}: {path} | layout={layout} | '
                'schema={schema_version}'.format(**source)
            )
            files = source.get('files', [])
            if isinstance(files, list):
                for file_info in files:
                    if not isinstance(file_info, dict):
                        continue
                    digest = str(file_info.get('sha256', ''))
                    lines.append(
                        '      {role}: {path} | sha256={digest}'.format(
                            role=file_info.get('role', 'source'),
                            path=file_info.get('path', ''),
                            digest=digest,
                        )
                    )
        networks = _dict_list(proposed, 'networks')
        vms = _dict_list(proposed, 'vms')
        identities = _dict_list(proposed, 'principals')
        attachments = _dict_list(proposed, 'attachments')
        credentials = _dict_list(proposed, 'credentials')
        lines.extend(
            [
                '',
                'Proposed machine records:',
                f'  networks: {len(networks)}',
                f'  VMs: {len(vms)}',
                f'  access identities: {len(identities)}',
                f'  attachments: {len(attachments)}',
                f'  credentials: {len(credentials)}',
            ]
        )
        for network in networks:
            if isinstance(network, dict):
                lines.append(f'    network: {network.get("name", "")}')
        for vm in vms:
            if isinstance(vm, dict):
                lines.append(
                    f'    VM: {vm.get("name", "")} | '
                    f'network={vm.get("network_name", "")}'
                )
        for identity in identities:
            if isinstance(identity, dict):
                lines.append(
                    f'    identity: {identity.get("host_user", "")} -> '
                    f'{identity.get("guest_user", "")} | '
                    f'vm={identity.get("vm_name", "")} | '
                    f'id={identity.get("id", "")}'
                )
        for attachment in attachments:
            if isinstance(attachment, dict):
                lines.append(
                    f'    attachment: {attachment.get("host_path", "")} -> '
                    f'{attachment.get("guest_dst", "")} | '
                    f'vm={attachment.get("vm_name", "")} | '
                    f'owner={attachment.get("owner_principal_id", "")}'
                )
        for credential in credentials:
            if isinstance(credential, dict):
                lines.append(
                    f'    credential: {credential.get("provider_host", "")}/'
                    f'{credential.get("owner", "")}/'
                    f'{credential.get("repository", "")} | '
                    f'id={credential.get("id", "")} | '
                    f'owner={credential.get("principal_id", "")}'
                )
        lines.append(f'Proposed user profiles: {len(self.profiles)}')
        for profile in self.profiles:
            lines.append(
                f'  - {profile.get("host_user", "")}: '
                f'{profile.get("path", "")} | '
                f'active_vm={profile.get("active_vm", "")}'
            )
        lines.append(
            f'Persistent-state moves: {len(self.persistent_state_moves)}'
        )
        for move in self.persistent_state_moves:
            lines.append(
                f'  - {move.get("source", "")} -> '
                f'{move.get("target", "")} | '
                f'exists={move.get("source_exists", False)}'
            )
        lines.append(
            f'Credential-material moves: '
            f'{len(self.credential_material_moves)}'
        )
        for move in self.credential_material_moves:
            lines.append(
                f'  - {move.get("legacy_credential_id", "")} -> '
                f'{move.get("credential_id", "")} | '
                f'{move.get("source", "")} -> {move.get("target", "")} | '
                f'exists={move.get("source_exists", False)}'
            )
        lines.extend(['', 'Runtime inventory:'])
        if not self.runtime.checked:
            lines.append('  not checked')
        elif self.runtime.error:
            lines.append(f'  unavailable: {self.runtime.error}')
        else:
            lines.append(f'  domains: {len(self.runtime.domains)}')
            lines.append(f'  networks: {len(self.runtime.networks)}')
            if self.runtime.unmanaged_domains:
                lines.append(
                    '  unmanaged domains: '
                    + ', '.join(self.runtime.unmanaged_domains)
                )
            if self.runtime.unmanaged_networks:
                lines.append(
                    '  unmanaged networks: '
                    + ', '.join(self.runtime.unmanaged_networks)
                )
            if self.runtime.missing_domains:
                lines.append(
                    '  missing managed domains: '
                    + ', '.join(self.runtime.missing_domains)
                )
        lines.append('')
        if self.conflicts:
            lines.append(f'Blocking conflicts ({len(self.conflicts)}):')
            for issue in self.conflicts:
                lines.append(f'  - [{issue.code}] {issue.message}')
        else:
            lines.append('Blocking conflicts: none')
        if self.warnings:
            lines.append(f'Warnings ({len(self.warnings)}):')
            for issue in self.warnings:
                lines.append(f'  - [{issue.code}] {issue.message}')
        else:
            lines.append('Warnings: none')
        lines.extend(
            [
                '',
                'No files, libvirt resources, guest accounts, or provider '
                'credentials were changed.',
            ]
        )
        return '\n'.join(lines) + '\n'


def _dict_list(mapping: dict[str, object], key: str) -> list[object]:
    value = mapping.get(key, [])
    if not isinstance(value, list):
        return []
    return cast(list[object], value)


def _normalize_store_path(path: Path) -> Path:
    expanded = path.expanduser().resolve()
    if expanded.is_dir():
        return expanded / 'config.toml'
    return expanded


def _infer_home(path: Path, host_user: str) -> Path:
    parts = path.parts
    for marker in ('.config', 'Library'):
        if marker in parts:
            idx = parts.index(marker)
            if idx > 0:
                return Path(*parts[:idx])
    try:
        return Path(pwd.getpwnam(host_user).pw_dir)
    except KeyError:
        return Path('/home') / host_user


def _resolve_host_identity(host_user: str) -> tuple[int, int, Path]:
    current = getpass.getuser()
    if host_user == current:
        uid_getter = getattr(os, 'getuid', None)
        gid_getter = getattr(os, 'getgid', None)
        uid = int(uid_getter()) if uid_getter is not None else -1
        gid = int(gid_getter()) if gid_getter is not None else -1
        return uid, gid, Path.home()
    try:
        record = pwd.getpwnam(host_user)
    except KeyError:
        return -1, -1, Path('/home') / host_user
    return int(record.pw_uid), int(record.pw_gid), Path(record.pw_dir)


def parse_legacy_source_spec(spec: str) -> LegacyStoreSource:
    """Parse ``[HOST_USER=]PATH`` into a released-store source."""
    raw = str(spec or '').strip()
    if not raw:
        raise ValueError('migration source may not be empty')
    if '=' in raw:
        host_user, raw_path = raw.split('=', 1)
        host_user = host_user.strip()
        raw_path = raw_path.strip()
        if not host_user or not raw_path:
            raise ValueError(
                'migration source must use [HOST_USER=]PATH, for example '
                'alice=/home/alice/.config/aivm/config.toml'
            )
    else:
        host_user = getpass.getuser()
        raw_path = raw
    path = _normalize_store_path(Path(raw_path))
    uid, gid, home = _resolve_host_identity(host_user)
    inferred = _infer_home(path, host_user)
    if not home.exists() and inferred != home:
        home = inferred
    elif host_user != getpass.getuser() and inferred.name == host_user:
        home = inferred
    return LegacyStoreSource(
        path=path,
        host_user=host_user,
        host_uid=uid,
        host_gid=gid,
        home=home,
    )


def default_legacy_source(path: Path) -> LegacyStoreSource:
    """Describe the invoking user's released store."""
    user = getpass.getuser()
    uid, gid, home = _resolve_host_identity(user)
    return LegacyStoreSource(
        path=_normalize_store_path(path),
        host_user=user,
        host_uid=uid,
        host_gid=gid,
        home=home,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _public_key_fingerprint(text: str) -> str:
    parts = str(text or '').strip().split()
    if len(parts) < 2:
        return ''
    try:
        blob = base64.b64decode(parts[1].encode('ascii'), validate=True)
    except (ValueError, UnicodeError):
        return ''
    encoded = base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii')
    return 'SHA256:' + encoded.rstrip('=')


def _read_public_key(path: str) -> tuple[str, str]:
    raw = str(path or '').strip()
    if not raw:
        return '', ''
    try:
        text = Path(raw).expanduser().read_text(encoding='utf-8').strip()
    except OSError:
        return '', ''
    return text, _public_key_fingerprint(text)


def _machine_cfg_dict(cfg: AgentVMConfig) -> dict[str, object]:
    data = asdict(cfg)
    data.pop('network', None)
    data.pop('firewall', None)
    vm = data.get('vm')
    if isinstance(vm, dict):
        vm.pop('user', None)
    paths = data.get('paths')
    if isinstance(paths, dict):
        data['paths'] = {'base_dir': paths.get('base_dir', '')}
    return data


def _flatten(value: object, prefix: str = '') -> dict[str, object]:
    if not isinstance(value, dict):
        return {prefix: value}
    mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in mapping):
        raise TypeError('migration comparison dictionaries require string keys')
    typed_mapping = cast(dict[str, object], mapping)
    result: dict[str, object] = {}
    for key in sorted(typed_mapping):
        child = typed_mapping[key]
        name = f'{prefix}.{key}' if prefix else key
        if isinstance(child, dict):
            result.update(_flatten(child, name))
        else:
            result[name] = child
    return result


def _difference_keys(left: object, right: object) -> list[str]:
    lhs = _flatten(left)
    rhs = _flatten(right)
    return [
        key
        for key in sorted(set(lhs) | set(rhs))
        if lhs.get(key) != rhs.get(key)
    ]


def _profile_target_path(source: LegacyStoreSource) -> Path:
    if source.home.resolve() == Path.home().resolve():
        configured = os.environ.get('XDG_CONFIG_HOME', '').strip()
        if configured:
            return Path(configured).expanduser().resolve() / 'aivm' / 'profile.toml'
    return source.home / '.config' / 'aivm' / 'profile.toml'


def _profile_proposal(
    source: LegacyStoreSource,
    reg: Store,
    conflicts: list[MigrationIssue],
) -> dict[str, object]:
    vm_cfgs = [item.cfg for item in reg.vms]
    active = next(
        (item.cfg for item in reg.vms if item.name == reg.active_vm),
        vm_cfgs[0] if vm_cfgs else reg.defaults,
    )
    if active is None:
        active = AgentVMConfig()
    values = {
        'ssh_identity_file': str(active.paths.ssh_identity_file),
        'ssh_pubkey_path': str(active.paths.ssh_pubkey_path),
        'state_dir': str(active.paths.state_dir),
    }
    for field_name in tuple(values):
        distinct = sorted(
            {
                str(getattr(cfg.paths, field_name))
                for cfg in vm_cfgs
                if str(getattr(cfg.paths, field_name)).strip()
            }
        )
        if len(distinct) > 1:
            conflicts.append(
                MigrationIssue(
                    code='profile-path-divergence',
                    message=(
                        f'Legacy store {source.path} uses multiple '
                        f'{field_name} values; one profile cannot represent '
                        'them without an explicit choice.'
                    ),
                    sources=(str(source.path),),
                    details={'field': field_name, 'values': distinct},
                )
            )
    default_guest_user = str(active.vm.user or 'agent')
    return {
        'host_user': source.host_user,
        'path': str(_profile_target_path(source)),
        'active_vm': reg.active_vm,
        'behavior': asdict(reg.behavior),
        'ssh_identity_file': values['ssh_identity_file'],
        'ssh_pubkey_path': values['ssh_pubkey_path'],
        'state_dir': values['state_dir'],
        'default_guest_user': default_guest_user,
    }


def _legacy_data_root(source: LegacyStoreSource) -> Path:
    if (
        source.host_user == getpass.getuser()
        and source.home.resolve() == Path.home().resolve()
    ):
        configured = os.environ.get('XDG_DATA_HOME', '').strip()
        if configured:
            return Path(configured).expanduser().resolve() / 'aivm'
    return source.home / '.local' / 'share' / 'aivm'


def _runtime_names(
    command: list[str], *, sudo: bool
) -> tuple[list[str], str]:
    result = CommandManager.current().run(
        command,
        role='read',
        sudo=sudo,
        check=False,
        capture=True,
    )
    if result.code != 0:
        raw = (result.stderr or result.stdout or 'command failed').strip()
        return [], raw
    names = {
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    }
    return sorted(names), ''


def collect_runtime_inventory(
    *, managed_vms: Iterable[str], managed_networks: Iterable[str], sudo: bool
) -> RuntimeInventory:
    """Read libvirt names without changing runtime state."""
    domains, domain_error = _runtime_names(
        virsh_cmd('list', '--all', '--name'), sudo=sudo
    )
    networks, network_error = _runtime_names(
        virsh_cmd('net-list', '--all', '--name'), sudo=sudo
    )
    error = '; '.join(item for item in (domain_error, network_error) if item)
    managed_vm_set = {str(item) for item in managed_vms}
    managed_network_set = {str(item) for item in managed_networks}
    return RuntimeInventory(
        checked=True,
        domains=domains,
        networks=networks,
        unmanaged_domains=sorted(set(domains) - managed_vm_set),
        unmanaged_networks=sorted(set(networks) - managed_network_set),
        missing_domains=(
            sorted(managed_vm_set - set(domains))
            if not domain_error
            else []
        ),
        error=error,
    )


def _source_summary(
    source: LegacyStoreSource,
    loaded: Any,
    reg: Store,
) -> dict[str, object]:
    files = [
        {
            'path': str(item.path),
            'role': item.role,
            'sha256': _file_sha256(item.path),
        }
        for item in loaded.sources
    ]
    return {
        'path': str(source.path),
        'host_user': source.host_user,
        'host_uid': source.host_uid,
        'host_gid': source.host_gid,
        'home': str(source.home),
        'layout': loaded.layout,
        'schema_version': reg.schema_version,
        'active_vm': reg.active_vm,
        'files': files,
    }


def build_migration_plan(
    sources: list[LegacyStoreSource],
    *,
    layout: MachineStoreLayout | None = None,
    check_runtime: bool = True,
    runtime_sudo: bool = False,
    runtime_collector: Callable[..., RuntimeInventory] = collect_runtime_inventory,
) -> MigrationPlan:
    """Build a deterministic migration proposal without writing anything."""
    layout = layout or machine_store_layout()
    conflicts: list[MigrationIssue] = []
    warnings: list[MigrationIssue] = []
    source_rows: list[dict[str, object]] = []
    profiles: list[dict[str, object]] = []
    persistent_moves: list[dict[str, object]] = []
    credential_material_moves: list[dict[str, object]] = []
    loaded_sources: list[tuple[LegacyStoreSource, Store]] = []

    if not sources:
        conflicts.append(
            MigrationIssue(
                code='no-sources',
                message='No released AIVM stores were supplied for migration.',
            )
        )

    seen_paths: set[Path] = set()
    for source in sorted(sources, key=lambda item: (item.host_user, str(item.path))):
        if source.path in seen_paths:
            conflicts.append(
                MigrationIssue(
                    code='duplicate-source',
                    message=f'Source store was supplied more than once: {source.path}',
                    sources=(str(source.path),),
                )
            )
            continue
        seen_paths.add(source.path)
        if not source.path.exists():
            conflicts.append(
                MigrationIssue(
                    code='source-missing',
                    message=f'Released store does not exist: {source.path}',
                    sources=(str(source.path),),
                )
            )
            continue
        try:
            loaded = load_config_document(source.path)
            reg = loaded.store
        except Exception as ex:
            conflicts.append(
                MigrationIssue(
                    code='source-invalid',
                    message=f'Could not load {source.path}: {ex}',
                    sources=(str(source.path),),
                )
            )
            continue
        if reg.store_kind != 'legacy':
            conflicts.append(
                MigrationIssue(
                    code='source-not-legacy',
                    message=(
                        f'{source.path} is {reg.store_kind!r}, not a released '
                        'per-user legacy store.'
                    ),
                    sources=(str(source.path),),
                )
            )
            continue
        if reg.schema_version > 8:
            warnings.append(
                MigrationIssue(
                    code='newer-legacy-schema',
                    message=(
                        f'{source.path} uses legacy schema {reg.schema_version}; '
                        'the released migration fixtures cover schema 8.'
                    ),
                    sources=(str(source.path),),
                )
            )
        source_rows.append(_source_summary(source, loaded, reg))
        if not reg.vms:
            conflicts.append(
                MigrationIssue(
                    code='source-has-no-vms',
                    message=f'Released store contains no VM records: {source.path}',
                    sources=(str(source.path),),
                )
            )
        if reg.active_vm and not any(item.name == reg.active_vm for item in reg.vms):
            conflicts.append(
                MigrationIssue(
                    code='active-vm-missing',
                    message=(
                        f'Released store {source.path} selects active VM '
                        f'{reg.active_vm!r}, but that VM record is absent.'
                    ),
                    sources=(str(source.path),),
                    vm_name=reg.active_vm,
                )
            )
        profiles.append(_profile_proposal(source, reg, conflicts))
        loaded_sources.append((source, reg))

    by_host_user: dict[str, list[str]] = {}
    for source, _reg in loaded_sources:
        by_host_user.setdefault(source.host_user, []).append(str(source.path))
    for host_user, paths in sorted(by_host_user.items()):
        if len(paths) > 1:
            conflicts.append(
                MigrationIssue(
                    code='duplicate-host-profile',
                    message=(
                        f'Multiple released stores would write the same profile '
                        f'for host user {host_user!r}.'
                    ),
                    sources=tuple(sorted(paths)),
                )
            )

    target = Store(
        schema_version=TARGET_MACHINE_SCHEMA_VERSION,
        store_kind='machine',
    )

    defaults_candidates = [
        (source, reg.defaults)
        for source, reg in loaded_sources
        if reg.defaults is not None
    ]
    if defaults_candidates:
        first_source, first_defaults = defaults_candidates[0]
        assert first_defaults is not None
        target.defaults = deepcopy(first_defaults)
        first_signature = _machine_cfg_dict(first_defaults)
        for source, defaults in defaults_candidates[1:]:
            assert defaults is not None
            difference = _difference_keys(
                first_signature, _machine_cfg_dict(defaults)
            )
            if difference:
                conflicts.append(
                    MigrationIssue(
                        code='defaults-conflict',
                        message=(
                            'Released stores disagree about machine defaults: '
                            f'{first_source.path} and {source.path}.'
                        ),
                        sources=(str(first_source.path), str(source.path)),
                        details={'fields': difference},
                    )
                )

    network_claims: dict[str, list[tuple[LegacyStoreSource, NetworkEntry]]] = {}
    vm_claims: dict[str, list[tuple[LegacyStoreSource, VMEntry, Store]]] = {}
    for source, reg in loaded_sources:
        for network in reg.networks:
            network_claims.setdefault(network.name, []).append((source, network))
        for vm in reg.vms:
            vm_claims.setdefault(vm.name, []).append((source, vm, reg))

    for name, network_claim_list in sorted(network_claims.items()):
        first_source, first = network_claim_list[0]
        first_data = asdict(first)
        for source, candidate in network_claim_list[1:]:
            difference = _difference_keys(first_data, asdict(candidate))
            if difference:
                conflicts.append(
                    MigrationIssue(
                        code='network-conflict',
                        message=(
                            f'Network {name!r} differs between '
                            f'{first_source.path} and {source.path}.'
                        ),
                        sources=(str(first_source.path), str(source.path)),
                        details={'fields': difference},
                    )
                )
        upsert_network(
            target,
            network=deepcopy(first.network),
            firewall=deepcopy(first.firewall),
            name=name,
        )

    for vm_name, vm_claim_list in sorted(vm_claims.items()):
        if len(vm_claim_list) > 1:
            sources_for_vm = tuple(str(item[0].path) for item in vm_claim_list)
            first_data = {
                'network_name': vm_claim_list[0][1].network_name,
                'cfg': _machine_cfg_dict(vm_claim_list[0][1].cfg),
            }
            differing: dict[str, list[str]] = {}
            for vm_source, vm_candidate, _vm_reg in vm_claim_list[1:]:
                fields = _difference_keys(
                    first_data,
                    {
                        'network_name': vm_candidate.network_name,
                        'cfg': _machine_cfg_dict(vm_candidate.cfg),
                    },
                )
                if fields:
                    differing[str(vm_source.path)] = fields
            conflicts.append(
                MigrationIssue(
                    code='multiple-store-vm-claim',
                    message=(
                        f'Multiple released stores claim VM {vm_name!r}; '
                        'AIVM will not choose or merge a machine definition silently.'
                    ),
                    vm_name=vm_name,
                    sources=sources_for_vm,
                    details={'differing_machine_fields': differing},
                )
            )
            continue

        source, vm, reg = vm_claim_list[0]
        upsert_vm_with_network(
            target,
            deepcopy(vm.cfg),
            network_name=vm.network_name,
        )
        public_key, fingerprint = _read_public_key(vm.cfg.paths.ssh_pubkey_path)
        principal_id = stable_principal_id(vm_name, source.host_user)
        principal = PrincipalEntry(
            id=principal_id,
            vm_name=vm_name,
            host_user=source.host_user,
            host_uid=source.host_uid,
            host_gid=source.host_gid,
            guest_user=vm.cfg.vm.user,
            ssh_public_key=public_key,
            state='legacy',
        )
        upsert_principal(target, principal)
        if source.host_uid < 0 or source.host_gid < 0:
            conflicts.append(
                MigrationIssue(
                    code='host-identity-unresolved',
                    message=(
                        f'Could not resolve UID/GID for host user '
                        f'{source.host_user!r} while planning VM {vm_name!r}.'
                    ),
                    vm_name=vm_name,
                    sources=(str(source.path),),
                )
            )
        if not public_key:
            conflicts.append(
                MigrationIssue(
                    code='public-key-missing',
                    message=(
                        f'Public SSH key for {source.host_user!r} is missing or '
                        f'unreadable: {vm.cfg.paths.ssh_pubkey_path!r}.'
                    ),
                    vm_name=vm_name,
                    sources=(str(source.path),),
                )
            )

        for attachment in reg.attachments:
            if attachment.vm_name != vm_name:
                continue
            upsert_attachment(
                target,
                host_path=attachment.host_path,
                vm_name=vm_name,
                owner_principal_id=principal_id,
                mode=attachment.mode,
                access=attachment.access,
                guest_dst=attachment.guest_dst,
                tag=attachment.tag,
                host_lexical_paths=attachment.host_lexical_paths,
            )

        if public_key and not fingerprint:
            conflicts.append(
                MigrationIssue(
                    code='public-key-invalid',
                    message=(
                        f'Public SSH key for {source.host_user!r} is not a '
                        f'valid OpenSSH public key: {vm.cfg.paths.ssh_pubkey_path!r}.'
                    ),
                    vm_name=vm_name,
                    sources=(str(source.path),),
                )
            )

        for credential in reg.credentials:
            if credential.vm_name != vm_name:
                continue
            repo = validate_repository_identity(
                credential.provider_host,
                credential.owner,
                credential.repository,
            )
            migrated = replace(
                credential,
                id=credential_id(vm_name, repo.canonical, principal_id),
                principal_id=principal_id,
            )
            upsert_credential(target, migrated)
            data_root = _legacy_data_root(source)
            old_material = data_root / vm_name / 'credentials' / credential.id
            new_material = data_root / vm_name / 'credentials' / migrated.id
            credential_material_moves.append(
                {
                    'host_user': source.host_user,
                    'vm_name': vm_name,
                    'principal_id': principal_id,
                    'legacy_credential_id': credential.id,
                    'credential_id': migrated.id,
                    'source': str(old_material),
                    'source_exists': old_material.exists(),
                    'target': str(new_material),
                    'action': 'rename-within-user-owned-data',
                }
            )

        legacy_state = _legacy_data_root(source) / vm_name / 'state'
        persistent_moves.append(
            {
                'host_user': source.host_user,
                'vm_name': vm_name,
                'source': str(legacy_state),
                'source_exists': legacy_state.exists(),
                'target': str(layout.vm_state_dir(vm_name) / 'persistent'),
            }
        )

    guest_destinations: dict[tuple[str, str], list[AttachmentEntry]] = {}
    for attachment in target.attachments:
        if attachment.guest_dst:
            guest_destinations.setdefault(
                (attachment.vm_name, attachment.guest_dst), []
            ).append(attachment)
    for (vm_name, guest_dst), records in sorted(guest_destinations.items()):
        if len(records) > 1:
            conflicts.append(
                MigrationIssue(
                    code='attachment-guest-destination-conflict',
                    message=(
                        f'Multiple migrated attachments target {guest_dst!r} '
                        f'inside VM {vm_name!r}.'
                    ),
                    vm_name=vm_name,
                    details={
                        'owners': sorted(
                            item.owner_principal_id for item in records
                        ),
                        'host_paths': sorted(item.host_path for item in records),
                    },
                )
            )

    if split_source_paths(layout.config_path):
        try:
            existing_machine = load_store(layout.config_path)
        except Exception as ex:
            conflicts.append(
                MigrationIssue(
                    code='target-store-invalid',
                    message=f'Could not read target machine store: {ex}',
                    sources=(str(layout.config_path),),
                )
            )
        else:
            if existing_machine.vms or existing_machine.networks:
                conflicts.append(
                    MigrationIssue(
                        code='target-store-not-empty',
                        message=(
                            f'Target machine store {layout.config_path} already '
                            'contains managed records; apply requires an '
                            'explicit merge decision.'
                        ),
                        sources=(str(layout.config_path),),
                        details={
                            'vms': sorted(item.name for item in existing_machine.vms),
                            'networks': sorted(
                                item.name for item in existing_machine.networks
                            ),
                        },
                    )
                )

    # Rendering and reparsing validates the complete in-memory proposal without
    # touching the target filesystem.
    try:
        parse_store_toml(render_store_toml(target, attachment_style='nested'))
    except Exception as ex:
        conflicts.append(
            MigrationIssue(
                code='proposal-invalid',
                message=f'Proposed machine store does not round-trip: {ex}',
            )
        )

    machine_report = {
        'schema_version': target.schema_version,
        'store_kind': target.store_kind,
        'defaults_present': target.defaults is not None,
        'networks': [
            {'name': item.name}
            for item in sorted(target.networks, key=lambda x: x.name)
        ],
        'vms': [
            {
                'name': item.name,
                'network_name': item.network_name,
                'machine_config': _machine_cfg_dict(item.cfg),
            }
            for item in sorted(target.vms, key=lambda x: x.name)
        ],
        'principals': [
            {
                'id': item.id,
                'vm_name': item.vm_name,
                'host_user': item.host_user,
                'host_uid': item.host_uid,
                'host_gid': item.host_gid,
                'guest_user': item.guest_user,
                'public_key_present': bool(item.ssh_public_key),
                'public_key_fingerprint': _public_key_fingerprint(
                    item.ssh_public_key
                ),
                'state': item.state,
            }
            for item in sorted(
                target.principals,
                key=lambda x: (x.vm_name, x.host_user),
            )
        ],
        'attachments': [
            asdict(item)
            for item in sorted(
                target.attachments,
                key=lambda x: (x.vm_name, x.owner_principal_id, x.host_path),
            )
        ],
        'credentials': [
            asdict(item)
            for item in sorted(
                target.credentials,
                key=lambda x: (x.vm_name, x.principal_id, x.id),
            )
        ],
    }

    if check_runtime:
        runtime = runtime_collector(
            managed_vms=sorted(vm_claims),
            managed_networks=sorted(network_claims),
            sudo=runtime_sudo,
        )
        if runtime.error:
            warnings.append(
                MigrationIssue(
                    code='runtime-inventory-unavailable',
                    message=(
                        'Libvirt runtime inventory was incomplete: '
                        f'{runtime.error}'
                    ),
                )
            )
        for vm_name in runtime.missing_domains:
            conflicts.append(
                MigrationIssue(
                    code='runtime-domain-missing',
                    message=(
                        f'Legacy store claims VM {vm_name!r}, but no libvirt '
                        'domain with that name was found.'
                    ),
                    vm_name=vm_name,
                )
            )
    else:
        runtime = RuntimeInventory(checked=False)
        warnings.append(
            MigrationIssue(
                code='runtime-inventory-skipped',
                message='Libvirt runtime inventory was skipped by request.',
            )
        )

    return MigrationPlan(
        target_machine_store=layout.config_path,
        sources=source_rows,
        machine=machine_report,
        profiles=sorted(profiles, key=lambda item: str(item['host_user'])),
        persistent_state_moves=sorted(
            persistent_moves,
            key=lambda item: (str(item['vm_name']), str(item['host_user'])),
        ),
        credential_material_moves=sorted(
            credential_material_moves,
            key=lambda item: (
                str(item['vm_name']),
                str(item['host_user']),
                str(item['legacy_credential_id']),
            ),
        ),
        runtime=runtime,
        conflicts=sorted(
            conflicts,
            key=lambda item: (item.code, item.vm_name, item.message),
        ),
        warnings=sorted(
            warnings,
            key=lambda item: (item.code, item.vm_name, item.message),
        ),
    )
