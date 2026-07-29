"""Resumable execution and rollback for released-store migration.

The read-only planner in :mod:`aivm.legacy.pre_0_6_0.migration` remains the authority for what
may be migrated.  This module freezes one ready plan, backs up every input and
replacement target, applies idempotent phases, verifies the result, and keeps a
journal that can be resumed or rolled back after interruption.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import shutil
import tempfile
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, cast

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...config_store import (
    load_store,
    render_store_toml,
    save_store_split,
    split_fragment_paths,
    split_source_paths,
)
from ...config_store.fs_policy import (
    StoreFilesystemPolicy,
    apply_store_file_policy,
    ensure_store_directory,
)
from ...errors import AIVMError
from ...guestctl import (
    BOOTSTRAP_GUEST_USER,
    BOOTSTRAP_SUDOERS_PATH,
    GUESTCTL_PATH,
    guestctl_source,
    restricted_bootstrap_authorized_key,
)
from ...machine_store import (
    MachineStoreLayout,
    current_machine_group_gid,
    current_machine_store_policy,
    ensure_machine_store_layout,
    machine_store_layout,
)
from .migration import (
    LegacyStoreSource,
    MigrationPlan,
    RuntimeInventory,
    build_migration_plan,
    collect_runtime_inventory,
)
from ...profile_store import (
    load_user_profile,
    render_user_profile,
    save_user_profile,
)
from ...runtime import require_ssh_identity, ssh_base_args
from ...enrollment import ensure_bootstrap_identity
from ...vm.connectivity import wait_for_ip

MIGRATION_JOURNAL_SCHEMA_VERSION = 1
MigrationStatus = Literal[
    'applying',
    'failed',
    'complete',
    'rolled-back',
    'rollback-failed',
]
BackupDisposition = Literal['evidence_only', 'restore_on_rollback']

_APPLY_STEPS = (
    'backups-created',
    'machine-store-written',
    'profiles-written',
    'credential-material-copied',
    'persistent-state-copied',
    'bootstrap-installed',
    'verified',
)


class MigrationExecutionError(AIVMError):
    """Raised when a migration cannot safely continue."""


@dataclass(frozen=True)
class BackupRecord:
    """One original path and its transaction-local backup."""

    original: str
    backup: str
    role: str
    existed: bool
    kind: Literal['missing', 'file', 'directory']
    sha256: str = ''
    disposition: BackupDisposition = 'restore_on_rollback'
    applied_existed: bool | None = None
    applied_sha256: str = ''

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> BackupRecord:
        kind_raw = str(raw.get('kind', 'missing'))
        kind: Literal['missing', 'file', 'directory']
        if kind_raw == 'missing':
            kind = 'missing'
        elif kind_raw == 'file':
            kind = 'file'
        elif kind_raw == 'directory':
            kind = 'directory'
        else:
            raise MigrationExecutionError(f'Invalid backup kind: {kind_raw!r}')
        role = str(raw.get('role', ''))
        disposition_raw = str(raw.get('disposition', ''))
        if not disposition_raw:
            disposition_raw = (
                'evidence_only'
                if role in {'legacy-store-input', 'persistent-input'}
                else 'restore_on_rollback'
            )
        if disposition_raw == 'evidence_only':
            disposition: BackupDisposition = 'evidence_only'
        elif disposition_raw == 'restore_on_rollback':
            disposition = 'restore_on_rollback'
        else:
            raise MigrationExecutionError(
                f'Invalid backup disposition: {disposition_raw!r}'
            )
        applied_value = raw.get('applied_existed')
        applied_existed = (
            applied_value if isinstance(applied_value, bool) else None
        )
        return cls(
            original=str(raw.get('original', '')),
            backup=str(raw.get('backup', '')),
            role=role,
            existed=bool(raw.get('existed', False)),
            kind=kind,
            sha256=str(raw.get('sha256', '')),
            disposition=disposition,
            applied_existed=applied_existed,
            applied_sha256=str(raw.get('applied_sha256', '')),
        )


@dataclass
class MigrationJournal:
    """Durable execution state for one deterministic migration plan."""

    migration_id: str
    plan_sha256: str
    target_machine_store: str
    sources: list[dict[str, object]]
    status: MigrationStatus = 'applying'
    completed_steps: list[str] = field(default_factory=list)
    backups: list[BackupRecord] = field(default_factory=list)
    error: str = ''
    verification: dict[str, object] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())

    def to_dict(self) -> dict[str, object]:
        return {
            'journal_schema_version': MIGRATION_JOURNAL_SCHEMA_VERSION,
            'migration_id': self.migration_id,
            'plan_sha256': self.plan_sha256,
            'target_machine_store': self.target_machine_store,
            'sources': self.sources,
            'status': self.status,
            'completed_steps': self.completed_steps,
            'backups': [item.to_dict() for item in self.backups],
            'error': self.error,
            'verification': self.verification,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> MigrationJournal:
        version = _object_int(raw.get('journal_schema_version', 0), default=0)
        if version != MIGRATION_JOURNAL_SCHEMA_VERSION:
            raise MigrationExecutionError(
                f'Unsupported migration journal schema {version}'
            )
        status = str(raw.get('status', 'failed'))
        allowed = {
            'applying',
            'failed',
            'complete',
            'rolled-back',
            'rollback-failed',
        }
        if status not in allowed:
            raise MigrationExecutionError(
                f'Invalid migration journal status: {status!r}'
            )
        source_value = raw.get('sources', [])
        sources: list[dict[str, object]] = []
        if isinstance(source_value, list):
            for item in source_value:
                if isinstance(item, dict) and all(
                    isinstance(key, str) for key in item
                ):
                    sources.append(cast(dict[str, object], item))
        completed_value = raw.get('completed_steps', [])
        completed = (
            [str(item) for item in completed_value]
            if isinstance(completed_value, list)
            else []
        )
        backup_value = raw.get('backups', [])
        backups: list[BackupRecord] = []
        if isinstance(backup_value, list):
            for item in backup_value:
                if isinstance(item, dict) and all(
                    isinstance(key, str) for key in item
                ):
                    backups.append(
                        BackupRecord.from_dict(cast(dict[str, object], item))
                    )
        verification_value = raw.get('verification', {})
        verification = (
            cast(dict[str, object], verification_value)
            if isinstance(verification_value, dict)
            and all(isinstance(key, str) for key in verification_value)
            else {}
        )
        return cls(
            migration_id=str(raw.get('migration_id', '')),
            plan_sha256=str(raw.get('plan_sha256', '')),
            target_machine_store=str(raw.get('target_machine_store', '')),
            sources=sources,
            status=cast(MigrationStatus, status),
            completed_steps=completed,
            backups=backups,
            error=str(raw.get('error', '')),
            verification=verification,
            created_at=str(raw.get('created_at', '')),
            updated_at=str(raw.get('updated_at', '')),
        )

    def render_text(self) -> str:
        lines = [
            f'Migration: {self.migration_id}',
            f'Status: {self.status}',
            f'Target: {self.target_machine_store}',
            f'Completed steps: {len(self.completed_steps)}/{len(_APPLY_STEPS)}',
        ]
        for step in self.completed_steps:
            lines.append(f'  - {step}')
        if self.error:
            lines.append(f'Error: {self.error}')
        if self.verification:
            lines.append(
                'Verification: '
                + str(self.verification.get('status', 'unknown'))
            )
        lines.append(f'Updated: {self.updated_at}')
        return '\n'.join(lines) + '\n'


@dataclass(frozen=True)
class MigrationApplyResult:
    """Result returned by apply, verify, or rollback services."""

    journal: MigrationJournal
    transaction_dir: Path
    resumed: bool = False


GuestInstaller = Callable[[str, AgentVMConfig, MachineStoreLayout], None]
RuntimeVerifier = Callable[
    [MigrationPlan, MachineStoreLayout], dict[str, object]
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise MigrationExecutionError('Expected a JSON object')
    return cast(dict[str, object], value)


def _object_int(value: object, *, default: int = -1) -> int:
    """Convert a validated JSON scalar to int without broad object casts."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _object_dict_list(value: object) -> list[dict[str, object]]:
    """Narrow one JSON-like value to string-keyed object dictionaries."""
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            result.append(cast(dict[str, object], item))
    return result


def _atomic_write_text(
    path: Path,
    text: str,
    mode: int = 0o664,
    *,
    policy: StoreFilesystemPolicy | None = None,
) -> None:
    if policy is None:
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        ensure_store_directory(path.parent, policy)
    with tempfile.NamedTemporaryFile(
        'w',
        encoding='utf-8',
        dir=path.parent,
        prefix=f'.{path.name}.',
        delete=False,
    ) as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
        tmp = Path(file.name)
    try:
        os.chmod(tmp, mode)
        if policy is not None and policy.group_gid is not None:
            os.chown(tmp, -1, policy.group_gid)
        os.replace(tmp, path)
        if policy is None:
            os.chmod(path, mode)
        else:
            apply_store_file_policy(
                path,
                StoreFilesystemPolicy(
                    managed_root=policy.managed_root,
                    directory_mode=policy.directory_mode,
                    file_mode=mode,
                    group_gid=policy.group_gid,
                    reject_symlinks=policy.reject_symlinks,
                ),
            )
    finally:
        tmp.unlink(missing_ok=True)


def _write_json(
    path: Path,
    payload: dict[str, object],
    mode: int = 0o664,
    *,
    policy: StoreFilesystemPolicy | None = None,
) -> None:
    _atomic_write_text(
        path,
        json.dumps(payload, indent=2, sort_keys=True) + '\n',
        mode,
        policy=policy,
    )


def _read_json(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as ex:
        raise MigrationExecutionError(
            f'Could not read migration state {path}: {ex}'
        ) from ex
    return _json_object(raw)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(path: Path) -> str:
    if path.is_file():
        info = path.stat()
        digest = hashlib.sha256()
        digest.update(str(info.st_mode & 0o7777).encode('ascii') + b'\0')
        digest.update(str(info.st_uid).encode('ascii') + b'\0')
        digest.update(str(info.st_gid).encode('ascii') + b'\0')
        digest.update(_file_sha256(path).encode('ascii'))
        return digest.hexdigest()
    digest = hashlib.sha256()
    root_info = path.stat()
    digest.update(str(root_info.st_mode & 0o7777).encode('ascii') + b'\0')
    digest.update(str(root_info.st_uid).encode('ascii') + b'\0')
    digest.update(str(root_info.st_gid).encode('ascii') + b'\0')
    for item in sorted(path.rglob('*')):
        rel = item.relative_to(path).as_posix()
        info = item.lstat()
        if item.is_symlink():
            raise MigrationExecutionError(
                f'Migration refuses symlinked input or target: {item}'
            )
        digest.update(rel.encode('utf-8') + b'\0')
        digest.update(str(info.st_mode & 0o7777).encode('ascii') + b'\0')
        digest.update(str(info.st_uid).encode('ascii') + b'\0')
        digest.update(str(info.st_gid).encode('ascii') + b'\0')
        if item.is_file():
            digest.update(_file_sha256(item).encode('ascii'))
    return digest.hexdigest()


def _tree_content_sha256(path: Path) -> str:
    """Hash relative paths and bytes while allowing destination mode policy."""
    if path.is_file():
        return _file_sha256(path)
    digest = hashlib.sha256()
    for item in sorted(path.rglob('*')):
        if item.is_symlink():
            raise MigrationExecutionError(
                f'Migration refuses symlinked input or target: {item}'
            )
        rel = item.relative_to(path).as_posix()
        digest.update(rel.encode('utf-8') + b'\0')
        digest.update(b'd' if item.is_dir() else b'f')
        if item.is_file():
            digest.update(_file_sha256(item).encode('ascii'))
    return digest.hexdigest()


def _plan_fingerprint_payload(plan: MigrationPlan) -> dict[str, object]:
    report = plan.to_dict()
    proposed = report.get('proposed', {})
    return {
        'plan_schema_version': report.get('plan_schema_version', 0),
        'target_machine_store': report.get('target_machine_store', ''),
        'sources': report.get('sources', []),
        'proposed': proposed,
    }


def migration_plan_sha256(plan: MigrationPlan) -> str:
    payload = json.dumps(
        _plan_fingerprint_payload(plan),
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def migration_id_for_plan(plan: MigrationPlan) -> str:
    return 'migration-' + migration_plan_sha256(plan)[:16]


def migration_root(layout: MachineStoreLayout | None = None) -> Path:
    selected = layout or machine_store_layout()
    return selected.state_dir / 'migrations'


def migration_transaction_dir(
    migration_id: str, layout: MachineStoreLayout | None = None
) -> Path:
    suffix = migration_id.removeprefix('migration-')
    if (
        not migration_id.startswith('migration-')
        or len(suffix) != 16
        or not all(char in '0123456789abcdef' for char in suffix)
    ):
        raise MigrationExecutionError(f'Invalid migration id: {migration_id!r}')
    return migration_root(layout) / migration_id


def _journal_path(transaction_dir: Path) -> Path:
    return transaction_dir / 'state.json'


def _plan_path(transaction_dir: Path) -> Path:
    return transaction_dir / 'plan.json'


def _expected_dir(transaction_dir: Path) -> Path:
    return transaction_dir / 'expected'


def _transaction_layout(transaction_dir: Path) -> MachineStoreLayout:
    try:
        root = transaction_dir.parents[2]
    except IndexError as ex:
        raise MigrationExecutionError(
            f'Invalid migration transaction path: {transaction_dir}'
        ) from ex
    return MachineStoreLayout.from_root(root)


def _transaction_policy(transaction_dir: Path) -> StoreFilesystemPolicy:
    return current_machine_store_policy(_transaction_layout(transaction_dir))


def _save_journal(transaction_dir: Path, journal: MigrationJournal) -> None:
    journal.updated_at = _utc_now()
    _write_json(
        _journal_path(transaction_dir),
        journal.to_dict(),
        policy=_transaction_policy(transaction_dir),
    )


def load_migration_journal(
    migration_id: str, *, layout: MachineStoreLayout | None = None
) -> MigrationApplyResult:
    tx = migration_transaction_dir(migration_id, layout)
    journal = MigrationJournal.from_dict(_read_json(_journal_path(tx)))
    return MigrationApplyResult(journal=journal, transaction_dir=tx)


def list_migration_ids(
    *, layout: MachineStoreLayout | None = None
) -> list[str]:
    root = migration_root(layout)
    if not root.is_dir():
        return []
    rows: list[tuple[float, str]] = []
    for path in root.glob('migration-*'):
        state = _journal_path(path)
        if path.is_dir() and state.is_file():
            rows.append((state.stat().st_mtime, path.name))
    return [name for _mtime, name in sorted(rows, reverse=True)]


def latest_migration_id(*, layout: MachineStoreLayout | None = None) -> str:
    ids = list_migration_ids(layout=layout)
    if not ids:
        raise MigrationExecutionError('No migration journal exists.')
    return ids[0]


def _source_rows_to_objects(
    rows: list[dict[str, object]],
) -> list[LegacyStoreSource]:
    return [
        LegacyStoreSource(
            path=Path(str(row.get('path', ''))).expanduser().resolve(),
            host_user=str(row.get('host_user', '')),
            host_uid=_object_int(row.get('host_uid', -1)),
            host_gid=_object_int(row.get('host_gid', -1)),
            home=Path(str(row.get('home', ''))).expanduser().resolve(),
        )
        for row in rows
    ]


def sources_from_journal(journal: MigrationJournal) -> list[LegacyStoreSource]:
    return _source_rows_to_objects(journal.sources)


def _verify_source_hashes(plan: MigrationPlan) -> None:
    changed: list[str] = []
    for source in plan.sources:
        files = source.get('files', [])
        if not isinstance(files, list):
            continue
        for item in files:
            if not isinstance(item, dict):
                continue
            path = Path(str(item.get('path', '')))
            expected = str(item.get('sha256', ''))
            if not path.is_file() or _file_sha256(path) != expected:
                changed.append(str(path))
    if changed:
        raise MigrationExecutionError(
            'Released-store inputs changed after planning; rebuild and review '
            'the plan before applying:\n  ' + '\n  '.join(sorted(changed))
        )


def _backup_path_for(original: Path, backup_root: Path) -> Path:
    digest = hashlib.sha256(str(original).encode('utf-8')).hexdigest()[:16]
    name = original.name or 'root'
    return backup_root / f'{digest}-{name}'


def _preserve_owner(source: Path, target: Path) -> None:
    source_info = source.stat()
    target_info = target.stat()
    if (target_info.st_uid, target_info.st_gid) == (
        source_info.st_uid,
        source_info.st_gid,
    ):
        return
    try:
        os.chown(target, source_info.st_uid, source_info.st_gid)
    except PermissionError as ex:
        raise MigrationExecutionError(
            f'Could not preserve ownership for {source} -> {target}'
        ) from ex


def _preserve_tree_owners(source: Path, target: Path) -> None:
    _preserve_owner(source, target)
    if source.is_dir():
        for item in sorted(source.rglob('*')):
            _preserve_owner(item, target / item.relative_to(source))


def _copy_path(source: Path, target: Path) -> None:
    if source.is_symlink():
        raise MigrationExecutionError(
            f'Refusing symlinked migration path: {source}'
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target, copy_function=shutil.copy2)
    elif source.is_file():
        shutil.copy2(source, target)
    else:
        raise MigrationExecutionError(
            f'Unsupported migration path type: {source}'
        )
    _preserve_tree_owners(source, target)


def _remove_path(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _backup_one(
    path: Path,
    *,
    role: str,
    disposition: BackupDisposition,
    backup_root: Path,
) -> BackupRecord:
    original = path.expanduser().resolve()
    backup = _backup_path_for(original, backup_root)
    if not original.exists():
        return BackupRecord(
            original=str(original),
            backup=str(backup),
            role=role,
            existed=False,
            kind='missing',
            disposition=disposition,
        )
    if original.is_symlink():
        raise MigrationExecutionError(
            f'Refusing symlinked migration path: {original}'
        )
    kind: Literal['file', 'directory'] = (
        'directory' if original.is_dir() else 'file'
    )
    digest = _tree_sha256(original)
    _copy_path(original, backup)
    if _tree_sha256(backup) != digest:
        raise MigrationExecutionError(
            f'Backup verification failed for {original}'
        )
    return BackupRecord(
        original=str(original),
        backup=str(backup),
        role=role,
        existed=True,
        kind=kind,
        sha256=digest,
        disposition=disposition,
    )


def _machine_target_paths(
    plan: MigrationPlan,
) -> list[tuple[Path, str, BackupDisposition]]:
    store = plan.proposed_store
    if store is None:
        raise MigrationExecutionError(
            'Migration plan lacks apply-phase machine data.'
        )
    targets = split_fragment_paths(store, plan.target_machine_store)
    paths: list[tuple[Path, str, BackupDisposition]] = [
        (targets['root'], 'target-machine-root', 'restore_on_rollback'),
        (
            targets['defaults'],
            'target-machine-defaults',
            'restore_on_rollback',
        ),
        (
            targets['networks'],
            'target-machine-networks',
            'restore_on_rollback',
        ),
        (
            plan.target_machine_store.parent / 'vms',
            'target-machine-vms',
            'restore_on_rollback',
        ),
    ]
    return paths


def _backup_candidates(
    plan: MigrationPlan,
    layout: MachineStoreLayout,
) -> list[tuple[Path, str, BackupDisposition]]:
    candidates: list[tuple[Path, str, BackupDisposition]] = []
    for source in plan.sources:
        files = source.get('files', [])
        if isinstance(files, list):
            for item in files:
                if isinstance(item, dict):
                    candidates.append(
                        (
                            Path(str(item.get('path', ''))),
                            'legacy-store-input',
                            'evidence_only',
                        )
                    )
    candidates.extend(_machine_target_paths(plan))
    for profile in plan.profiles:
        candidates.append(
            (
                Path(str(profile.get('path', ''))),
                'profile-target',
                'restore_on_rollback',
            )
        )
    for move in plan.credential_material_moves:
        # Private source material is retained in place and fingerprinted rather
        # than duplicated into the shared migration journal. Only a pre-existing
        # replacement target needs a protected rollback copy.
        candidates.append(
            (
                Path(str(move.get('target', ''))),
                'private-credential-target',
                'restore_on_rollback',
            )
        )
    for move in plan.persistent_state_moves:
        candidates.append(
            (
                Path(str(move.get('source', ''))),
                'persistent-input',
                'evidence_only',
            )
        )
        candidates.append(
            (
                Path(str(move.get('target', ''))),
                'persistent-target',
                'restore_on_rollback',
            )
        )
    for vm_name in sorted(plan.legacy_vm_cfgs):
        from ...enrollment import bootstrap_identity_paths

        candidates.append(
            (
                bootstrap_identity_paths(vm_name, layout=layout).directory,
                'private-bootstrap-target',
                'restore_on_rollback',
            )
        )
    # Deduplicate exact paths while retaining the first, most specific role.
    result: list[tuple[Path, str, BackupDisposition]] = []
    seen: set[Path] = set()
    for path, role, disposition in candidates:
        normalized = path.expanduser().resolve()
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append((normalized, role, disposition))
    return result


def _create_backups(
    plan: MigrationPlan,
    transaction_dir: Path,
    layout: MachineStoreLayout,
) -> list[BackupRecord]:
    policy = _transaction_policy(transaction_dir)
    root = ensure_store_directory(transaction_dir / 'backups', policy)
    private_root = transaction_dir / 'backups-private'
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private_root, 0o700)
    return [
        _backup_one(
            path,
            role=role,
            disposition=disposition,
            backup_root=(private_root if role.startswith('private-') else root),
        )
        for path, role, disposition in _backup_candidates(plan, layout)
    ]


def _freeze_expected(plan: MigrationPlan, transaction_dir: Path) -> None:
    store = plan.proposed_store
    if store is None:
        raise MigrationExecutionError(
            'Migration plan lacks proposed machine store.'
        )
    policy = _transaction_policy(transaction_dir)
    expected = ensure_store_directory(_expected_dir(transaction_dir), policy)
    _atomic_write_text(
        expected / 'machine.toml',
        render_store_toml(store),
        policy=policy,
    )
    profile_dir = ensure_store_directory(expected / 'profiles', policy)
    profile_index: list[dict[str, object]] = []
    for proposal in plan.profiles:
        host_user = str(proposal.get('host_user', ''))
        profile = plan.proposed_profiles.get(host_user)
        if profile is None:
            raise MigrationExecutionError(
                f'Migration plan lacks profile material for {host_user!r}'
            )
        name = (
            hashlib.sha256(host_user.encode('utf-8')).hexdigest()[:16] + '.toml'
        )
        _atomic_write_text(
            profile_dir / name,
            render_user_profile(profile),
            policy=policy,
        )
        profile_index.append(
            {
                'host_user': host_user,
                'path': str(proposal.get('path', '')),
                'expected': str(profile_dir / name),
                'host_uid': _object_int(
                    next(
                        row.get('host_uid', -1)
                        for row in plan.sources
                        if str(row.get('host_user', '')) == host_user
                    )
                ),
                'host_gid': _object_int(
                    next(
                        row.get('host_gid', -1)
                        for row in plan.sources
                        if str(row.get('host_user', '')) == host_user
                    )
                ),
            }
        )
    _write_json(
        expected / 'profiles.json',
        {'profiles': profile_index},
        policy=policy,
    )


def _step_complete(journal: MigrationJournal, step: str) -> bool:
    return step in journal.completed_steps


def _mark_step(
    transaction_dir: Path, journal: MigrationJournal, step: str
) -> None:
    if step not in journal.completed_steps:
        journal.completed_steps.append(step)
    journal.status = 'applying'
    journal.error = ''
    _save_journal(transaction_dir, journal)


def _capture_migration_outputs(
    journal: MigrationJournal,
    roles: set[str],
) -> None:
    """Record the exact target state produced by one completed apply phase."""
    updated: list[BackupRecord] = []
    for record in journal.backups:
        if record.role not in roles:
            updated.append(record)
            continue
        path = Path(record.original)
        if path.is_symlink():
            raise MigrationExecutionError(
                f'Refusing symlinked migration output: {path}'
            )
        if path.exists():
            updated.append(
                replace(
                    record,
                    applied_existed=True,
                    applied_sha256=_tree_sha256(path),
                )
            )
        else:
            updated.append(
                replace(
                    record,
                    applied_existed=False,
                    applied_sha256='',
                )
            )
    journal.backups = updated


def _write_machine_store(
    plan: MigrationPlan, layout: MachineStoreLayout
) -> None:
    store = plan.proposed_store
    if store is None:
        raise MigrationExecutionError(
            'Migration plan lacks proposed machine store.'
        )
    ensure_machine_store_layout(layout, group_gid=current_machine_group_gid())
    save_store_split(
        store,
        layout.config_path,
        reason='migrate released per-user store into machine authority',
        io_policy=current_machine_store_policy(layout),
    )


def _write_profiles(plan: MigrationPlan) -> None:
    source_by_user = {
        str(item.get('host_user', '')): item for item in plan.sources
    }
    for proposal in plan.profiles:
        host_user = str(proposal.get('host_user', ''))
        target = Path(str(proposal.get('path', ''))).expanduser().resolve()
        profile = plan.proposed_profiles.get(host_user)
        if profile is None:
            raise MigrationExecutionError(
                f'Migration plan lacks profile material for {host_user!r}'
            )
        source = source_by_user.get(host_user, {})
        uid = _object_int(source.get('host_uid', -1))
        gid = _object_int(source.get('host_gid', -1))
        if os.geteuid() != 0 and uid not in {-1, os.geteuid()}:
            raise MigrationExecutionError(
                f'Writing profile for host user {host_user!r} requires root; '
                f'target is {target}. Re-run the migration with sudo while '
                'preserving the explicit source specifications.'
            )
        save_user_profile(profile, target)
        if os.geteuid() == 0 and uid >= 0 and gid >= 0:
            os.chown(target.parent, uid, gid)
            os.chown(target, uid, gid)


def _copy_tree_if_needed(source: Path, target: Path) -> None:
    if not source.exists():
        return
    if source.is_symlink() or target.is_symlink():
        raise MigrationExecutionError(
            f'Refusing symlinked migration source or target: {source} -> {target}'
        )
    source_digest = _tree_sha256(source)
    if target.exists():
        if _tree_sha256(target) == source_digest:
            return
        raise MigrationExecutionError(
            f'Migration target already exists with different content: {target}'
        )
    _copy_path(source, target)
    if _tree_sha256(target) != source_digest:
        raise MigrationExecutionError(
            f'Copied migration data failed verification: {source} -> {target}'
        )


def _copy_credential_material(plan: MigrationPlan) -> None:
    for move in plan.credential_material_moves:
        _copy_tree_if_needed(
            Path(str(move.get('source', ''))),
            Path(str(move.get('target', ''))),
        )


def _apply_machine_state_policy(
    target: Path, layout: MachineStoreLayout
) -> None:
    policy = current_machine_store_policy(layout)
    if target.is_dir():
        ensure_store_directory(target, policy)
        for item in sorted(target.rglob('*')):
            if item.is_dir():
                ensure_store_directory(item, policy)
            elif item.is_file():
                apply_store_file_policy(item, policy)
    elif target.is_file():
        ensure_store_directory(target.parent, policy)
        apply_store_file_policy(target, policy)


def _copy_persistent_state(
    plan: MigrationPlan, layout: MachineStoreLayout
) -> None:
    for move in plan.persistent_state_moves:
        source = Path(str(move.get('source', '')))
        target = Path(str(move.get('target', '')))
        if not source.exists():
            continue
        if target.exists():
            if _tree_content_sha256(target) != _tree_content_sha256(source):
                raise MigrationExecutionError(
                    f'Migration target already exists with different content: {target}'
                )
        else:
            _copy_path(source, target)
        _apply_machine_state_policy(target, layout)
        if _tree_content_sha256(target) != _tree_content_sha256(source):
            raise MigrationExecutionError(
                f'Copied migration data failed verification: {source} -> {target}'
            )


def _guest_install_script(public_key: str) -> str:
    restricted = restricted_bootstrap_authorized_key(public_key)
    guestctl_b64 = base64.b64encode(guestctl_source().encode('utf-8')).decode(
        'ascii'
    )
    key_b64 = base64.b64encode((restricted + '\n').encode('utf-8')).decode(
        'ascii'
    )
    sudoers = (
        f'{BOOTSTRAP_GUEST_USER} ALL=(root) NOPASSWD: '
        f'{GUESTCTL_PATH} --forced\n'
    )
    sudoers_b64 = base64.b64encode(sudoers.encode('utf-8')).decode('ascii')
    user_q = shlex.quote(BOOTSTRAP_GUEST_USER)
    home_q = shlex.quote(f'/var/lib/{BOOTSTRAP_GUEST_USER}')
    auth_q = shlex.quote(
        f'/var/lib/{BOOTSTRAP_GUEST_USER}/.ssh/authorized_keys'
    )
    key_parts = public_key.split()
    if len(key_parts) < 2:
        raise MigrationExecutionError('Malformed bootstrap public key')
    payload_q = shlex.quote(key_parts[1])
    return f"""set -euo pipefail
if ! getent group {user_q} >/dev/null 2>&1; then
    groupadd --system {user_q}
fi
if ! id -u {user_q} >/dev/null 2>&1; then
    useradd --system --gid {user_q} --home-dir {home_q} --create-home --shell /bin/bash {user_q}
fi
install -d -m 0700 -o {user_q} -g {user_q} {home_q}/.ssh
printf %s {shlex.quote(key_b64)} | base64 -d > {auth_q}
chown {user_q}:{user_q} {auth_q}
chmod 0600 {auth_q}
printf %s {shlex.quote(guestctl_b64)} | base64 -d > {shlex.quote(GUESTCTL_PATH)}
chmod 0755 {shlex.quote(GUESTCTL_PATH)}
printf %s {shlex.quote(sudoers_b64)} | base64 -d > {shlex.quote(BOOTSTRAP_SUDOERS_PATH)}
chmod 0440 {shlex.quote(BOOTSTRAP_SUDOERS_PATH)}
visudo -cf {shlex.quote(BOOTSTRAP_SUDOERS_PATH)} >/dev/null
test -x {shlex.quote(GUESTCTL_PATH)}
grep -Fq {payload_q} {auth_q}
"""


def install_bootstrap_through_legacy_access(
    vm_name: str,
    cfg: AgentVMConfig,
    layout: MachineStoreLayout,
) -> None:
    """Install the restricted bootstrap helper through existing creator SSH."""
    identity = ensure_bootstrap_identity(vm_name, layout=layout)
    private_key = require_ssh_identity(cfg.paths.ssh_identity_file)
    ip = wait_for_ip(cfg)
    target = f'{cfg.vm.user}@{ip}'
    script = _guest_install_script(identity.public_key)
    cmd = [
        'ssh',
        *ssh_base_args(
            private_key,
            strict_host_key_checking='accept-new',
        ),
        target,
        'sudo',
        '-n',
        'bash',
        '-s',
    ]
    result = CommandManager.current().run(
        cmd,
        role='modify',
        input_text=script,
        check=False,
        capture=True,
        summary=f'Install restricted enrollment helper in {vm_name}',
        detail='Uses the already-working legacy guest identity; no VM is recreated.',
    )
    if result.code != 0:
        detail = (
            result.stderr or result.stdout or 'guest installation failed'
        ).strip()
        raise MigrationExecutionError(
            f'Could not install bootstrap helper in {vm_name!r}: {detail}'
        )


def _install_bootstrap(
    plan: MigrationPlan,
    layout: MachineStoreLayout,
    installer: GuestInstaller,
) -> None:
    for vm_name, cfg in sorted(plan.legacy_vm_cfgs.items()):
        installer(vm_name, cfg, layout)


def verify_migration_local(
    plan: MigrationPlan,
    layout: MachineStoreLayout,
) -> dict[str, object]:
    """Verify source immutability and every host-side migrated artifact."""
    _verify_source_hashes(plan)
    expected_store = plan.proposed_store
    if expected_store is None:
        raise MigrationExecutionError(
            'Migration plan lacks proposed machine store.'
        )
    actual_store = load_store(
        layout.config_path,
        io_policy=current_machine_store_policy(layout),
    )
    if render_store_toml(actual_store) != render_store_toml(expected_store):
        raise MigrationExecutionError(
            'Machine-store verification failed: persisted logical state differs '
            'from the reviewed migration plan.'
        )
    for proposal in plan.profiles:
        host_user = str(proposal.get('host_user', ''))
        expected = plan.proposed_profiles.get(host_user)
        if expected is None:
            raise MigrationExecutionError(
                f'Missing expected profile for {host_user!r}'
            )
        actual = load_user_profile(Path(str(proposal.get('path', ''))))
        if render_user_profile(actual) != render_user_profile(expected):
            raise MigrationExecutionError(
                f'Profile verification failed for {host_user!r}'
            )
    copied_credentials = 0
    for move in plan.credential_material_moves:
        source = Path(str(move.get('source', '')))
        target = Path(str(move.get('target', '')))
        if source.exists():
            if not target.exists() or _tree_sha256(source) != _tree_sha256(
                target
            ):
                raise MigrationExecutionError(
                    f'Credential material verification failed: {source} -> {target}'
                )
            copied_credentials += 1
    copied_state = 0
    for move in plan.persistent_state_moves:
        source = Path(str(move.get('source', '')))
        target = Path(str(move.get('target', '')))
        if source.exists():
            if not target.exists() or _tree_content_sha256(
                source
            ) != _tree_content_sha256(target):
                raise MigrationExecutionError(
                    f'Persistent state verification failed: {source} -> {target}'
                )
            copied_state += 1
    return {
        'status': 'passed',
        'source_files': sum(
            len(files)
            for item in plan.sources
            for files in [item.get('files', [])]
            if isinstance(files, list)
        ),
        'machine_fragments': len(split_source_paths(layout.config_path)),
        'profiles': len(plan.profiles),
        'credential_material_copies': copied_credentials,
        'persistent_state_copies': copied_state,
    }


def verify_migration_runtime(
    plan: MigrationPlan,
    layout: MachineStoreLayout,
    *,
    runtime_sudo: bool = False,
) -> dict[str, object]:
    """Verify libvirt identity and creator SSH without mutating runtime state."""
    inventory: RuntimeInventory = collect_runtime_inventory(
        managed_vms=sorted(plan.legacy_vm_cfgs),
        managed_networks=[
            str(item.get('name', ''))
            for item in _object_dict_list(plan.machine.get('networks', []))
        ],
        sudo=runtime_sudo,
    )
    if inventory.error:
        raise MigrationExecutionError(
            f'Runtime verification could not inspect libvirt: {inventory.error}'
        )
    if inventory.missing_domains:
        raise MigrationExecutionError(
            'Runtime verification is missing managed domains: '
            + ', '.join(inventory.missing_domains)
        )
    ssh_verified: list[str] = []
    for vm_name, cfg in sorted(plan.legacy_vm_cfgs.items()):
        private_key = require_ssh_identity(cfg.paths.ssh_identity_file)
        ip = wait_for_ip(cfg)
        result = CommandManager.current().run(
            [
                'ssh',
                *ssh_base_args(
                    private_key, strict_host_key_checking='accept-new'
                ),
                f'{cfg.vm.user}@{ip}',
                'true',
            ],
            role='read',
            check=False,
            capture=True,
        )
        if result.code != 0:
            raise MigrationExecutionError(
                f'Creator SSH verification failed for {vm_name!r}: '
                f'{(result.stderr or result.stdout).strip()}'
            )
        ssh_verified.append(vm_name)
    return {
        'status': 'passed',
        'domains': sorted(plan.legacy_vm_cfgs),
        'creator_ssh_verified': ssh_verified,
    }


def apply_migration(
    plan: MigrationPlan,
    *,
    layout: MachineStoreLayout | None = None,
    guest_installer: GuestInstaller = install_bootstrap_through_legacy_access,
    runtime_verifier: RuntimeVerifier = verify_migration_runtime,
    fail_after_step: str = '',
) -> MigrationApplyResult:
    """Apply or resume one ready migration plan."""
    layout = layout or machine_store_layout(plan.target_machine_store.parent)
    planned_target = plan.target_machine_store.expanduser().resolve()
    actual_target = layout.config_path.expanduser().resolve()
    if planned_target != actual_target:
        raise MigrationExecutionError(
            'Migration layout does not match the reviewed target: '
            f'plan={planned_target}, layout={actual_target}'
        )
    if plan.blocked:
        codes = ', '.join(item.code for item in plan.conflicts)
        raise MigrationExecutionError(
            f'Migration plan is blocked and cannot be applied: {codes}'
        )
    if plan.proposed_store is None:
        raise MigrationExecutionError(
            'Migration plan was deserialized without apply-phase material; '
            'rebuild it from the released sources.'
        )
    _verify_source_hashes(plan)
    ensure_machine_store_layout(layout, group_gid=current_machine_group_gid())
    migration_id = migration_id_for_plan(plan)
    tx = migration_transaction_dir(migration_id, layout)
    policy = current_machine_store_policy(layout)
    ensure_store_directory(tx, policy)
    state_path = _journal_path(tx)
    resumed = state_path.exists()
    plan_sha = migration_plan_sha256(plan)
    if resumed:
        journal = MigrationJournal.from_dict(_read_json(state_path))
        if journal.plan_sha256 != plan_sha:
            raise MigrationExecutionError(
                'Existing migration journal does not match the current plan.'
            )
        if journal.status == 'complete':
            verification = verify_migration_local(plan, layout)
            verification['runtime'] = runtime_verifier(plan, layout)
            journal.verification = verification
            _save_journal(tx, journal)
            return MigrationApplyResult(
                journal=journal, transaction_dir=tx, resumed=True
            )
        if journal.status == 'rolled-back':
            raise MigrationExecutionError(
                f'Migration {migration_id} was rolled back; create and review a '
                'fresh plan before applying again.'
            )
        journal.status = 'applying'
        journal.error = ''
    else:
        journal = MigrationJournal(
            migration_id=migration_id,
            plan_sha256=plan_sha,
            target_machine_store=str(layout.config_path),
            sources=plan.sources,
        )
        _write_json(_plan_path(tx), plan.to_dict(), policy=policy)
        _freeze_expected(plan, tx)
        _save_journal(tx, journal)

    def run_step(
        name: str,
        action: Callable[[], None],
        *,
        output_roles: set[str] | None = None,
    ) -> None:
        if _step_complete(journal, name):
            return
        action()
        if output_roles:
            _capture_migration_outputs(journal, output_roles)
            _save_journal(tx, journal)
        _mark_step(tx, journal, name)
        if fail_after_step == name:
            raise MigrationExecutionError(
                f'Injected migration interruption after {name}'
            )

    try:

        def backups_action() -> None:
            journal.backups = _create_backups(plan, tx, layout)
            _save_journal(tx, journal)

        run_step('backups-created', backups_action)
        run_step(
            'machine-store-written',
            lambda: _write_machine_store(plan, layout),
            output_roles={
                'target-machine-root',
                'target-machine-defaults',
                'target-machine-networks',
                'target-machine-vms',
            },
        )
        run_step(
            'profiles-written',
            lambda: _write_profiles(plan),
            output_roles={'profile-target'},
        )
        run_step(
            'credential-material-copied',
            lambda: _copy_credential_material(plan),
            output_roles={'private-credential-target'},
        )
        run_step(
            'persistent-state-copied',
            lambda: _copy_persistent_state(plan, layout),
            output_roles={'persistent-target'},
        )
        run_step(
            'bootstrap-installed',
            lambda: _install_bootstrap(plan, layout, guest_installer),
            output_roles={'private-bootstrap-target'},
        )

        def verify_action() -> None:
            verification = verify_migration_local(plan, layout)
            verification['runtime'] = runtime_verifier(plan, layout)
            journal.verification = verification
            _save_journal(tx, journal)

        run_step('verified', verify_action)
        journal.status = 'complete'
        journal.error = ''
        _save_journal(tx, journal)
    except Exception as ex:
        journal.status = 'failed'
        journal.error = str(ex)
        _save_journal(tx, journal)
        if isinstance(ex, MigrationExecutionError):
            raise
        raise MigrationExecutionError(str(ex)) from ex
    return MigrationApplyResult(
        journal=journal, transaction_dir=tx, resumed=resumed
    )


def rebuild_plan_from_journal(
    journal: MigrationJournal,
    *,
    layout: MachineStoreLayout,
    check_runtime: bool = True,
    runtime_sudo: bool = False,
) -> MigrationPlan:
    plan = build_migration_plan(
        sources_from_journal(journal),
        layout=layout,
        check_runtime=check_runtime,
        runtime_sudo=runtime_sudo,
    )
    # A resumed migration is expected to find the machine store written by an
    # earlier phase. Suppress only the generic non-empty-target conflict when
    # the actual logical store is byte-for-byte the reviewed proposal.
    if plan.proposed_store is not None and split_source_paths(
        layout.config_path
    ):
        try:
            actual = load_store(
                layout.config_path,
                io_policy=current_machine_store_policy(layout),
            )
        except Exception:
            pass
        else:
            if render_store_toml(actual) == render_store_toml(
                plan.proposed_store
            ):
                plan.conflicts = [
                    item
                    for item in plan.conflicts
                    if item.code != 'target-store-not-empty'
                ]
    if migration_plan_sha256(plan) != journal.plan_sha256:
        raise MigrationExecutionError(
            'Released inputs or planner output changed since the migration '
            'journal was created. Roll back or inspect the frozen plan instead '
            'of resuming with different state.'
        )
    return plan


def verify_applied_migration(
    migration_id: str,
    *,
    layout: MachineStoreLayout | None = None,
    runtime_verifier: RuntimeVerifier = verify_migration_runtime,
) -> MigrationApplyResult:
    layout = layout or machine_store_layout()
    loaded = load_migration_journal(migration_id, layout=layout)
    journal = loaded.journal
    if journal.status not in {'complete', 'failed', 'applying'}:
        raise MigrationExecutionError(
            f'Migration {migration_id} is {journal.status!r}, not applied.'
        )
    plan = rebuild_plan_from_journal(
        journal, layout=layout, check_runtime=False
    )
    verification = verify_migration_local(plan, layout)
    verification['runtime'] = runtime_verifier(plan, layout)
    journal.verification = verification
    if set(_APPLY_STEPS).issubset(journal.completed_steps):
        journal.status = 'complete'
        journal.error = ''
    _save_journal(loaded.transaction_dir, journal)
    return MigrationApplyResult(
        journal=journal, transaction_dir=loaded.transaction_dir, resumed=True
    )


RollbackAction = Literal['noop', 'restore']


def _current_backup_path_state(path: Path) -> tuple[bool, str]:
    if path.is_symlink():
        raise MigrationExecutionError(
            f'Refusing symlinked rollback target: {path}'
        )
    if not path.exists():
        return False, ''
    return True, _tree_sha256(path)


def _state_matches(
    current: tuple[bool, str],
    *,
    existed: bool,
    sha256: str,
) -> bool:
    current_existed, current_sha256 = current
    if current_existed != existed:
        return False
    return not existed or current_sha256 == sha256


def _classify_rollback_target(record: BackupRecord) -> RollbackAction:
    """Prove whether one target is untouched or still migration-produced."""
    original = Path(record.original)
    current = _current_backup_path_state(original)
    if _state_matches(
        current,
        existed=record.existed,
        sha256=record.sha256,
    ):
        return 'noop'
    if record.applied_existed is None:
        raise MigrationExecutionError(
            f'Rollback cannot prove that the current contents of {original} '
            'were produced by migration. The apply phase may have failed '
            'partway through this target; preserve it for manual recovery.'
        )
    if not _state_matches(
        current,
        existed=record.applied_existed,
        sha256=record.applied_sha256,
    ):
        raise MigrationExecutionError(
            f'Rollback target changed after migration wrote it: {original}. '
            'Refusing to overwrite concurrent or operator changes.'
        )
    if record.existed:
        backup = Path(record.backup)
        if not backup.exists():
            raise MigrationExecutionError(
                f'Migration backup is missing: {backup}'
            )
        if record.sha256 and _tree_sha256(backup) != record.sha256:
            raise MigrationExecutionError(
                f'Migration backup changed after creation: {backup}'
            )
    return 'restore'


def rollback_migration(
    migration_id: str,
    *,
    layout: MachineStoreLayout | None = None,
) -> MigrationApplyResult:
    """Restore migration-owned targets without rewriting retained inputs."""
    layout = layout or machine_store_layout()
    loaded = load_migration_journal(migration_id, layout=layout)
    journal = loaded.journal
    if journal.status == 'rolled-back':
        return loaded
    try:
        # Preflight every target before mutating any of them. This avoids a
        # partially completed rollback merely because a later target contains
        # concurrent or operator changes.
        actions: list[tuple[BackupRecord, RollbackAction]] = []
        for record in reversed(journal.backups):
            if record.disposition == 'evidence_only':
                continue
            actions.append((record, _classify_rollback_target(record)))

        for record, action in actions:
            if action == 'noop':
                continue
            # Close the preflight-to-write window as much as practical. If the
            # target changed after global preflight, stop before replacing it.
            if _classify_rollback_target(record) == 'noop':
                continue
            original = Path(record.original)
            backup = Path(record.backup)
            _remove_path(original)
            if record.existed:
                _copy_path(backup, original)
                if record.sha256 and _tree_sha256(original) != record.sha256:
                    raise MigrationExecutionError(
                        f'Rollback verification failed for {original}'
                    )
        journal.status = 'rolled-back'
        journal.error = ''
        journal.verification = {'status': 'rolled-back'}
        _save_journal(loaded.transaction_dir, journal)
    except Exception as ex:
        journal.status = 'rollback-failed'
        journal.error = str(ex)
        _save_journal(loaded.transaction_dir, journal)
        if isinstance(ex, MigrationExecutionError):
            raise
        raise MigrationExecutionError(str(ex)) from ex
    return MigrationApplyResult(
        journal=journal,
        transaction_dir=loaded.transaction_dir,
        resumed=True,
    )


__all__ = [
    'BackupRecord',
    'GuestInstaller',
    'MigrationApplyResult',
    'MigrationExecutionError',
    'MigrationJournal',
    'RuntimeVerifier',
    'apply_migration',
    'install_bootstrap_through_legacy_access',
    'latest_migration_id',
    'list_migration_ids',
    'load_migration_journal',
    'migration_id_for_plan',
    'migration_plan_sha256',
    'migration_root',
    'migration_transaction_dir',
    'rebuild_plan_from_journal',
    'rollback_migration',
    'sources_from_journal',
    'verify_applied_migration',
    'verify_migration_local',
    'verify_migration_runtime',
]
