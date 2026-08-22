"""Durable, resumable deletion of one managed VM and its host artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Iterable

from loguru import logger as log

from ..attachments.persistent import (
    _cleanup_persistent_host_replay_artifacts,
    _reconcile_persistent_host_binds,
    _sync_persistent_attachment_manifest_on_host,
    _sync_persistent_host_replay_manifest,
)
from ..attachments.resolve import (
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED_ROOT,
)
from ..attachments.shared_root import _detach_shared_root_host_bind
from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_store import (
    AttachmentEntry,
    Store,
    find_attachments_for_vm,
    find_network,
    find_vm,
    load_store,
    network_users,
    remove_vm,
    save_store,
)
from ..config_store.fs_policy import StoreFilesystemPolicy
from ..config_store.io import _atomic_write_text
from ..credentials.guards import (
    discard_released_credential_material,
    require_vm_credentials_released,
)
from ..enrollment import bootstrap_identity_paths
from ..errors import AIVMError
from ..machine_store import (
    MachineResourceLockScope,
    current_machine_group_gid,
    current_machine_store_policy,
    machine_resource_locks,
)
from ..privilege import path_needs_sudo
from ..profile_store import save_user_profile
from ..runtime import pin_locale
from ..scoped_store import StoreScope, load_scope_profile
from ..vm.share import AttachmentAccess, AttachmentMode, ResolvedAttachment
from .domain import (
    _destroy_and_undefine_vm,
    domain_file_storage_paths,
    domain_is_defined,
    require_managed_storage_path,
)
from .paths import _paths

JOURNAL_SCHEMA_VERSION = 1


@dataclass
class VMDeletionJournal:
    """All coordinates needed to resume deletion after a partial failure."""

    schema_version: int
    vm_name: str
    config_path: str
    storage_paths: list[str]
    vm_base_dir: str
    machine_state_dir: str
    bootstrap_dir: str
    completed_phases: list[str] = field(default_factory=list)
    status: str = 'active'
    last_error: str = ''

    def completed(self, phase: str) -> bool:
        return phase in self.completed_phases

    def mark(self, phase: str) -> None:
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)
        self.last_error = ''


class _DeletionLockScope:
    """Optional machine-wide lock wrapper with explicit enter/exit methods."""

    def __init__(self, scope: StoreScope, vm_name: str) -> None:
        self.inner: MachineResourceLockScope | None = None
        if scope.is_machine:
            assert scope.machine_layout is not None
            self.inner = machine_resource_locks(
                scope.machine_layout,
                group_gid=current_machine_group_gid(scope.machine_layout),
                include_store=True,
                vms=[vm_name],
            )

    def __enter__(self) -> None:
        if self.inner is not None:
            self.inner.__enter__()
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self.inner is None:
            return False
        return self.inner.__exit__(exc_type, exc, tb)


def _resource_stem(name: str) -> str:
    clean = ''.join(c if c.isalnum() or c in '._-' else '-' for c in name)
    clean = clean.strip('.-')[:80] or 'vm'
    digest = hashlib.sha256(name.encode('utf-8')).hexdigest()[:10]
    return f'{clean}-{digest}'


def _journal_path_for_vm_name(
    scope: StoreScope, vm_name: str, *, legacy_state_dir: str = ''
) -> Path:
    if scope.is_machine:
        assert scope.machine_layout is not None
        root = scope.machine_layout.state_dir / 'deletions'
    else:
        if not legacy_state_dir:
            raise AIVMError(
                'A legacy deletion journal cannot be located after its VM '
                'record is gone without the original state directory.'
            )
        root = Path(legacy_state_dir).expanduser() / 'deletions'
    return root / f'{_resource_stem(vm_name)}.json'


def _journal_path(scope: StoreScope, cfg: AgentVMConfig) -> Path:
    return _journal_path_for_vm_name(
        scope, cfg.vm.name, legacy_state_dir=cfg.paths.state_dir
    )


def require_vm_creation_not_blocked(
    scope: StoreScope, cfg: AgentVMConfig, cfg_path: Path
) -> None:
    """Refuse to reuse a VM name while an earlier deletion is unfinished."""
    journal_path = _journal_path(scope, cfg)
    journal = _load_journal(journal_path)
    if journal is None or journal.status == 'complete':
        return
    if journal.vm_name != cfg.vm.name or journal.config_path != str(cfg_path):
        raise AIVMError(f'Deletion journal target mismatch: {journal_path}')
    completed = ', '.join(journal.completed_phases) or 'none'
    raise AIVMError(
        f'VM name {cfg.vm.name!r} has an unfinished deletion journal at '
        f'{journal_path} (completed phases: {completed}). Resume '
        f'`aivm vm delete {cfg.vm.name}` before creating or recreating that '
        'managed VM name.'
    )


def _journal_policy(scope: StoreScope) -> StoreFilesystemPolicy:
    if scope.is_machine:
        assert scope.machine_layout is not None
        return current_machine_store_policy(scope.machine_layout)
    return StoreFilesystemPolicy(directory_mode=0o700, file_mode=0o600)


def _save_journal(
    path: Path, journal: VMDeletionJournal, scope: StoreScope
) -> None:
    payload = json.dumps(asdict(journal), indent=2, sort_keys=True) + '\n'
    _atomic_write_text(path, payload, _journal_policy(scope))


def _journal_required_text(
    raw: dict[object, object], key: str, *, path: Path
) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise AIVMError(
            f'VM deletion journal {path} has invalid {key!r}: {value!r}'
        )
    return value


def _journal_optional_text(
    raw: dict[object, object], key: str, *, default: str = '', path: Path
) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str):
        raise AIVMError(
            f'VM deletion journal {path} has invalid {key!r}: {value!r}'
        )
    return value


def _journal_text_list(
    raw: dict[object, object], key: str, *, path: Path
) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list):
        raise AIVMError(
            f'VM deletion journal {path} has invalid {key!r}: {value!r}'
        )
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise AIVMError(
                f'VM deletion journal {path} has invalid {key!r}: {value!r}'
            )
        result.append(item)
    return result


def _load_journal(path: Path) -> VMDeletionJournal | None:
    try:
        decoded = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as ex:
        raise AIVMError(
            f'Could not read VM deletion journal {path}: {ex}'
        ) from ex
    if not isinstance(decoded, dict):
        raise AIVMError(f'VM deletion journal is not an object: {path}')
    raw: dict[object, object] = decoded
    schema_value = raw.get('schema_version')
    if not isinstance(schema_value, int) or isinstance(schema_value, bool):
        raise AIVMError(
            f'VM deletion journal {path} has invalid schema_version: '
            f'{schema_value!r}'
        )
    journal = VMDeletionJournal(
        schema_version=schema_value,
        vm_name=_journal_required_text(raw, 'vm_name', path=path),
        config_path=_journal_required_text(raw, 'config_path', path=path),
        storage_paths=_journal_text_list(raw, 'storage_paths', path=path),
        vm_base_dir=_journal_required_text(raw, 'vm_base_dir', path=path),
        machine_state_dir=_journal_optional_text(
            raw, 'machine_state_dir', path=path
        ),
        bootstrap_dir=_journal_optional_text(raw, 'bootstrap_dir', path=path),
        completed_phases=_journal_text_list(raw, 'completed_phases', path=path),
        status=_journal_optional_text(
            raw, 'status', default='active', path=path
        ),
        last_error=_journal_optional_text(raw, 'last_error', path=path),
    )
    if journal.schema_version != JOURNAL_SCHEMA_VERSION:
        raise AIVMError(
            f'Unsupported VM deletion journal schema '
            f'{journal.schema_version}: {path}'
        )
    return journal


def _initial_storage_paths(cfg: AgentVMConfig) -> list[str]:
    paths: list[Path] = []
    if domain_is_defined(cfg.vm.name):
        paths.extend(domain_file_storage_paths(cfg.vm.name))
    expected = _paths(cfg)['img_dir'] / f'{cfg.vm.name}.qcow2'
    if expected not in paths:
        paths.append(expected)
    return [str(path) for path in paths]


def _new_journal(
    scope: StoreScope, cfg: AgentVMConfig, cfg_path: Path
) -> VMDeletionJournal:
    machine_state = ''
    bootstrap_dir = ''
    if scope.is_machine:
        assert scope.machine_layout is not None
        machine_state = str(scope.machine_layout.vm_state_dir(cfg.vm.name))
        bootstrap_dir = str(
            bootstrap_identity_paths(
                cfg.vm.name, layout=scope.machine_layout
            ).directory
        )
    return VMDeletionJournal(
        schema_version=JOURNAL_SCHEMA_VERSION,
        vm_name=cfg.vm.name,
        config_path=str(cfg_path),
        storage_paths=_initial_storage_paths(cfg),
        vm_base_dir=str(_paths(cfg)['base_dir']),
        machine_state_dir=machine_state,
        bootstrap_dir=bootstrap_dir,
    )


def _persist_phase(
    path: Path,
    journal: VMDeletionJournal,
    scope: StoreScope,
    phase: str,
) -> None:
    journal.mark(phase)
    _save_journal(path, journal, scope)


def _persistent_records_to_detaching(reg: Store, vm_name: str) -> bool:
    changed = False
    for item in reg.attachments:
        if (
            item.vm_name == vm_name
            and item.mode == ATTACHMENT_MODE_PERSISTENT
            and item.state != 'detaching'
        ):
            item.state = 'detaching'
            changed = True
    return changed


def _resolved_attachment(item: AttachmentEntry) -> ResolvedAttachment:
    return ResolvedAttachment(
        vm_name=item.vm_name,
        mode=AttachmentMode(str(item.mode)),
        source_dir=item.host_path,
        guest_dst=item.guest_dst or item.host_path,
        tag=item.tag,
        access=AttachmentAccess(str(item.access)),
        owner_principal_id=item.owner_principal_id,
    )


def _cleanup_attachment_artifacts(
    scope: StoreScope,
    cfg: AgentVMConfig,
    cfg_path: Path,
    reg: Store,
) -> None:
    if _persistent_records_to_detaching(reg, cfg.vm.name):
        save_store(
            reg,
            cfg_path,
            reason=(
                f'Mark persistent attachments detaching before deleting VM '
                f'{cfg.vm.name}.'
            ),
        )
    # An empty/disabled approved manifest is installed before pruning, so the
    # privileged helper cannot recreate a bind after it has been removed.
    _sync_persistent_attachment_manifest_on_host(cfg, cfg_path, dry_run=False)
    _sync_persistent_host_replay_manifest(cfg, cfg_path, dry_run=False)
    _reconcile_persistent_host_binds(
        cfg, cfg_path, dry_run=False, vm_running=False
    )
    _cleanup_persistent_host_replay_artifacts(
        cfg, cfg_path, dry_run=False, force=True
    )
    for item in find_attachments_for_vm(reg, cfg.vm.name):
        if item.mode == ATTACHMENT_MODE_SHARED_ROOT:
            _detach_shared_root_host_bind(
                cfg, _resolved_attachment(item), yes=True, dry_run=False
            )


def _path_exists(path: Path) -> bool:
    """Return a definitive deletion-path presence answer or fail closed."""
    result = CommandManager.current().run(
        pin_locale(['stat', '--format=%F', '--', str(path)]),
        sudo=path_needs_sudo(path),
        role='read',
        check=False,
        capture=True,
        summary=f'Verify deletion path {path}',
    )
    if result.code == 0:
        return True
    detail = (result.stderr or result.stdout or '').strip()
    confirmed_absent = (
        result.code == 1
        and detail.startswith('stat: cannot stat')
        and detail.endswith('No such file or directory')
    )
    if confirmed_absent:
        return False
    raise AIVMError(
        f'Could not determine whether deletion path exists: {path}: '
        f'{detail or f"stat exited with status {result.code}"}'
    )


def _require_managed_storage_path(cfg: AgentVMConfig, path: Path) -> None:
    """Deletion-flavored front for the shared containment chokepoint.

    The containment rule itself lives in
    :func:`aivm.vm.domain.require_managed_storage_path` so the recreate
    path enforces the identical check; only the recovery guidance here is
    deletion-specific.
    """
    require_managed_storage_path(
        cfg,
        path,
        action='deletion',
        recovery=(
            'The deletion journal is retained so an operator can detach, '
            'move, or explicitly manage the external storage before '
            'retrying.'
        ),
    )


def _remove_retained_storage(cfg: AgentVMConfig, paths: Iterable[Path]) -> None:
    mgr = CommandManager.current()
    for path in paths:
        _require_managed_storage_path(cfg, path)
        if not _path_exists(path):
            continue
        mgr.run(
            ['rm', '-f', '--', str(path)],
            sudo=path_needs_sudo(path),
            role='modify',
            check=True,
            capture=True,
            summary=f'Remove retained managed VM storage {path}',
        )
        if _path_exists(path):
            raise AIVMError(f'Managed VM storage still exists: {path}')


def _remove_tree(path: Path, *, label: str) -> None:
    if not str(path):
        return
    mgr = CommandManager.current()
    quoted = shlex.quote(str(path))
    script = (
        f'if [ -L {quoted} ]; then '
        f'echo "refusing symlinked {label}: {quoted}" >&2; exit 1; fi; '
        f'rm -rf --one-file-system -- {quoted}'
    )
    mgr.run(
        ['bash', '-c', script],
        sudo=path_needs_sudo(path),
        role='modify',
        check=True,
        capture=True,
        summary=f'Remove {label}',
        detail=f'path={path}',
    )


def _assert_no_mounts_below(path: Path) -> None:
    # ``--list`` is load-bearing: the default tree rendering prefixes every
    # non-root line with box-drawing glyphs (``├─``), which the path filter
    # below would silently discard, letting rm -rf proceed over live mounts.
    result = CommandManager.current().run(
        [
            'findmnt',
            '-R',
            '--list',
            '-n',
            '-o',
            'TARGET',
            '--target',
            str(path),
        ],
        sudo=path_needs_sudo(path),
        role='read',
        check=False,
        capture=True,
        summary=f'Check for mounts beneath {path}',
    )
    if result.code != 0:
        # ``findmnt --target`` reports an absent path as status 1 without a
        # useful diagnostic. Confirm that exact recovery case independently;
        # every other inspection failure must stop destructive cleanup.
        probe = CommandManager.current().run(
            pin_locale(['stat', '--format=%F', '--', str(path)]),
            sudo=path_needs_sudo(path),
            role='read',
            check=False,
            capture=True,
            summary=f'Confirm whether deletion root is absent: {path}',
        )
        probe_detail = (probe.stderr or probe.stdout or '').strip()
        confirmed_absent = (
            probe.code == 1
            and probe_detail.startswith('stat: cannot stat')
            and probe_detail.endswith('No such file or directory')
        )
        if confirmed_absent:
            return
        if probe.code != 0:
            raise AIVMError(
                f'Could not inspect deletion root {path} after mount '
                f'enumeration failed: '
                f'{probe_detail or f"stat exited with status {probe.code}"}. '
                'Refusing to remove the VM directory.'
            )
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Could not verify that no mounts remain beneath {path}: '
            f'{detail or f"findmnt exited with status {result.code}"}. '
            'Refusing to remove the VM directory.'
        )
    targets = [
        line.strip() for line in result.stdout.splitlines() if line.strip()
    ]
    root = Path(os.path.abspath(os.fspath(path)))
    nested = []
    for raw in targets:
        if not raw.startswith('/'):
            # A mount target we cannot interpret (tree glyphs, escaping) means
            # the enumeration cannot be trusted as a deletion authorization.
            raise AIVMError(
                f'Unrecognized findmnt output while checking for mounts '
                f'beneath {path}: {raw!r}. Refusing to remove the VM '
                'directory.'
            )
        candidate = Path(os.path.abspath(raw))
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        nested.append(raw)
    if nested:
        rendered = '\n'.join(f'  - {item}' for item in nested)
        raise AIVMError(
            f'Refusing to remove VM directory while mounts remain beneath '
            f'{path}:\n{rendered}'
        )


def _revalidate_domain_storage_paths(
    cfg: AgentVMConfig,
    journal: VMDeletionJournal,
) -> tuple[Path, ...]:
    """Require the live domain disk inventory to match the durable journal."""
    recorded = tuple(Path(item) for item in journal.storage_paths)
    if not domain_is_defined(cfg.vm.name):
        return recorded

    current = tuple(domain_file_storage_paths(cfg.vm.name))
    # Validate every live path before comparing inventories. A newly attached
    # unmanaged disk is a containment violation, not merely an inventory
    # mismatch, and must be rejected before any destructive phase.
    for path in current:
        _require_managed_storage_path(cfg, path)
    recorded_by_text = {
        os.path.abspath(os.fspath(path)): path for path in recorded
    }
    current_by_text = {
        os.path.abspath(os.fspath(path)): path for path in current
    }
    recorded_names = set(recorded_by_text)
    current_names = set(current_by_text)
    if recorded_names != current_names:
        added = sorted(current_names - recorded_names)
        removed = sorted(recorded_names - current_names)
        details: list[str] = []
        if added:
            details.append(
                'new live domain disks:\n'
                + '\n'.join(f'  - {item}' for item in added)
            )
        if removed:
            details.append(
                'journaled disks no longer present in the domain:\n'
                + '\n'.join(f'  - {item}' for item in removed)
            )
        raise AIVMError(
            f'VM {cfg.vm.name!r} storage changed after its deletion journal '
            'was created. Refusing `virsh undefine --remove-all-storage` '
            'until an operator reviews the changed inventory.\n'
            + '\n'.join(details)
        )

    return current


def _cleanup_owned_trees(journal: VMDeletionJournal) -> None:
    """Preflight every owned tree before beginning recursive cleanup."""
    candidates: list[tuple[Path, str]] = []
    if journal.bootstrap_dir:
        candidates.append((Path(journal.bootstrap_dir), 'bootstrap identity'))
    if journal.machine_state_dir:
        candidates.append(
            (Path(journal.machine_state_dir), 'per-VM machine state')
        )
    candidates.append((Path(journal.vm_base_dir), 'AIVM-managed VM directory'))

    # Mount enumeration is an authorization check for recursive deletion.  Run
    # every required inspection before removing any tree so one late probe
    # failure cannot leave a partially completed cleanup.
    seen: set[Path] = set()
    for path, _label in candidates:
        normalized = Path(os.path.abspath(os.fspath(path)))
        if normalized in seen:
            continue
        seen.add(normalized)
        _assert_no_mounts_below(normalized)

    for path, label in candidates:
        _remove_tree(path, label=label)


def _clear_current_profile(scope: StoreScope, vm_name: str, reg: Store) -> None:
    if not scope.is_machine:
        return
    profile = load_scope_profile(scope)
    if profile.active_vm != vm_name:
        return
    profile.active_vm = (
        sorted(vm.name for vm in reg.vms if vm.name != vm_name)[0]
        if any(vm.name != vm_name for vm in reg.vms)
        else ''
    )
    assert scope.profile_path is not None
    save_user_profile(profile, scope.profile_path)


_FINALIZATION_PREREQUISITES = (
    'attachments-cleaned',
    'credentials-cleaned',
    'domain-and-storage-removed',
    'owned-trees-removed',
    'profile-cleared',
)


def complete_missing_vm_deletion(
    scope: StoreScope,
    cfg_path: Path,
    vm_name: str,
) -> VMDeletionJournal | None:
    """Finish journal bookkeeping after the final store write already landed.

    Atomic store replacement can succeed immediately before the process dies
    while recording ``store-finalized``. An explicit ``vm delete <name>`` can
    recover that narrow window even though the VM entry is no longer available
    to materialize an :class:`AgentVMConfig`.
    """
    if not scope.is_machine or scope.machine_layout is None:
        return None
    journal_path = _journal_path_for_vm_name(scope, vm_name)
    if not journal_path.exists():
        return None
    with _DeletionLockScope(scope, vm_name):
        reg = load_store(cfg_path)
        if find_vm(reg, vm_name) is not None:
            return None
        journal = _load_journal(journal_path)
        if journal is None:
            return None
        if journal.vm_name != vm_name or journal.config_path != str(cfg_path):
            raise AIVMError(f'Deletion journal target mismatch: {journal_path}')
        missing = [
            phase
            for phase in _FINALIZATION_PREREQUISITES
            if not journal.completed(phase)
        ]
        if missing:
            rendered = ', '.join(missing)
            raise AIVMError(
                f'VM {vm_name!r} is absent from the machine store, but its '
                f'deletion journal lacks completed cleanup phases: {rendered}. '
                'Retaining the journal for operator recovery.'
            )
        journal.mark('store-finalized')
        journal.status = 'complete'
        journal.last_error = ''
        _save_journal(journal_path, journal, scope)
        return journal


def delete_managed_vm(
    scope: StoreScope,
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
) -> VMDeletionJournal | None:
    """Delete a VM through a resumable, idempotent host-side journal."""
    if dry_run:
        preview_store = load_store(cfg_path)
        require_vm_credentials_released(
            preview_store, cfg.vm.name, action='deleted'
        )
        print(
            f'DRYRUN: would create/resume deletion journal for {cfg.vm.name}, '
            'prune attachment mounts, remove replay/bootstrap/state artifacts, '
            'remove the libvirt domain with storage, then delete the store record.'
        )
        return None

    journal_path = _journal_path(scope, cfg)
    with _DeletionLockScope(scope, cfg.vm.name):
        reg = load_store(cfg_path)
        credentials = require_vm_credentials_released(
            reg, cfg.vm.name, action='deleted'
        )
        journal = _load_journal(journal_path)
        if journal is not None and (
            journal.status == 'complete'
            or (
                journal.completed('domain-and-storage-removed')
                and domain_is_defined(cfg.vm.name)
            )
        ):
            log.warning(
                'Starting a fresh deletion journal for recreated VM {}.',
                cfg.vm.name,
            )
            journal = None
        if journal is None:
            journal = _new_journal(scope, cfg, cfg_path)
            _save_journal(journal_path, journal, scope)
        if journal.vm_name != cfg.vm.name or journal.config_path != str(
            cfg_path
        ):
            raise AIVMError(f'Deletion journal target mismatch: {journal_path}')

        try:
            # Complete every domain and storage inspection before the first
            # destructive phase. A failed libvirt query or filesystem probe
            # must not leave attachments, credentials, or trees half-cleaned.
            preflight_storage = _revalidate_domain_storage_paths(cfg, journal)
            for storage_path in preflight_storage:
                _require_managed_storage_path(cfg, storage_path)
                _path_exists(storage_path)

            # Refuse unmanaged or symlink-escaped storage before the first
            # destructive phase. Libvirt's --remove-all-storage must never be
            # allowed to delete a file outside the VM's AIVM-owned tree.
            for storage_text in journal.storage_paths:
                _require_managed_storage_path(cfg, Path(storage_text))

            if not journal.completed('attachments-cleaned'):
                _cleanup_attachment_artifacts(scope, cfg, cfg_path, reg)
                reg = load_store(cfg_path)
                _persist_phase(
                    journal_path, journal, scope, 'attachments-cleaned'
                )

            if not journal.completed('credentials-cleaned'):
                discard_released_credential_material(credentials)
                _persist_phase(
                    journal_path, journal, scope, 'credentials-cleaned'
                )

            if not journal.completed('domain-and-storage-removed'):
                # Recapture immediately before the storage-removing libvirt
                # operation.  A resumed journal must not authorize disks that
                # were attached or replaced after its original preflight.
                storage_paths = _revalidate_domain_storage_paths(cfg, journal)
                report = _destroy_and_undefine_vm(
                    cfg.vm.name, storage_paths=storage_paths
                )
                # Direct filesystem removal is authorized only after a
                # successful libvirt query proves the domain is absent.
                if domain_is_defined(cfg.vm.name):
                    raise AIVMError(
                        f'VM domain still exists after deletion: {cfg.vm.name}'
                    )
                _remove_retained_storage(cfg, report.retained_storage_paths)
                remaining = [p for p in storage_paths if _path_exists(p)]
                if remaining:
                    rendered = '\n'.join(f'  - {p}' for p in remaining)
                    raise AIVMError(
                        f'VM storage remains after cleanup:\n{rendered}'
                    )
                _persist_phase(
                    journal_path,
                    journal,
                    scope,
                    'domain-and-storage-removed',
                )

            if not journal.completed('owned-trees-removed'):
                _cleanup_owned_trees(journal)
                _persist_phase(
                    journal_path, journal, scope, 'owned-trees-removed'
                )

            reg = load_store(cfg_path)
            if not journal.completed('profile-cleared'):
                _clear_current_profile(scope, cfg.vm.name, reg)
                _persist_phase(journal_path, journal, scope, 'profile-cleared')

            if not journal.completed('store-finalized'):
                remove_vm(reg, cfg.vm.name, remove_attachments=True)
                save_store(
                    reg,
                    cfg_path,
                    reason=(
                        f'Finalize journaled deletion of VM {cfg.vm.name} '
                        'after all external cleanup succeeded.'
                    ),
                )
                _persist_phase(journal_path, journal, scope, 'store-finalized')

            journal.status = 'complete'
            journal.last_error = ''
            _save_journal(journal_path, journal, scope)
        except BaseException as ex:
            journal.status = 'active'
            journal.last_error = f'{type(ex).__name__}: {ex}'
            try:
                _save_journal(journal_path, journal, scope)
            except Exception as journal_ex:
                log.error(
                    'Could not persist deletion failure to {}: {}',
                    journal_path,
                    journal_ex,
                )
            raise

        net_name = (cfg.network.name or '').strip()
        if net_name:
            net = find_network(reg, net_name)
            if net is not None and not network_users(reg, net_name):
                log.warning(
                    "Network '{}' now has no VM users and remains defined. "
                    'Destroy it explicitly if no longer needed.',
                    net_name,
                )
        return journal


__all__ = [
    'VMDeletionJournal',
    'complete_missing_vm_deletion',
    'delete_managed_vm',
    'require_vm_creation_not_blocked',
]
