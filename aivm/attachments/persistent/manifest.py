"""Persistent-attachment manifest model and host/guest sync.

Hosts canonical desired-state manifest writes plus the rsync-based push
into the guest. Machine-store VMs use one global manifest under machine state;
legacy stores retain the released user-owned XDG location.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from types import TracebackType

from ...commands import CommandManager
from ...config import AgentVMConfig
from aivm.config_scopes import guest_transport_from_effective_cfg
from ...config_store import (
    find_attachments_for_vm,
    load_store,
)
from ...legacy.pre_0_6_0.paths import persistent_host_state_dir
from ...config_store.io import _atomic_write_text
from ...machine_store import (
    current_machine_group_gid,
    current_machine_store_policy,
    is_machine_store_path,
    MachineResourceLockScope,
    machine_resource_locks,
    machine_store_layout,
)
from ...persistent_replay import (
    PERSISTENT_ATTACHMENT_GUEST_STATE_PATH,
    PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR,
    PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
    PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX,
    PERSISTENT_ROOT_GUEST_MOUNT_ROOT,
)
from ...runtime import require_ssh_identity, ssh_base_args
from ..resolve import ATTACHMENT_MODE_PERSISTENT
from . import transport


@dataclass(frozen=True)
class PersistentAttachmentRecord:
    attachment_id: str
    owner_principal_id: str
    mode: str
    source_dir: str
    host_lexical_paths: tuple[str, ...]
    shared_root_token: str
    guest_dst: str
    access: str
    source_dev: int
    source_ino: int
    enabled: bool = True


def _persistent_host_state_dir(
    cfg: AgentVMConfig, cfg_path: Path | None = None
) -> Path:
    """Return canonical host replay state for one VM.

    Machine-store installations keep replay state beside the host-wide desired
    state so every trusted caller observes one manifest. Legacy stores retain
    their released per-user XDG location until migration.
    """
    if cfg_path is not None and is_machine_store_path(cfg_path):
        return machine_store_layout().vm_state_dir(cfg.vm.name) / 'persistent'
    return persistent_host_state_dir(cfg.vm.name)


def _persistent_host_manifest_path(
    cfg: AgentVMConfig, cfg_path: Path | None = None
) -> Path:
    return (
        _persistent_host_state_dir(cfg, cfg_path)
        / PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME
    )


class _PersistentManifestLock:
    """Serialize manifest generation with machine-store mutations."""

    def __init__(self, cfg: AgentVMConfig, cfg_path: Path) -> None:
        self.scope: MachineResourceLockScope | None = None
        if is_machine_store_path(cfg_path):
            self.scope = machine_resource_locks(
                machine_store_layout(),
                group_gid=current_machine_group_gid(),
                include_store=True,
                vms=[cfg.vm.name],
            )

    def __enter__(self) -> None:
        if self.scope is not None:
            self.scope.__enter__()
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self.scope is None:
            return False
        return self.scope.__exit__(exc_type, exc, tb)


def _persistent_manifest_lock(
    cfg: AgentVMConfig, cfg_path: Path
) -> _PersistentManifestLock:
    """Return the class-based persistent-manifest lock scope."""
    return _PersistentManifestLock(cfg, cfg_path)


def _persistent_host_replay_manifest_path(cfg: AgentVMConfig) -> Path:
    """Root-owned manifest consumed by the privileged host replay service."""
    raw = str(cfg.vm.name or '').strip()
    safe = re.sub(r'[^A-Za-z0-9_.-]+', '-', raw).strip('.-') or 'vm'
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()[:10]
    filename = f'{safe[:80]}-{digest}.json'
    return Path(PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR) / filename


def _approved_state_directories_are_safe() -> bool:
    paths = [
        Path(PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR).parent,
        Path(PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR),
    ]
    for path in paths:
        try:
            info = path.lstat()
        except OSError:
            return False
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            return False
    return True


def _ensure_approved_state_directories(*, dry_run: bool) -> None:
    """Create a root-controlled chain beneath /var/lib without following links."""
    if _approved_state_directories_are_safe():
        return
    parent = Path(PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR).parent
    state_dir = Path(PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR)
    if dry_run:
        print(
            'DRYRUN: would secure persistent host replay state directories '
            f'{parent} and {state_dir}'
        )
        return
    # The first directory is directly below trusted /var/lib. Once it is
    # corrected to root:root 0755, an unprivileged process can no longer race
    # replacement of the second directory.
    script = (
        'set -eu; '
        f'for path in {shlex.quote(str(parent))} {shlex.quote(str(state_dir))}; do '
        'if [ -L "$path" ]; then '
        'echo "refusing symlink in persistent replay state path: $path" >&2; exit 1; '
        'fi; '
        'install -d -m 0755 -o root -g root -- "$path"; '
        'done'
    )
    mgr = CommandManager.current()
    with mgr.step(
        'Secure persistent host replay state directory',
        why=(
            'The root replay service may only consume manifests beneath a '
            'root-owned, non-user-writable directory chain.'
        ),
        approval_scope='persistent-host-replay-state-dir',
    ):
        mgr.submit(
            ['bash', '-c', script],
            sudo=True,
            role='modify',
            summary='Create root-owned persistent replay state directories',
            detail=f'target={state_dir}',
        )


def _persistent_host_replay_state_needed(
    cfg: AgentVMConfig, cfg_path: Path
) -> bool:
    """True when the root replay service has, or must be told about, work.

    An installed manifest must track record changes -- including down to
    empty, so a detach of the last persistent folder still propagates.  But
    with no persistent record and nothing previously installed there is no
    replay state to create, secure, or update: privilege gates on the
    command, not the feature, so a VM that never opted into persistent
    attachments must not demand root for their replay machinery (e.g.
    ``vm up`` under ``privilege_mode='never'``).
    """
    with _persistent_manifest_lock(cfg, cfg_path):
        if _persistent_host_replay_manifest_path(cfg).exists():
            needed = True
        else:
            records = _persistent_attachment_records_for_vm(cfg, cfg_path)
            # Detaching records intentionally render as disabled entries. They
            # still need an approved empty/disabled manifest so a retry can
            # prove stale host binds are pruned before deleting the record.
            needed = bool(records)
    return needed


def _sync_persistent_host_replay_manifest(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
) -> Path:
    """Install the replay input into root-owned, non-user-writable storage."""
    target = _persistent_host_replay_manifest_path(cfg)
    with _persistent_manifest_lock(cfg, cfg_path):
        if not _persistent_host_replay_state_needed(cfg, cfg_path):
            return target
        _ensure_approved_state_directories(dry_run=dry_run)
        manifest_text = _persistent_attachment_manifest_text(cfg, cfg_path)
        transport._install_host_text_if_changed(
            target,
            manifest_text,
            '0644',
            label='approved persistent host replay manifest',
            dry_run=dry_run,
            force_sudo=True,
            owner='root',
            group='root',
        )
    return target


def _persistent_host_replay_service_name(vm_name: str) -> str:
    return (
        f'{PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX}-{vm_name}.service'
    )


def _persistent_attachment_records_for_vm(
    cfg: AgentVMConfig,
    cfg_path: Path,
) -> list[PersistentAttachmentRecord]:
    reg = load_store(cfg_path)
    records: list[PersistentAttachmentRecord] = []
    for att in find_attachments_for_vm(reg, cfg.vm.name):
        if str(att.mode or '').strip() != ATTACHMENT_MODE_PERSISTENT:
            continue
        enabled = str(att.state or 'active') == 'active'
        source_dev = 0
        source_ino = 0
        if enabled:
            source_dev = int(att.source_dev)
            source_ino = int(att.source_ino)
            if source_dev <= 0 or source_ino <= 0:
                if is_machine_store_path(cfg_path):
                    recovery = (
                        'Detach and reattach this attachment before privileged '
                        'replay.'
                    )
                else:
                    recovery = (
                        'This attachment is still recorded in a pre-0.6 legacy '
                        'store. Run `aivm config migrate plan --sudo`, then '
                        '`aivm config migrate apply --sudo --yes`. If migration '
                        'reports that the source is unavailable, restore the '
                        'source path or detach and reattach this attachment.'
                    )
                raise RuntimeError(
                    f'Persistent attachment {att.host_path!r} lacks a pinned '
                    f'source object identity. {recovery}'
                )
        records.append(
            PersistentAttachmentRecord(
                attachment_id=(
                    f'{att.owner_principal_id or "legacy"}:'
                    f'{att.tag or att.host_path}'
                ),
                owner_principal_id=str(att.owner_principal_id or ''),
                mode=str(att.mode or ATTACHMENT_MODE_PERSISTENT),
                source_dir=str(att.host_path),
                host_lexical_paths=tuple(att.host_lexical_paths or ()),
                shared_root_token=str(att.tag or ''),
                guest_dst=str(att.guest_dst or ''),
                access=str(att.access or 'rw'),
                source_dev=source_dev,
                source_ino=source_ino,
                enabled=enabled,
            )
        )
    return sorted(
        records,
        key=lambda rec: (
            rec.owner_principal_id, rec.guest_dst, rec.shared_root_token
        ),
    )


def _persistent_attachment_manifest_text(
    cfg: AgentVMConfig,
    cfg_path: Path,
) -> str:
    records = _persistent_attachment_records_for_vm(cfg, cfg_path)
    payload = {
        'schema_version': 2,
        'vm_name': cfg.vm.name,
        'shared_root_mount': PERSISTENT_ROOT_GUEST_MOUNT_ROOT,
        'records': [asdict(rec) for rec in records],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + '\n'


def _sync_persistent_attachment_manifest_on_host(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
) -> Path:
    manifest_path = _persistent_host_manifest_path(cfg, cfg_path)
    with _persistent_manifest_lock(cfg, cfg_path):
        manifest_text = _persistent_attachment_manifest_text(cfg, cfg_path)
        if dry_run:
            print(
                f'DRYRUN: would write persistent attachment manifest to {manifest_path}'
            )
            return manifest_path
        if is_machine_store_path(cfg_path):
            new_bytes = manifest_text.encode('utf-8')
            if not manifest_path.exists() or manifest_path.read_bytes() != new_bytes:
                _atomic_write_text(
                    manifest_path,
                    manifest_text,
                    current_machine_store_policy(),
                )
        else:
            transport._write_text_if_changed(manifest_path, manifest_text)
    return manifest_path


def _sync_persistent_attachment_manifest_to_guest(
    cfg: AgentVMConfig,
    ip: str,
    *,
    cfg_path: Path | None = None,
    dry_run: bool,
    check: bool = True,
) -> bool:
    context = guest_transport_from_effective_cfg(cfg)
    manifest_path = _persistent_host_manifest_path(cfg, cfg_path)
    remote_target = (
        f'{context.ssh_target(ip)}:{PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}'
    )
    ident = require_ssh_identity(context.ssh_identity_file)
    ssh_args = [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
            connect_timeout=15,
            batch_mode=True,
        ),
    ]
    mgr = CommandManager.current()
    if dry_run:
        print(
            'DRYRUN: would sync persistent attachment manifest with rsync '
            f'{manifest_path} -> {remote_target}'
        )
        return False
    with mgr.step(
        'Sync persistent attachment manifest into guest',
        why='Push the host canonical manifest into the guest-local replay input using a checksum-based rsync so unchanged content stays untouched.',
        approval_scope=f'persistent-manifest-sync:{cfg.vm.name}',
    ):
        transport._run_guest_ssh_script_with_retry(
            cfg,
            ip,
            script=(
                f'sudo -n mkdir -p {shlex.quote(str(Path(PERSISTENT_ATTACHMENT_GUEST_STATE_PATH).parent))}'
            ),
            summary='Prepare guest persistent manifest directory',
            detail=f'target={PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}',
            dry_run=dry_run,
            role='modify',
            check=check,
        )
        result = transport._run_rsync_with_retry(
            [
                'rsync',
                '--archive',
                '--checksum',
                '--itemize-changes',
                '--no-owner',
                '--no-group',
                '--chmod=F644',
                '--rsync-path',
                'sudo -n rsync',
                '-e',
                ' '.join(shlex.quote(arg) for arg in ssh_args),
                str(manifest_path),
                remote_target,
            ],
            summary='Sync persistent attachment manifest to guest',
            detail=f'source={manifest_path} target={remote_target}',
            dry_run=dry_run,
            check=check,
        )
    assert result is not None
    if not check:
        code = int(getattr(result, 'code', getattr(result, 'returncode', 0)))
        if code != 0:
            stderr = str(getattr(result, 'stderr', '') or '').strip()
            stdout = str(getattr(result, 'stdout', '') or '').strip()
            raise RuntimeError(stderr or stdout or f'rsync failed code={code}')
    return bool((result.stdout or '').strip())
