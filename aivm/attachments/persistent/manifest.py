"""Persistent-attachment manifest model and host/guest sync.

Hosts the canonical desired-state manifest writes (under user-owned
``app_data_dir``) plus the rsync-based push into the guest.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...config_store import (
    find_attachments_for_vm,
    load_store,
    persistent_host_state_dir,
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
    mode: str
    source_dir: str
    host_lexical_paths: tuple[str, ...]
    shared_root_token: str
    guest_dst: str
    access: str
    enabled: bool = True


def _persistent_host_state_dir(cfg: AgentVMConfig) -> Path:
    # Keep the canonical manifest outside the exported persistent-root tree so
    # the guest replay helper never depends on reading through virtiofs.
    # This lives in user-owned app data, not under the libvirt-managed VM tree.
    return persistent_host_state_dir(cfg.vm.name)


def _persistent_host_manifest_path(cfg: AgentVMConfig) -> Path:
    return (
        _persistent_host_state_dir(cfg)
        / PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME
    )


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


def _sync_persistent_host_replay_manifest(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
) -> Path:
    """Install the replay input into root-owned, non-user-writable storage."""
    target = _persistent_host_replay_manifest_path(cfg)
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
        records.append(
            PersistentAttachmentRecord(
                attachment_id=str(att.tag or att.host_path),
                mode=str(att.mode or ATTACHMENT_MODE_PERSISTENT),
                source_dir=str(att.host_path),
                host_lexical_paths=tuple(att.host_lexical_paths or ()),
                shared_root_token=str(att.tag or ''),
                guest_dst=str(att.guest_dst or ''),
                access=str(att.access or 'rw'),
                enabled=True,
            )
        )
    return sorted(
        records, key=lambda rec: (rec.guest_dst, rec.shared_root_token)
    )


def _persistent_attachment_manifest_text(
    cfg: AgentVMConfig,
    cfg_path: Path,
) -> str:
    records = _persistent_attachment_records_for_vm(cfg, cfg_path)
    payload = {
        'schema_version': 1,
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
    manifest_path = _persistent_host_manifest_path(cfg)
    manifest_text = _persistent_attachment_manifest_text(cfg, cfg_path)
    if dry_run:
        print(
            f'DRYRUN: would write persistent attachment manifest to {manifest_path}'
        )
        return manifest_path
    transport._write_text_if_changed(manifest_path, manifest_text)
    return manifest_path


def _sync_persistent_attachment_manifest_to_guest(
    cfg: AgentVMConfig,
    ip: str,
    *,
    dry_run: bool,
    check: bool = True,
) -> bool:
    manifest_path = _persistent_host_manifest_path(cfg)
    remote_target = (
        f'{cfg.vm.user}@{ip}:{PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}'
    )
    ident = require_ssh_identity(cfg.paths.ssh_identity_file)
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
