"""Persistent-attachment manifest model and host/guest sync.

Hosts the canonical desired-state manifest writes (under user-owned
``app_data_dir``) plus the rsync-based push into the guest.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass
from pathlib import Path

from loguru import logger as log

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...config_store import (
    find_attachments_for_vm,
    load_store,
    persistent_host_state_dir,
)
from ...persistent_replay import (
    PERSISTENT_ATTACHMENT_GUEST_STATE_PATH,
    PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME,
    PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX,
    PERSISTENT_ROOT_GUEST_MOUNT_ROOT,
)
from ...runtime import require_ssh_identity, ssh_base_args
from ..resolve import ATTACHMENT_MODE_PERSISTENT
from . import transport


def _persistent_root_host_dir(cfg: AgentVMConfig) -> Path:
    return Path(cfg.paths.base_dir) / cfg.vm.name / 'persistent-root'


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


def _persistent_host_replay_service_name(vm_name: str) -> str:
    return f'{PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX}-{vm_name}.service'


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
