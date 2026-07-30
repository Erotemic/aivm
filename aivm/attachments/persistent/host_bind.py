"""Host-side bind reconcile + replay-service install for persistent attachments."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from loguru import logger as log

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...persistent_replay import (
    PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN,
    PERSISTENT_BIND_TOKEN_PATTERN,
    PERSISTENT_ROOT_VIRTIOFS_TAG,
    persistent_host_replay_python,
    persistent_host_replay_service_unit,
)

_TOKEN_RE = re.compile(PERSISTENT_BIND_TOKEN_PATTERN)
from ...privilege import path_needs_sudo
from ...vm import attach_vm_share, vm_share_mappings
from ...vm.paths import persistent_root_host_dir as _persistent_root_host_dir
from ..shared_root import _needs_mkdir
from . import manifest, transport


def _ensure_persistent_root_parent_dir(
    cfg: AgentVMConfig,
    *,
    dry_run: bool,
) -> None:
    """Create the trusted export root before it is attached to a VM."""
    target = _persistent_root_host_dir(cfg)
    if not _needs_mkdir(target):
        return
    if dry_run:
        print(f'DRYRUN: would create persistent-root parent directory {target}')
        return
    mgr = CommandManager.current()
    with mgr.step(
        'Prepare persistent-root parent directory',
        why=(
            'Create the host-side export directory that contains only '
            'descriptor-pinned persistent bind targets.'
        ),
        approval_scope=f'persistent-root-parent:{cfg.vm.name}',
    ):
        mgr.submit(
            ['mkdir', '-p', str(target)],
            ownership='tool',
            sudo=path_needs_sudo(target),
            role='modify',
            summary='Create persistent-root parent directory',
            detail=f'target={target}',
        )


def _ensure_persistent_host_replay_helper(*, dry_run: bool) -> bool:
    """Install the one privileged descriptor-pinned bind primitive."""
    return transport._install_host_text_if_changed(
        Path(PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN),
        persistent_host_replay_python(),
        '0755',
        label='persistent host replay helper',
        dry_run=dry_run,
    )


def _approved_binds_already_applied(
    approved_manifest: Path, export_root: Path
) -> bool:
    """True when the live export root already matches the approved manifest.

    The replay helper needs root, and on a shared machine the manifest spans
    *every* principal's persistent attachments. Submitting it unconditionally
    meant that any caller starting the VM -- including one who owns none of
    those attachments and has no sudo -- had to escalate merely to re-assert
    binds that were already in place. The privilege model gates on the
    command, so the fix is not to run the command when there is nothing for
    it to do.

    Every check here is an unprivileged ``stat``-family call, and every
    uncertainty answers False, because a wrong "converged" leaves a guest
    with a silently missing bind. In particular a target that cannot be
    read, a manifest that cannot be parsed, and a source whose identity no
    longer matches all fall through to the privileged helper.

    The identity test is the load-bearing one: a bind target *is* the source
    directory, so ``lstat`` of the target returning the approved
    ``(dev, ino)`` proves both that the bind exists and that it still points
    at the approved object -- without needing any access to the source
    itself, which on a shared machine usually lives in another user's home.
    """
    try:
        payload = json.loads(approved_manifest.read_text(encoding='utf-8'))
        records = payload['records']
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if not isinstance(records, list):
        return False

    desired_tokens: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            return False
        token = str(record.get('shared_root_token') or '')
        if not bool(record.get('enabled', True)):
            continue
        if not token:
            return False
        desired_tokens.add(token)
        target = export_root / token
        try:
            info = target.lstat()
        except OSError:
            return False
        if not stat.S_ISDIR(info.st_mode):
            # A symlink or file standing in for the bind target. The helper
            # opens these with O_NOFOLLOW for exactly this reason.
            return False
        if (int(info.st_dev), int(info.st_ino)) != (
            int(record.get('source_dev', -1)),
            int(record.get('source_ino', -1)),
        ):
            return False
        if not _bind_access_matches(target, str(record.get('access') or 'rw')):
            return False

    # A record that was disabled or detached leaves a mount the helper would
    # prune; anything still mounted under a non-desired token is work to do.
    # Scoped to the names the helper itself will act on, so an unrelated
    # mount it would skip cannot leave this permanently "not converged".
    try:
        children = list(export_root.iterdir())
    except OSError:
        return False
    for child in children:
        if child.name in desired_tokens or not _TOKEN_RE.fullmatch(child.name):
            continue
        try:
            if child.is_mount():
                return False
        except OSError:
            return False
    return True


def _bind_access_matches(target: Path, access: str) -> bool:
    """Compare a mounted bind's read-only flag against the approved access.

    ``statvfs`` reports the mount's own ``ST_RDONLY``, which is what the
    helper's ``remount,bind,ro`` sets, so this needs neither ``findmnt`` nor
    root.
    """
    try:
        flags = os.statvfs(target).f_flag
    except OSError:
        return False
    read_only = bool(flags & os.ST_RDONLY)
    return read_only == (access.strip() == 'ro')


def _run_persistent_host_replay(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
    prune_stale: bool = True,
) -> None:
    """Apply the approved manifest through the privileged pinned-FD helper."""
    approved_manifest = manifest._sync_persistent_host_replay_manifest(
        cfg, cfg_path, dry_run=dry_run
    )
    helper_changed = _ensure_persistent_host_replay_helper(dry_run=dry_run)
    if dry_run:
        print(
            'DRYRUN: would replay approved persistent host bind manifest '
            f'{approved_manifest}'
        )
        return
    if not helper_changed and _approved_binds_already_applied(
        approved_manifest, _persistent_root_host_dir(cfg)
    ):
        log.debug(
            'Persistent host binds already match the approved manifest; '
            'skipping the privileged replay for VM {}.',
            cfg.vm.name,
        )
        return
    cmd = [
        PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN,
        '--manifest',
        str(approved_manifest),
        '--export-root',
        str(_persistent_root_host_dir(cfg)),
        '--vm-name',
        cfg.vm.name,
    ]
    if prune_stale:
        cmd.append('--prune-stale')
    mgr = CommandManager.current()
    with mgr.step(
        'Reconcile persistent host binds',
        why=(
            'Open approved source and target directories without following '
            'symlinks, bind through held descriptors, and prune stale mounts.'
        ),
        approval_scope=f'persistent-host-replay:{cfg.vm.name}',
    ):
        mgr.submit(
            cmd,
            sudo=True,
            role='modify',
            summary='Replay approved persistent host bind manifest',
            detail=f'manifest={approved_manifest}',
        )


def _install_persistent_host_bind_replay(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
) -> bool:
    if not manifest._persistent_host_replay_state_needed(cfg, cfg_path):
        log.info(
            'No persistent attachments recorded for VM {}; not installing '
            'the host replay service.',
            cfg.vm.name,
        )
        return False
    approved_manifest_path = manifest._sync_persistent_host_replay_manifest(
        cfg, cfg_path, dry_run=dry_run
    )
    helper_changed = _ensure_persistent_host_replay_helper(dry_run=dry_run)
    service_name = manifest._persistent_host_replay_service_name(cfg.vm.name)
    unit_changed = transport._install_host_text_if_changed(
        Path('/etc/systemd/system') / service_name,
        persistent_host_replay_service_unit(
            vm_name=cfg.vm.name,
            manifest_path=str(approved_manifest_path),
            export_root=str(_persistent_root_host_dir(cfg)),
        ),
        '0644',
        label='persistent host replay unit',
        dry_run=dry_run,
    )
    if dry_run:
        return helper_changed or unit_changed
    mgr = CommandManager.current()
    with mgr.step(
        'Enable persistent host replay service',
        why='Ensure the host-side persistent bind replay service is available after reboot.',
        approval_scope=f'persistent-host-replay-service:{cfg.vm.name}',
    ):
        if unit_changed:
            mgr.submit(
                ['systemctl', 'daemon-reload'],
                sudo=True,
                role='modify',
                summary='Reload systemd after persistent host replay unit changes',
                detail=f'service={service_name}',
            )
        mgr.submit(
            ['systemctl', 'enable', service_name],
            sudo=True,
            role='modify',
            summary='Enable persistent host replay service',
            detail=f'service={service_name}',
        )
    return helper_changed or unit_changed


def _cleanup_persistent_host_replay_artifacts(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
    force: bool = False,
) -> bool:
    """Disable and remove per-VM host replay artifacts when no longer needed."""
    records = manifest._persistent_attachment_records_for_vm(cfg, cfg_path)
    if records and not force:
        return False
    service_name = manifest._persistent_host_replay_service_name(cfg.vm.name)
    unit_path = Path('/etc/systemd/system') / service_name
    approved_manifest = manifest._persistent_host_replay_manifest_path(cfg)
    if dry_run:
        print(
            'DRYRUN: would disable and remove persistent host replay artifacts '
            f'for VM {cfg.vm.name}'
        )
        return True
    mgr = CommandManager.current()
    with mgr.step(
        'Remove persistent host replay artifacts',
        why=(
            'No persistent attachment remains, so the per-VM root replay unit '
            'and approved manifest must not outlive their desired state.'
        ),
        approval_scope=f'persistent-host-replay-cleanup:{cfg.vm.name}',
    ):
        mgr.submit(
            ['systemctl', 'disable', '--now', service_name],
            sudo=True,
            role='modify',
            check=False,
            summary='Disable persistent host replay service',
            detail=f'service={service_name}',
        )
        mgr.submit(
            ['rm', '-f', '--', str(unit_path), str(approved_manifest)],
            sudo=True,
            role='modify',
            summary='Remove persistent host replay unit and manifest',
            detail=f'unit={unit_path} manifest={approved_manifest}',
        )
        mgr.submit(
            ['systemctl', 'daemon-reload'],
            sudo=True,
            role='modify',
            summary='Reload systemd after replay cleanup',
        )
    return True


def _reconcile_persistent_host_binds(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
    vm_running: bool | None = None,
) -> None:
    """Converge host binds and the VM's persistent-root mapping."""
    records = manifest._persistent_attachment_records_for_vm(cfg, cfg_path)
    if records or manifest._persistent_host_replay_state_needed(cfg, cfg_path):
        _run_persistent_host_replay(
            cfg, cfg_path, dry_run=dry_run, prune_stale=True
        )
    if any(record.enabled for record in records):
        _ensure_persistent_root_vm_mapping(
            cfg, dry_run=dry_run, vm_running=vm_running
        )


def _ensure_persistent_root_vm_mapping(
    cfg: AgentVMConfig,
    *,
    dry_run: bool,
    vm_running: bool | None = None,
) -> None:
    source = str(_persistent_root_host_dir(cfg))
    tag = PERSISTENT_ROOT_VIRTIOFS_TAG
    # vm_share_mappings escalates to sudo internally only when the
    # unprivileged read fails, so one call covers both cases.
    mappings = vm_share_mappings(cfg, use_sudo=True)
    if any(src == source and t == tag for src, t in mappings):
        return
    attach_vm_share(
        cfg,
        source,
        tag,
        dry_run=dry_run,
        vm_running=vm_running,
    )


def _prepare_persistent_attachment_host_and_vm(
    cfg: AgentVMConfig,
    attachment: object,
    *,
    dry_run: bool,
    vm_running: bool | None,
) -> None:
    """Prepare only the VM mapping; binds require a persisted approved record.

    The actual host bind is intentionally deferred until after the attachment
    record and approved manifest exist, when ``_reconcile_persistent_host_binds``
    invokes the descriptor-pinned privileged helper.
    """
    del cfg, attachment, dry_run, vm_running
    # Host preparation starts only after the owner-scoped record is persisted.
