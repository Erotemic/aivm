"""Host-side bind reconcile + replay-service install for persistent attachments."""

from __future__ import annotations

from pathlib import Path

from loguru import logger as log

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...persistent_replay import (
    PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN,
    PERSISTENT_ROOT_VIRTIOFS_TAG,
    persistent_host_replay_python,
    persistent_host_replay_service_unit,
)
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
    if dry_run:
        print(f'DRYRUN: would create persistent-root parent directory {target}')
        return
    if not _needs_mkdir(target):
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
    _ensure_persistent_host_replay_helper(dry_run=dry_run)
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
