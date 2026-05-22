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
from ...vm import attach_vm_share, vm_share_mappings
from ...vm.share import AttachmentMode, ResolvedAttachment
from ..resolve import _normalize_attachment_access
from ..shared_root import (
    _needs_privileged_mkdir,
    _shared_root_host_target,
    _target_is_bind_of,
)
from . import manifest, transport


def _install_persistent_host_bind_replay(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
) -> bool:
    del cfg_path
    helper_changed = transport._install_host_text_if_changed(
        Path(PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN),
        persistent_host_replay_python(),
        '0755',
        label='persistent host replay helper',
        dry_run=dry_run,
    )
    service_name = manifest._persistent_host_replay_service_name(cfg.vm.name)
    unit_changed = transport._install_host_text_if_changed(
        Path('/etc/systemd/system') / service_name,
        persistent_host_replay_service_unit(
            vm_name=cfg.vm.name,
            manifest_path=str(manifest._persistent_host_manifest_path(cfg)),
            export_root=str(manifest._persistent_root_host_dir(cfg)),
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


def _reconcile_persistent_host_binds(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    dry_run: bool,
    vm_running: bool | None = None,
) -> None:
    records = manifest._persistent_attachment_records_for_vm(cfg, cfg_path)
    for record in records:
        if not record.enabled:
            continue
        host_src = Path(record.source_dir).expanduser()
        if not host_src.exists():
            log.warning(
                'Skipping persistent host bind replay for VM {} because host path is missing: {}',
                cfg.vm.name,
                host_src,
            )
            continue
        if not host_src.is_dir():
            log.warning(
                'Skipping persistent host bind replay for VM {} because host path is not a directory: {}',
                cfg.vm.name,
                host_src,
            )
            continue
        attachment = ResolvedAttachment(
            vm_name=cfg.vm.name,
            mode=AttachmentMode.PERSISTENT,
            access=_normalize_attachment_access(str(record.access or 'rw')),
            source_dir=str(host_src.resolve()),
            guest_dst=str(record.guest_dst or ''),
            tag=str(record.shared_root_token or ''),
        )
        _prepare_persistent_attachment_host_and_vm(
            cfg,
            attachment,
            dry_run=dry_run,
            vm_running=vm_running,
        )


def _ensure_persistent_root_parent_dir(
    cfg: AgentVMConfig,
    *,
    dry_run: bool,
) -> None:
    target = manifest._persistent_root_host_dir(cfg)
    if dry_run:
        print(f'DRYRUN: would create persistent-root parent directory {target}')
        return
    if not _needs_privileged_mkdir(target):
        return
    mgr = CommandManager.current()
    with mgr.step(
        'Prepare persistent-root parent directory',
        why='Create the host-side persistent-root export directory used by the persistent attachment virtiofs device.',
        approval_scope=f'persistent-root-parent:{cfg.vm.name}',
    ):
        mgr.submit(
            ['mkdir', '-p', str(target)],
            sudo=True,
            role='modify',
            summary='Create persistent-root parent directory',
            detail=f'target={target}',
        )


def _ensure_persistent_root_vm_mapping(
    cfg: AgentVMConfig,
    *,
    dry_run: bool,
    vm_running: bool | None = None,
) -> None:
    source = str(manifest._persistent_root_host_dir(cfg))
    tag = PERSISTENT_ROOT_VIRTIOFS_TAG
    mappings = vm_share_mappings(cfg, use_sudo=False)
    if any(src == source and t == tag for src, t in mappings):
        return
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


def _ensure_persistent_root_host_bind(
    cfg: AgentVMConfig,
    attachment: ResolvedAttachment,
    *,
    dry_run: bool,
) -> Path:
    # Reuse the shared-root target-token layout, but stage it under the
    # dedicated persistent-root export tree so the two backends never share the
    # same virtiofs device or host export directory.
    source = Path(attachment.source_dir).resolve()
    parent = manifest._persistent_root_host_dir(cfg)
    target = parent / Path(_shared_root_host_target(cfg, attachment.tag)).name
    if dry_run:
        print(
            f'DRYRUN: would bind-mount {source} -> {target} for persistent mode'
        )
        return target
    # Read-only fast path: when the target is already a bind of the requested
    # source, the whole step is a no-op and the user does not need to be
    # prompted for sudo. _target_is_bind_of is a pure stat check that doesn't
    # need sudo and won't false-positive on unrelated mounts.
    if _target_is_bind_of(source, target):
        return target
    mgr = CommandManager.current()
    needs_parent = _needs_privileged_mkdir(parent)
    needs_target = _needs_privileged_mkdir(target)
    with mgr.step(
        'Prepare persistent-root host bind target',
        why='Ensure the persistent-root staged bind exists without tearing down stable host-side state.',
        approval_scope=f'persistent-root-host-bind:{cfg.vm.name}:{attachment.tag}',
    ):
        if needs_parent:
            mgr.submit(
                ['mkdir', '-p', str(parent)],
                sudo=True,
                role='modify',
                summary='Create persistent-root parent directory',
                detail=f'target={parent}',
            )
        if needs_target:
            mgr.submit(
                ['mkdir', '-p', str(target)],
                sudo=True,
                role='modify',
                summary='Create persistent-root bind target',
                detail=f'target={target}',
            )
        mgr.submit(
            ['mount', '--bind', str(source), str(target)],
            sudo=True,
            role='modify',
            summary='Bind requested host folder into persistent-root target',
            detail=f'source={source} target={target}',
        )
    return target


def _prepare_persistent_attachment_host_and_vm(
    cfg: AgentVMConfig,
    attachment: ResolvedAttachment,
    *,
    dry_run: bool,
    vm_running: bool | None,
) -> None:
    _ensure_persistent_root_parent_dir(cfg, dry_run=dry_run)
    _ensure_persistent_root_host_bind(
        cfg,
        attachment,
        dry_run=dry_run,
    )
    _ensure_persistent_root_vm_mapping(
        cfg,
        dry_run=dry_run,
        vm_running=vm_running,
    )
