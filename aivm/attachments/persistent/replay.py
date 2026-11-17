"""Guest-side replay install + reconcile orchestration."""

from __future__ import annotations

import shlex
from pathlib import Path

from loguru import logger as log

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...errors import CommandControlError
from ...persistent_replay import (
    PERSISTENT_ATTACHMENT_REPLAY_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    PERSISTENT_REPLAY_DEGRADED_EXIT,
    PERSISTENT_REPLAY_REPAIR_EXIT,
    persistent_replay_python,
    persistent_replay_service_unit,
)
from . import host_bind, inspection, manifest, transport


def _install_persistent_attachment_replay(
    cfg: AgentVMConfig,
    ip: str,
    *,
    dry_run: bool,
    check: bool = True,
) -> bool:
    replay_py = persistent_replay_python()
    service_text = persistent_replay_service_unit()
    helper_changed = transport._install_guest_text_if_changed(
        cfg,
        ip,
        target=PERSISTENT_ATTACHMENT_REPLAY_BIN,
        text=replay_py,
        mode='0755',
        label='guest replay helper',
        dry_run=dry_run,
        check=check,
    )
    unit_changed = transport._install_guest_text_if_changed(
        cfg,
        ip,
        target=f'/etc/systemd/system/{PERSISTENT_ATTACHMENT_REPLAY_SERVICE}',
        text=service_text,
        mode='0644',
        label='guest replay unit',
        dry_run=dry_run,
        check=check,
    )
    if dry_run:
        return False
    if unit_changed:
        transport._run_guest_root_script(
            cfg,
            ip,
            script=(
                'set -euo pipefail; '
                'sudo -n systemctl daemon-reload; '
                f'sudo -n systemctl enable {PERSISTENT_ATTACHMENT_REPLAY_SERVICE}'
            ),
            summary='Refresh persistent attachment replay unit',
            detail='Reload systemd and ensure the persistent attachment replay service stays enabled after the unit file changes.',
            dry_run=dry_run,
            check=check,
        )
    return helper_changed or unit_changed


def _reconcile_persistent_attachments_in_guest(
    cfg: AgentVMConfig,
    cfg_path: Path,
    ip: str,
    *,
    dry_run: bool,
    replay_even_if_unchanged: bool = True,
    continue_on_error: bool = False,
    reconcile_host: bool = True,
    host_exports_ready: bool = False,
    only_guest_dst: str = '',
    preserve_live_mounts: bool = False,
    symlink_checks: list[inspection.SymlinkCheck] | None = None,
) -> None:
    # Host writes the canonical desired-state manifest first. The guest-local
    # manifest and helper are refreshed next. Scoped foreground operations use
    # ``only_guest_dst`` so they touch one attachment without reconciling
    # unrelated live work. Code/ssh session entry additionally requests
    # ``preserve_live_mounts``; explicit attach may still repair the selected
    # mount. Boot/maintenance callers omit the scope and retain full replay.
    def _strict_reconcile() -> None:
        manifest._sync_persistent_attachment_manifest_on_host(
            cfg, cfg_path, dry_run=dry_run
        )
        if reconcile_host:
            if host_exports_ready:
                # A stopped-VM start path may have staged the saved exports
                # before boot so guest replay cannot bind empty token holders.
                # Only the VM-level persistent-root mapping remains here.
                host_bind._ensure_persistent_root_vm_mapping(
                    cfg, dry_run=dry_run, vm_running=True
                )
            else:
                host_bind._reconcile_persistent_host_binds(
                    cfg,
                    cfg_path,
                    dry_run=dry_run,
                    vm_running=True,
                    only_guest_dst=only_guest_dst,
                    preserve_live_binds=preserve_live_mounts,
                )
        live = None
        symlinks_changed = False
        if preserve_live_mounts and symlink_checks is not None and not dry_run:
            live = inspection.inspect_foreground(
                cfg, ip, only_guest_dst, list(dict.fromkeys(symlink_checks)),
            )
            symlinks_changed = inspection.apply_symlink_repairs(cfg, ip, live)
        guest_manifest_changed = (
            manifest._sync_persistent_attachment_manifest_to_guest(
                cfg,
                ip,
                cfg_path=cfg_path,
                dry_run=dry_run,
                check=not continue_on_error,
                guest_directory_exists=(
                    live.manifest_directory if live is not None else None
                ),
            )
        )
        replay_changed = False
        if live is None or not all(
            live.files[path] for path in (
                PERSISTENT_ATTACHMENT_REPLAY_BIN,
                f'/etc/systemd/system/{PERSISTENT_ATTACHMENT_REPLAY_SERVICE}',
            )
        ):
            replay_changed = _install_persistent_attachment_replay(
                cfg, ip, dry_run=dry_run, check=not continue_on_error,
            )
        if dry_run:
            return
        if (
            replay_even_if_unchanged or guest_manifest_changed
            or replay_changed or live is not None
        ):
            replay_script = f'sudo -n {shlex.quote(PERSISTENT_ATTACHMENT_REPLAY_BIN)}'
            if only_guest_dst:
                replay_script += (
                    ' --only-guest-dst ' + shlex.quote(only_guest_dst)
                )
                if preserve_live_mounts:
                    replay_script += ' --preserve-live-mounts'
            if preserve_live_mounts:
                # Any intervening repair invalidates the batched mount result.
                # Re-read against the new manifest and path resolution.
                inspected = (
                    live.replay if live is not None and not (
                        guest_manifest_changed or replay_changed or symlinks_changed
                    ) else None
                )
                if inspected is None:
                    with CommandManager.current().step(
                        'Inspect requested guest mount',
                        why='Read live mount identity before deciding whether any repair needs approval.',
                    ):
                        inspected = transport._run_guest_root_script(
                            cfg, ip, script=replay_script + ' --check',
                            summary='Inspect requested persistent attachment',
                            detail=f'target={only_guest_dst}', dry_run=False,
                            role='read', allowed_exit_codes=(
                                0, PERSISTENT_REPLAY_DEGRADED_EXIT,
                                PERSISTENT_REPLAY_REPAIR_EXIT,
                            ),
                        )
                assert inspected is not None
                if inspected.code not in (
                    0, PERSISTENT_REPLAY_DEGRADED_EXIT, PERSISTENT_REPLAY_REPAIR_EXIT,
                ):
                    raise RuntimeError(
                        inspected.stderr or 'guest mount inspection failed'
                    )
                if inspected.code != PERSISTENT_REPLAY_REPAIR_EXIT:
                    if inspected.code == PERSISTENT_REPLAY_DEGRADED_EXIT:
                        log.warning('guest-persistent-replay: {}', inspected.stderr.strip())
                    else:
                        log.info('Guest workspace verified at {}.', only_guest_dst)
                    return
                log.info(
                    'Guest workspace repair needed: {}',
                    inspected.stderr.strip() or only_guest_dst,
                )
            replay_result = transport._run_guest_root_script(
                cfg,
                ip,
                script=replay_script,
                summary='Replay persistent attachment mounts inside guest',
                detail=(
                    'Verify and repair the requested guest-visible persistent '
                    f'attachment only: {only_guest_dst}'
                    if only_guest_dst
                    else 'Verify and repair guest-visible persistent attachment bind mounts from the persisted manifest.'
                ),
                dry_run=dry_run,
                check=not continue_on_error,
                allowed_exit_codes=(0, PERSISTENT_REPLAY_DEGRADED_EXIT),
            )
            if replay_result is not None:
                code = int(
                    getattr(
                        replay_result,
                        'code',
                        getattr(replay_result, 'returncode', 0),
                    )
                )
                stderr = str(
                    getattr(replay_result, 'stderr', '') or ''
                ).strip()
                if stderr:
                    for line in stderr.splitlines():
                        log.warning('guest-persistent-replay: {}', line)
                if code == PERSISTENT_REPLAY_DEGRADED_EXIT:
                    log.warning(
                        'Guest persistent attachment replay completed in '
                        'degraded mode for VM {}; conflicting or unavailable '
                        'live state was left non-destructively as encountered.',
                        cfg.vm.name,
                    )
                elif code != 0:
                    stdout = str(
                        getattr(replay_result, 'stdout', '') or ''
                    ).strip()
                    raise RuntimeError(
                        stderr or stdout or f'guest replay failed code={code}'
                    )

    if not continue_on_error:
        _strict_reconcile()
        return
    outer_manager = CommandManager.current()
    isolated_manager = CommandManager(
        yes=outer_manager.yes,
        yes_sudo=outer_manager.yes_sudo,
        auto_approve_readonly_sudo=outer_manager.auto_approve_readonly_sudo,
    )
    CommandManager.activate(isolated_manager)
    try:
        _strict_reconcile()
    except CommandControlError:
        # A declined or unapproved prompt is the user's decision, not a
        # recoverable guest failure; best-effort must not continue past it.
        raise
    except Exception as ex:  # pragma: no cover - guest runtime path
        log.warning(
            'persistent-reconcile: VM {} ip={} failed but restore will continue: {}',
            cfg.vm.name,
            ip,
            ex,
        )
    finally:
        CommandManager.activate(outer_manager)
