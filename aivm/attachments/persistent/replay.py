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
    persistent_replay_python,
    persistent_replay_service_unit,
)
from . import host_bind, manifest, transport


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
    only_guest_dst: str = '',
    preserve_live_mounts: bool = False,
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
            host_bind._reconcile_persistent_host_binds(
                cfg,
                cfg_path,
                dry_run=dry_run,
                vm_running=True,
                only_guest_dst=only_guest_dst,
                preserve_live_binds=preserve_live_mounts,
            )
        guest_manifest_changed = (
            manifest._sync_persistent_attachment_manifest_to_guest(
                cfg,
                ip,
                cfg_path=cfg_path,
                dry_run=dry_run,
                check=not continue_on_error,
            )
        )
        replay_changed = _install_persistent_attachment_replay(
            cfg,
            ip,
            dry_run=dry_run,
            check=not continue_on_error,
        )
        if dry_run:
            return
        if replay_even_if_unchanged or guest_manifest_changed or replay_changed:
            replay_script = f'sudo -n {shlex.quote(PERSISTENT_ATTACHMENT_REPLAY_BIN)}'
            if only_guest_dst:
                replay_script += (
                    ' --only-guest-dst ' + shlex.quote(only_guest_dst)
                )
                if preserve_live_mounts:
                    replay_script += ' --preserve-live-mounts'
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
