"""Guest-side virtiofs fd guard drift detection and application.

``aivm vm update`` reconciles the guard (see ``aivm/fdguard.py`` and
``docs/source/virtiofs.rst``) against ``virtiofs.fd_guard*`` config the same
way it reconciles libvirt hardware: probe the live state, plan the delta,
apply on approval. The guard lives inside the guest, so both probe and apply
run over SSH and are only possible while the VM is up and reachable —
otherwise detection reports a note instead of drift and the next update
retries. New VMs do not need this path; cloud-init installs the guard at
first boot when enabled.
"""

from __future__ import annotations

import shlex

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...errors import AIVMError
from ...fdguard import (
    FDGUARD_TIMER,
    fdguard_expected_hashes,
    fdguard_install_script,
    fdguard_probe_script,
    fdguard_uninstall_script,
    parse_fdguard_probe,
)
from ...runtime import require_ssh_identity, ssh_base_args
from ...status import probe_ssh_ready
from ..connectivity import get_ip_cached
from .models import FdGuardDrift, VMUpdateDrift


def _guest_ssh_cmd(cfg: AgentVMConfig, ip: str, script: str) -> list[str]:
    """Build the SSH command that runs ``script`` as one quoted sh -c arg."""
    ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    return [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
            connect_timeout=10,
            batch_mode=True,
        ),
        f'{cfg.vm.user}@{ip}',
        f'sh -c {shlex.quote(script)}',
    ]


def _fdguard_drift(
    cfg: AgentVMConfig, *, vm_running: bool
) -> tuple[FdGuardDrift | None, tuple[str, ...]]:
    """Compare guest guard state against ``virtiofs.fd_guard*`` config.

    Returns ``(drift-or-None, notes)``. Probe failures are notes, not
    errors: the guard must never block an otherwise valid hardware update.
    """
    desired = bool(cfg.virtiofs.fd_guard)
    if not vm_running:
        return None, (
            'VM is not running; guest virtiofs fd guard state was not '
            'verified. Rerun `aivm vm update` while the VM is up (new VMs '
            'install the guard via cloud-init).',
        )
    ip = get_ip_cached(cfg)
    if not ip or not probe_ssh_ready(cfg, ip).ok:
        return None, (
            'Could not reach the guest over SSH; virtiofs fd guard state '
            'was not verified.',
        )
    res = CommandManager.current().run(
        _guest_ssh_cmd(cfg, ip, fdguard_probe_script()),
        sudo=False,
        check=False,
        capture=True,
        timeout=30,
        summary=f'Probe virtiofs fd guard state in VM {cfg.vm.name}',
    )
    if res.code != 0:
        return None, (
            'Guest virtiofs fd guard probe failed; state was not verified.',
        )
    state = parse_fdguard_probe(res.stdout or '')
    installed = state.get('installed') == 'yes'
    timer_enabled = state.get('timer_enabled') == 'enabled'

    if not desired:
        if installed or timer_enabled:
            return (
                FdGuardDrift(
                    action='uninstall',
                    reason=(
                        'virtiofs.fd_guard is disabled in config but the '
                        'guard is installed in the guest'
                    ),
                    ip=ip,
                ),
                (),
            )
        return None, ()

    if not installed:
        return (
            FdGuardDrift(
                action='install',
                reason='guard is not installed in the guest',
                ip=ip,
            ),
            (),
        )
    if not timer_enabled:
        return (
            FdGuardDrift(
                action='install',
                reason=f'{FDGUARD_TIMER} is not enabled in the guest',
                ip=ip,
            ),
            (),
        )
    expected = fdguard_expected_hashes(
        threshold=int(cfg.virtiofs.fd_guard_threshold),
        interval_sec=int(cfg.virtiofs.fd_guard_interval_sec),
    )
    stale = sorted(
        key for key, want in expected.items() if state.get(key, '') != want
    )
    if stale:
        pretty = ', '.join(key.removeprefix('sha_') for key in stale)
        return (
            FdGuardDrift(
                action='install',
                reason=(
                    'installed guard files differ from config-rendered '
                    f'content ({pretty})'
                ),
                ip=ip,
            ),
            (),
        )
    return None, ()


def _apply_fdguard_drift(
    cfg: AgentVMConfig, drift: VMUpdateDrift, *, dry_run: bool
) -> bool:
    """Install/refresh or uninstall the guard in the guest over SSH."""
    fd = drift.fd_guard
    if fd is None:
        return False
    if fd.action == 'uninstall':
        script = fdguard_uninstall_script()
    else:
        script = fdguard_install_script(
            threshold=int(cfg.virtiofs.fd_guard_threshold),
            interval_sec=int(cfg.virtiofs.fd_guard_interval_sec),
        )
    if dry_run:
        print(
            f'DRYRUN: would {fd.action} virtiofs fd guard in guest '
            f'({fd.reason})'
        )
        return True
    ip = fd.ip or get_ip_cached(cfg)
    if not ip:
        raise AIVMError(
            'Cannot reconcile the virtiofs fd guard: guest IP is '
            'unavailable. Bring the VM up and rerun `aivm vm update`, or '
            f'use `aivm vm fdguard --action {fd.action}` directly.'
        )
    CommandManager.current().run(
        _guest_ssh_cmd(cfg, ip, script),
        sudo=False,
        check=True,
        capture=True,
        timeout=120,
        summary=f'{fd.action.capitalize()} virtiofs fd guard in VM {cfg.vm.name}',
        detail=(
            'Reconciles the aivm-virtiofs-guard systemd timer inside the '
            'guest (via guest passwordless sudo) to match virtiofs.fd_guard '
            'config.'
        ),
    )
    if fd.action == 'uninstall':
        print(f'Uninstalled virtiofs fd guard from {cfg.vm.name}.')
    else:
        print(
            f'Installed/refreshed virtiofs fd guard in {cfg.vm.name} '
            f'(threshold={cfg.virtiofs.fd_guard_threshold}, '
            f'interval={cfg.virtiofs.fd_guard_interval_sec}s).'
        )
    return True
