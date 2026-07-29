"""Libvirt domain inspection and power-state helpers."""

from __future__ import annotations

import os
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..errors import AIVMError
from ..privilege import virsh_needs_sudo
from ..runtime import virsh_cmd
from .connectivity import get_ip_cached

log = logger


def _vm_defined(name: str) -> bool:
    mgr = CommandManager.current()
    if mgr.current_plan() is None:
        with mgr.step(
            'Inspect VM definition',
            why=(
                'Check whether the libvirt domain already exists before '
                'deciding whether create, recreate, or cleanup work is needed.'
            ),
            approval_scope=f'vm-defined:{name}',
        ):
            res = mgr.submit(
                virsh_cmd('dominfo', name),
                sudo=virsh_needs_sudo(),
                role='read',
                check=False,
                capture=True,
                eager=True,
                summary=f'Inspect VM definition {name}',
            ).result()
    else:
        res = mgr.run(
            virsh_cmd('dominfo', name),
            sudo=virsh_needs_sudo(),
            role='read',
            check=False,
            capture=True,
            summary=f'Inspect VM definition {name}',
        )
    return res.code == 0


def domain_is_defined(name: str) -> bool:
    """Return whether the system libvirt connection defines ``name``."""
    return _vm_defined(name)


@dataclass(frozen=True)
class DomainRemovalReport:
    """Observed result of one libvirt domain removal."""

    storage_paths: tuple[Path, ...]
    retained_storage_paths: tuple[Path, ...]

    @property
    def storage_removed(self) -> bool:
        return not self.retained_storage_paths


def domain_file_storage_paths(name: str) -> tuple[Path, ...]:
    """Return every file-backed disk path from the live domain XML."""
    if not _vm_defined(name):
        return ()
    mgr = CommandManager.current()
    res = mgr.run(
        virsh_cmd('dumpxml', name),
        sudo=virsh_needs_sudo(),
        role='read',
        check=False,
        capture=True,
        summary=f'Capture managed storage coordinates for VM {name}',
    )
    if res.code != 0:
        detail = (res.stderr or res.stdout or '').strip()
        raise AIVMError(
            f'Could not capture storage paths before deleting VM {name!r}: '
            f'{detail or "virsh dumpxml failed"}'
        )
    try:
        root = ET.fromstring(res.stdout)
    except ET.ParseError as ex:
        raise AIVMError(
            f'Could not parse libvirt XML before deleting VM {name!r}: {ex}'
        ) from ex
    paths: list[Path] = []
    seen: set[str] = set()
    for disk in root.findall('./devices/disk'):
        if str(disk.attrib.get('device', 'disk')).strip() != 'disk':
            continue
        source = disk.find('source')
        if source is None:
            raise AIVMError(
                f'VM {name!r} has a disk without a source; AIVM cannot '
                'verify storage deletion.'
            )
        raw = str(source.attrib.get('file', '')).strip()
        if not raw:
            source_kind = ', '.join(
                f'{key}={value!r}' for key, value in sorted(source.attrib.items())
            ) or '(no source attributes)'
            raise AIVMError(
                f'VM {name!r} uses non-file or otherwise unverifiable disk '
                f'storage ({source_kind}). Refusing deletion because AIVM '
                'cannot prove that every managed disk was removed.'
            )
        if raw in seen:
            continue
        path = Path(raw)
        if not path.is_absolute():
            raise AIVMError(
                f'VM {name!r} has a non-absolute file-backed disk path: {raw!r}'
            )
        seen.add(raw)
        paths.append(path)
    return tuple(paths)


def _host_path_exists(path: Path) -> bool:
    result = CommandManager.current().run(
        ['test', '-e', str(path)],
        sudo=virsh_needs_sudo(),
        role='read',
        check=False,
        capture=True,
        summary=f'Verify managed VM storage removal: {path}',
    )
    return result.code == 0


def _destroy_and_undefine_vm(
    name: str,
    *,
    storage_paths: tuple[Path, ...] | None = None,
) -> DomainRemovalReport:
    """Remove one domain without ever falling back to retained storage."""
    expected = None if storage_paths is None else tuple(storage_paths)
    captured = (
        domain_file_storage_paths(name)
        if expected is None
        else expected
    )

    def require_expected_inventory() -> None:
        if expected is None:
            return
        current = domain_file_storage_paths(name)
        expected_names = {
            os.path.abspath(os.fspath(path)) for path in expected
        }
        current_names = {
            os.path.abspath(os.fspath(path)) for path in current
        }
        if current_names != expected_names:
            added = sorted(current_names - expected_names)
            removed = sorted(expected_names - current_names)
            details: list[str] = []
            if added:
                details.append(
                    'new live domain disks:\n'
                    + '\n'.join(f'  - {item}' for item in added)
                )
            if removed:
                details.append(
                    'expected disks no longer present:\n'
                    + '\n'.join(f'  - {item}' for item in removed)
                )
            raise AIVMError(
                f'VM {name!r} storage inventory changed before undefine. '
                'Refusing --remove-all-storage.\n'
                + '\n'.join(details)
            )

    mgr = CommandManager.current()
    if _vm_defined(name):
        require_expected_inventory()
        mgr.run(
            virsh_cmd('destroy', name),
            sudo=virsh_needs_sudo(),
            role='modify',
            check=False,
            capture=True,
        )
        if _vm_defined(name):
            # The journal comparison is repeated after shutdown, immediately
            # before storage-removing undefine attempts. This catches disks
            # attached during an interrupted or concurrent deletion window.
            require_expected_inventory()
        # Different libvirt states require different metadata flags, but every
        # attempt retains --remove-all-storage. Silently retrying without that
        # flag destroys the only record that identifies orphaned disks.
        attempts = [
            virsh_cmd(
                'undefine',
                name,
                '--managed-save',
                '--snapshots-metadata',
                '--nvram',
                '--remove-all-storage',
            ),
            virsh_cmd(
                'undefine', name, '--nvram', '--remove-all-storage'
            ),
            virsh_cmd('undefine', name, '--remove-all-storage'),
        ]
        errs: list[str] = []
        for cmd in attempts:
            res = mgr.run(
                cmd,
                sudo=virsh_needs_sudo(),
                role='modify',
                check=False,
                capture=True,
            )
            if res.code != 0:
                msg = (res.stderr or res.stdout or '').strip()
                if msg:
                    errs.append(f'{cmd}: {msg}')
            if not _vm_defined(name):
                break
        if _vm_defined(name):
            detail = '\n'.join(errs[-3:]) if errs else '(no details)'
            raise AIVMError(
                f'Failed to undefine VM {name}; domain is still present after '
                f'storage-removing retries.\n{detail}'
            )
    retained = tuple(path for path in captured if _host_path_exists(path))
    return DomainRemovalReport(
        storage_paths=captured, retained_storage_paths=retained
    )

def vm_exists(cfg: AgentVMConfig, *, dry_run: bool = False) -> bool:
    if dry_run:
        return False
    return _vm_defined(cfg.vm.name)

def _is_vm_active(state: str) -> bool:
    """Return True if the libvirt state indicates an active domain.

    Active states include 'running', 'idle', 'paused', 'blocked', 'pmsuspended',
    and transient states like 'in shutdown' or 'shutting down'. Inactive
    states include 'shut off', 'crashed'.
    """
    state = state.lower().strip()
    # Active states: running, idle, paused, blocked, pmsuspended, in shutdown, shutting down
    active_states = [
        'running',
        'idle',
        'paused',
        'blocked',
        'pmsuspended',
        'in shutdown',
        'shutting down',
    ]
    return any(s in state for s in active_states)

def _get_vm_state(name: str) -> tuple[int, str, str]:
    """Get the current state of a VM.

    Returns a tuple of (return_code, state_string, error_string).
    The state and error strings are lowercased and stripped.
    On success, state contains the VM state and error is empty.
    On failure, state is empty and error contains the error message.
    """
    mgr = CommandManager.current()
    res = mgr.run(
        virsh_cmd('domstate', name),
        sudo=virsh_needs_sudo(),
        role='read',
        check=False,
        capture=True,
        summary=f'Get state of VM {name}',
    )
    state = (res.stdout or '').strip().lower()
    error = (res.stderr or '').strip().lower()
    return (res.code, state, error)

def _wait_for_vm_state(
    name: str,
    target_state: str,
    *,
    timeout_s: int = 120,
    poll_interval_s: int = 2,
) -> None:
    """Wait for a VM to reach a target state.

    Polls the VM state until it matches ``target_state`` or the timeout
    expires. Raises ``RuntimeError`` if the timeout is reached before
    the target state is observed, or if the domstate command fails.
    """

    elapsed = 0
    last_state = ''
    last_error = ''
    while elapsed < timeout_s:
        code, state, error = _get_vm_state(name)
        if code != 0:
            # Command failed - this is an error, not just a state change
            last_error = error
            raise RuntimeError(
                f'Failed to get state for VM {name} (code={code}). '
                f'Error: {last_error}'
            )
        if target_state in state:
            return
        time.sleep(poll_interval_s)
        elapsed += poll_interval_s
        last_state = state
    raise RuntimeError(
        f'Timeout waiting for VM {name} to reach state {target_state!r} '
        f'(current state: {last_state!r}) after {timeout_s}s.'
    )

def _wait_for_vm_not_state(
    name: str,
    exclude_state: str,
    *,
    timeout_s: int = 10,
    poll_interval_s: int = 1,
) -> None:
    """Wait for a VM to leave a specific state.

    Polls the VM state until it no longer matches ``exclude_state`` or the
    timeout expires. Raises ``RuntimeError`` if the timeout is reached or
    if the domstate command fails.
    This is useful for waiting for a VM to transition out of a suspended state.
    """

    elapsed = 0
    last_state = ''
    last_error = ''
    while elapsed < timeout_s:
        code, state, error = _get_vm_state(name)
        if code != 0:
            # Command failed - this is an error, not a state change
            last_error = error
            raise RuntimeError(
                f'Failed to get state for VM {name} (code={code}). '
                f'Error: {last_error}'
            )
        if exclude_state not in state:
            return
        time.sleep(poll_interval_s)
        elapsed += poll_interval_s
        last_state = state
    raise RuntimeError(
        f'Timeout waiting for VM {name} to leave state {exclude_state!r} '
        f'(still in state: {last_state!r}) after {timeout_s}s.'
    )

def shutdown_vm(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    """Gracefully shut down the VM using ACPI shutdown signal.

    This sends a graceful shutdown signal to the guest OS. If the guest
    does not shut down within a reasonable time, callers may need to use
    ``destroy_vm`` for a forced shutdown.
    """
    name = cfg.vm.name
    if dry_run:
        log.info('DRYRUN: virsh shutdown {}', name)
        return
    mgr = CommandManager.current()
    with mgr.intent(
        f'Shut down VM {name}',
        why='Gracefully stop the VM by sending an ACPI shutdown signal to the guest OS.',
        role='modify',
    ):
        # First check if VM is active
        code, state, error = _get_vm_state(name)
        if code != 0:
            msg = error or 'unknown error'
            raise RuntimeError(
                f'Failed to get state for VM {name} (code={code}). Error: {msg}'
            )
        if not _is_vm_active(state):
            log.info(
                'VM {} is not active (state={}); nothing to do.', name, state
            )
            return

        # Handle pmsuspended specially - resume first since ACPI shutdown
        # requires the guest to be running to receive the signal
        if 'pmsuspended' in state:
            log.info('VM {} is pmsuspended; resuming first', name)
            res = mgr.run(
                virsh_cmd('resume', name),
                sudo=virsh_needs_sudo(),
                role='modify',
                check=False,
                capture=True,
                summary='Resume pmsuspended VM',
            )
            if res.code != 0:
                msg = (res.stderr or res.stdout or '').strip()
                raise RuntimeError(f'Failed to resume VM {name}.\n{msg}')
            # Wait for VM to transition out of pmsuspended
            _wait_for_vm_not_state(
                name, 'pmsuspended', timeout_s=10, poll_interval_s=1
            )
            # Re-check state after resume to ensure VM is in a valid state for shutdown
            code, state, error = _get_vm_state(name)
            if code != 0:
                msg = error or 'unknown error'
                raise RuntimeError(
                    f'Failed to get state for VM {name} after resume (code={code}). '
                    f'Error: {msg}'
                )
            if not _is_vm_active(state):
                log.info(
                    'VM {} transitioned to inactive state {} after resume; nothing to do.',
                    name,
                    state,
                )
                return
            log.info('VM {} resumed (state={})', name, state)

        # Send ACPI shutdown signal
        res = mgr.run(
            virsh_cmd('shutdown', name),
            sudo=virsh_needs_sudo(),
            role='modify',
            check=False,
            capture=True,
            summary=f'Send ACPI shutdown signal to VM {name}',
        )
        if res.code != 0:
            msg = (res.stderr or res.stdout or '').strip()
            raise RuntimeError(
                f'Failed to send shutdown signal to VM {name}.\n{msg}'
            )
        log.info('Shutdown signal sent to VM {}', name)

def restart_vm(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    """Gracefully restart the VM (shutdown then start).

    This sends a graceful shutdown signal to the guest OS, waits for it to
    stop, and then starts the VM again. If the guest does not shut down
    within a reasonable time, this may need to be followed by a forced
    restart using ``destroy_vm`` and ``create_or_start_vm``.

    This operation requires the VM to already exist; it will not create
    a new VM.
    """
    name = cfg.vm.name
    if dry_run:
        log.info('DRYRUN: restart VM {}', name)
        return

    # Verify the VM exists before attempting restart
    if not _vm_defined(name):
        raise AIVMError(
            f'VM {name!r} does not exist. Restart requires an existing VM; '
            f'use `aivm vm up` to create and start it.'
        )

    mgr = CommandManager.current()
    with mgr.intent(
        f'Restart VM {name}',
        why='Gracefully stop and then start the VM to apply changes or recover from transient issues.',
        role='modify',
    ):
        # First check if VM is active
        code, state, error = _get_vm_state(name)
        if code != 0:
            msg = error or 'unknown error'
            raise RuntimeError(
                f'Failed to get state for VM {name} (code={code}). Error: {msg}'
            )

        if _is_vm_active(state):
            # Handle pmsuspended specially - resume it first, then shutdown
            if 'pmsuspended' in state:
                log.info('VM {} is pmsuspended; resuming first', name)
                res = mgr.run(
                    virsh_cmd('resume', name),
                    sudo=virsh_needs_sudo(),
                    role='modify',
                    check=False,
                    capture=True,
                    summary='Resume pmsuspended VM',
                )
                if res.code != 0:
                    msg = (res.stderr or res.stdout or '').strip()
                    raise RuntimeError(f'Failed to resume VM {name}.\n{msg}')
                # Wait for VM to transition out of pmsuspended
                _wait_for_vm_not_state(
                    name, 'pmsuspended', timeout_s=10, poll_interval_s=1
                )
                # Re-check state after resume to ensure VM is in a valid state for shutdown
                code, state, error = _get_vm_state(name)
                if code != 0:
                    msg = error or 'unknown error'
                    raise RuntimeError(
                        f'Failed to get state for VM {name} after resume (code={code}). '
                        f'Error: {msg}'
                    )
                if not _is_vm_active(state):
                    log.info(
                        'VM {} transitioned to inactive state {} after resume; starting it.',
                        name,
                        state,
                    )
                    _start_vm(name)
                    log.info('VM {} restarted', name)
                    return
                log.info('VM {} resumed (state={})', name, state)

            log.info('Sending shutdown signal to VM {} (state={})', name, state)
            # Send ACPI shutdown signal
            res = mgr.run(
                virsh_cmd('shutdown', name),
                sudo=virsh_needs_sudo(),
                role='modify',
                check=False,
                capture=True,
                summary='Send ACPI shutdown signal to VM',
            )
            if res.code != 0:
                msg = (res.stderr or res.stdout or '').strip()
                raise RuntimeError(
                    f'Failed to send shutdown signal to VM {name}.\n{msg}'
                )
            # Wait for the VM to actually shut down before starting it again
            log.info('Waiting for VM {} to shut down...', name)
            _wait_for_vm_state(
                name, 'shut off', timeout_s=120, poll_interval_s=2
            )
            log.info('VM {} has shut down', name)
        else:
            log.info(
                'VM {} is not active (state={}); starting it.', name, state
            )

        # Start the VM (use start_vm helper, not create_or_start_vm)
        log.info('Starting VM {}', name)
        _start_vm(name)
        log.info('VM {} restarted', name)

def _start_vm(name: str) -> None:
    """Start a defined VM by name.

    This is a low-level helper that only starts an existing domain;
    it does not create or recreate the VM.
    """
    mgr = CommandManager.current()
    mgr.run(
        virsh_cmd('start', name),
        sudo=virsh_needs_sudo(),
        role='modify',
        check=True,
        summary=f'Start VM {name}',
    )

def destroy_vm(
    cfg: AgentVMConfig, *, dry_run: bool = False
) -> DomainRemovalReport | None:
    name = cfg.vm.name
    if dry_run:
        log.info('DRYRUN: virsh destroy/undefine {}', name)
        return None
    mgr = CommandManager.current()
    with mgr.intent(
        f'Destroy VM {name}',
        why='Remove the libvirt domain and its related managed definition state.',
        role='modify',
    ):
        report = _destroy_and_undefine_vm(name)
    if report.retained_storage_paths:
        rendered = '\n'.join(
            f'  - {path}' for path in report.retained_storage_paths
        )
        raise AIVMError(
            f'VM {name!r} was undefined, but storage remains:\n{rendered}'
        )
    log.info('VM removed with storage verified absent: {}', name)
    return report

def vm_status(cfg: AgentVMConfig) -> str:
    name = cfg.vm.name
    mgr = CommandManager.current()
    with mgr.intent(
        f'Inspect VM {name}',
        why='Read the live libvirt domain details and cached IP for this VM.',
        role='read',
    ):
        dom = mgr.run(
            virsh_cmd('dominfo', name),
            sudo=virsh_needs_sudo(),
            role='read',
            check=False,
            capture=True,
            summary=f'Inspect VM definition {name}',
        )
        if dom.code != 0:
            return f'VM not found: {name}\n'
        state = mgr.run(
            virsh_cmd('domstate', name),
            sudo=virsh_needs_sudo(),
            role='read',
            check=False,
            capture=True,
            summary=f'Inspect VM runtime state {name}',
        ).stdout.strip()
        ip = get_ip_cached(cfg) or ''
        return (
            dom.stdout
            + f'\nstate={state}\n'
            + (f'cached_ip={ip}\n' if ip else '')
        )
