"""Libvirt domain inspection and power-state helpers."""

from __future__ import annotations

import time

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
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
                ['virsh', 'dominfo', name],
                sudo=True,
                role='read',
                check=False,
                capture=True,
                eager=True,
                summary=f'Inspect VM definition {name}',
            ).result()
    else:
        res = mgr.run(
            ['virsh', 'dominfo', name],
            sudo=True,
            role='read',
            check=False,
            capture=True,
            summary=f'Inspect VM definition {name}',
        )
    return res.code == 0

def _destroy_and_undefine_vm(name: str) -> None:
    mgr = CommandManager.current()
    mgr.run(
        ['virsh', 'destroy', name],
        sudo=True,
        role='modify',
        check=False,
        capture=True,
    )
    # Different libvirt states require different undefine flags.
    attempts = [
        [
            'virsh',
            'undefine',
            name,
            '--managed-save',
            '--snapshots-metadata',
            '--nvram',
            '--remove-all-storage',
        ],
        [
            'virsh',
            'undefine',
            name,
            '--managed-save',
            '--snapshots-metadata',
            '--nvram',
        ],
        ['virsh', 'undefine', name, '--nvram', '--remove-all-storage'],
        ['virsh', 'undefine', name, '--nvram'],
        ['virsh', 'undefine', name, '--remove-all-storage'],
        ['virsh', 'undefine', name],
    ]
    errs: list[str] = []
    for cmd in attempts:
        res = mgr.run(
            cmd,
            sudo=True,
            role='modify',
            check=False,
            capture=True,
        )
        if res.code != 0:
            msg = (res.stderr or res.stdout or '').strip()
            if msg:
                errs.append(f'{cmd}: {msg}')
        if not _vm_defined(name):
            return
    detail = '\n'.join(errs[-4:]) if errs else '(no details)'
    raise RuntimeError(
        f'Failed to undefine VM {name}; domain is still present after retries.\n{detail}'
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
        ['virsh', 'domstate', name],
        sudo=True,
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
    import time

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
    import time

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
                ['virsh', 'resume', name],
                sudo=True,
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
            ['virsh', 'shutdown', name],
            sudo=True,
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
        raise RuntimeError(
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
                    ['virsh', 'resume', name],
                    sudo=True,
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
                ['virsh', 'shutdown', name],
                sudo=True,
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
        ['virsh', 'start', name],
        sudo=True,
        role='modify',
        check=True,
        summary=f'Start VM {name}',
    )

def destroy_vm(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    name = cfg.vm.name
    if dry_run:
        log.info('DRYRUN: virsh destroy/undefine {}', name)
        return
    mgr = CommandManager.current()
    with mgr.intent(
        f'Destroy VM {name}',
        why='Remove the libvirt domain and its related managed definition state.',
        role='modify',
    ):
        _destroy_and_undefine_vm(name)
    log.info('VM removed: {}', name)

def vm_status(cfg: AgentVMConfig) -> str:
    name = cfg.vm.name
    mgr = CommandManager.current()
    with mgr.intent(
        f'Inspect VM {name}',
        why='Read the live libvirt domain details and cached IP for this VM.',
        role='read',
    ):
        dom = mgr.run(
            ['virsh', 'dominfo', name],
            sudo=True,
            role='read',
            check=False,
            capture=True,
            summary=f'Inspect VM definition {name}',
        )
        if dom.code != 0:
            return f'VM not found: {name}\n'
        state = mgr.run(
            ['virsh', 'domstate', name],
            sudo=True,
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
