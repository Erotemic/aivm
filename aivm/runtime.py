"""Runtime command-shaping helpers for virsh/ssh invocations.

Keeping these helpers centralized reduces drift in connection defaults and
libvirt URI usage across CLI and VM lifecycle modules.

Runtime modes
-------------

aivm supports two libvirt runtimes, selected per-VM via ``runtime.mode``:

* ``'system'``  -- the privileged system daemon (``qemu:///system``):
  managed NAT network, ``/var/lib/libvirt/aivm`` storage, optional
  nftables firewall, and the ``behavior.privilege_mode`` escalation
  policy.
* ``'session'`` -- the per-user daemon (``qemu:///session``): user-owned
  storage, user-mode passt networking with a forwarded localhost SSH
  port, and a structural never-sudo guarantee (session activation forces
  ``privilege_mode='sudoless'`` on the active CommandManager).

The active mode is context-local state set by :func:`activate_runtime`
when a VM config is resolved. Every libvirt client command is built via
:func:`virsh_cmd` (and ``virt-install`` uses :func:`current_libvirt_uri`),
so there is exactly one place URI selection happens; session mode never
falls back to ``qemu:///system``.
"""

from __future__ import annotations

from contextvars import ContextVar

from loguru import logger as log

from .errors import MissingSSHIdentityError, SessionRuntimeError

RUNTIME_MODES = ('system', 'session')

SYSTEM_LIBVIRT_URI = 'qemu:///system'
SESSION_LIBVIRT_URI = 'qemu:///session'

#: Backward-compatible alias; prefer :func:`current_libvirt_uri`.
LIBVIRT_URI = SYSTEM_LIBVIRT_URI

_CURRENT_RUNTIME_MODE: ContextVar[str] = ContextVar(
    'aivm_current_runtime_mode', default='system'
)


def normalize_runtime_mode(value: object) -> str:
    """Normalize a configured runtime mode, defaulting to ``'system'``."""
    mode = str(value or 'system').strip().lower()
    if mode not in RUNTIME_MODES:
        log.warning(
            "Unknown runtime.mode {!r}; falling back to 'system'. "
            'Valid values: {}',
            value,
            ', '.join(RUNTIME_MODES),
        )
        return 'system'
    return mode


def current_runtime_mode() -> str:
    """Return the context-local runtime mode (``'system'`` when unset)."""
    return _CURRENT_RUNTIME_MODE.get()


def runtime_is_session() -> bool:
    """Return True when the active runtime is the per-user session daemon."""
    return current_runtime_mode() == 'session'


def libvirt_uri_for_mode(mode: str) -> str:
    """Return the libvirt connection URI for a runtime mode."""
    if normalize_runtime_mode(mode) == 'session':
        return SESSION_LIBVIRT_URI
    return SYSTEM_LIBVIRT_URI


def current_libvirt_uri() -> str:
    """Return the libvirt URI every client command must target right now."""
    return libvirt_uri_for_mode(current_runtime_mode())


def activate_runtime(mode: object) -> str:
    """Install ``mode`` as the context-local runtime and enforce its policy.

    Session mode structurally forbids sudo: it flips the active
    CommandManager to ``privilege_mode='sudoless'`` so the never-sudo
    guarantee is enforced at the one chokepoint every subprocess goes
    through, not by call-site discipline.
    """
    normalized = normalize_runtime_mode(mode)
    _CURRENT_RUNTIME_MODE.set(normalized)
    if normalized == 'session':
        from .commands import CommandManager

        mgr = CommandManager.current()
        if mgr.privilege_mode != 'sudoless':
            log.debug(
                'Session runtime forces privilege_mode=sudoless '
                '(was {!r})',
                mgr.privilege_mode,
            )
            mgr.privilege_mode = 'sudoless'
    return normalized


def require_system_runtime(*, feature: str, hint: str) -> None:
    """Fail fast when a system-only feature is used on a session VM.

    Use this for operations the session runtime fundamentally cannot
    provide (managed libvirt networks, nftables firewall, host bind
    mounts) so users get feature-level guidance instead of a failed
    libvirt command deep inside a flow.
    """
    if not runtime_is_session():
        return
    raise SessionRuntimeError(
        f'{feature} is not available in runtime.mode=session '
        '(per-user qemu:///session).\n'
        f'{hint}'
    )


def virsh_cmd(*args: str) -> list[str]:
    """Build a virsh argv pinned to the active runtime's libvirt URI."""
    return ['virsh', '-c', current_libvirt_uri(), *args]


def virsh_system_cmd(*args: str) -> list[str]:
    """Build a virsh argv pinned to the system daemon.

    Deprecated compatibility shim: package code uses :func:`virsh_cmd` so
    the URI follows the active runtime. Only reach for this when a command
    must target ``qemu:///system`` regardless of runtime.
    """
    return ['virsh', '-c', SYSTEM_LIBVIRT_URI, *args]


def virsh_domain_missing(stderr: str) -> bool:
    """Return True when virsh failed because the domain does not exist.

    Distinguishes "domain not found" from permission/connection failures so
    callers know that retrying with sudo cannot change the answer.
    """
    detail = (stderr or '').lower()
    return 'failed to get domain' in detail or 'domain not found' in detail


def require_ssh_identity(identity: str) -> str:
    ident = (identity or '').strip()
    if not ident:
        raise MissingSSHIdentityError(
            'paths.ssh_identity_file is empty; run aivm config init or set it in config.'
        )
    return ident


def ssh_base_args(
    ident: str,
    *,
    strict_host_key_checking: str = 'accept-new',
    connect_timeout: int | None = None,
    batch_mode: bool = False,
    user_known_hosts_file: str | None = None,
    identities_only: bool = True,
    port: int | None = None,
) -> list[str]:
    args: list[str] = []
    if port is not None and int(port) != 22:
        # Session VMs are reached through a forwarded localhost port;
        # system VMs keep default-port argv (no -p) for stability.
        args.extend(['-p', str(int(port))])
    if batch_mode:
        args.extend(['-o', 'BatchMode=yes'])
    if connect_timeout is not None:
        args.extend(['-o', f'ConnectTimeout={connect_timeout}'])
    args.extend(['-o', f'StrictHostKeyChecking={strict_host_key_checking}'])
    if user_known_hosts_file:
        args.extend(['-o', f'UserKnownHostsFile={user_known_hosts_file}'])
    if identities_only:
        # Match the generated ~/.ssh/config entry. Without this, ssh may try
        # keys from the agent or earlier Host blocks before the configured
        # IdentityFile, and sshd can disconnect with "Too many authentication
        # failures" before the aivm key is ever offered.
        args.extend(['-o', 'IdentitiesOnly=yes'])
    args.extend(['-i', ident])
    return args
