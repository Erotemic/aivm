"""Runtime command-shaping helpers for virsh/ssh invocations.

Keeping these helpers centralized reduces drift in connection defaults and
libvirt URI usage across CLI and VM lifecycle modules.

aivm targets the privileged system libvirt daemon (``qemu:///system``).
A per-user ``qemu:///session`` runtime was prototyped and removed; see
``docs/planning/deferred/session-runtime.md``.
"""

from __future__ import annotations

from .errors import MissingSSHIdentityError

SYSTEM_LIBVIRT_URI = 'qemu:///system'

#: Backward-compatible alias for :data:`SYSTEM_LIBVIRT_URI`.
LIBVIRT_URI = SYSTEM_LIBVIRT_URI


def virsh_cmd(*args: str) -> list[str]:
    """Build a virsh argv pinned to the system libvirt daemon."""
    return ['virsh', '-c', SYSTEM_LIBVIRT_URI, *args]


def pin_locale(cmd: list[str]) -> list[str]:
    """Prefix ``env LC_ALL=C`` so the command's output can be string-matched.

    virsh (and ``stat``, and most of coreutils) localizes its diagnostics,
    state names, and field labels, so matchers such as
    :func:`virsh_domain_missing` only see the English text they expect when
    the invocation pins the C locale.  The pin rides inside the argv rather
    than in an ``env=`` override so it also survives sudo's environment
    reset when the command escalates.  Apply it to every invocation whose
    stdout/stderr is string-matched; output that is merely displayed or
    exit-code-checked stays in the user's locale.

    Being the one spelling of this rule is the point: a locale-sensitive
    probe that skips it is findable by grep, and one that hand-rolls the
    ``env LC_ALL=C`` prefix is not.
    """
    return ['env', 'LC_ALL=C', *cmd]


def current_libvirt_uri() -> str:
    """Return the libvirt URI every client command must target."""
    return SYSTEM_LIBVIRT_URI


def virsh_domain_missing(stderr: str) -> bool:
    """Return True when virsh failed because the domain does not exist.

    Distinguishes "domain not found" from permission/connection failures so
    callers know that retrying with sudo cannot change the answer.

    Only the C-locale diagnostics match: run the virsh command under
    :func:`pin_locale` (or an ``LC_ALL=C`` env override) or translated
    stderr will defeat the check.
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


def ssh_forward_agent_socket_args(socket_path: str) -> list[str]:
    """Forward exactly one dedicated agent without letting SSH mutate it.

    OpenSSH has a non-obvious coupling here: even when ``ForwardAgent`` names
    an explicit socket path, the client still runs its ordinary authentication
    agent presence check before requesting forwarding.  If ``IdentityAgent`` /
    ``SSH_AUTH_SOCK`` is absent, forwarding is silently disabled and the guest
    receives no ``SSH_AUTH_SOCK``.

    Point ``IdentityAgent`` at the same dedicated socket so that presence check
    succeeds, but force ``AddKeysToAgent=no`` so the VM login key can never be
    inserted into the repository agent by ambient host policy.  Callers also
    use ``IdentitiesOnly=yes`` with an explicit VM ``IdentityFile``; therefore
    the dedicated agent is available for transport but its repository keys are
    not candidates for VM login authentication.

    Keep these three options together.  Splitting them across call sites makes
    the forwarding/isolation invariant depend on ambient OpenSSH configuration.
    """
    selected = str(socket_path or '').strip()
    if not selected:
        return []
    return [
        '-o',
        f'IdentityAgent={selected}',
        '-o',
        'AddKeysToAgent=no',
        '-o',
        f'ForwardAgent={selected}',
    ]


def ssh_base_args(
    ident: str,
    *,
    strict_host_key_checking: str = 'accept-new',
    connect_timeout: int | None = None,
    batch_mode: bool = False,
    user_known_hosts_file: str | None = None,
    identities_only: bool = True,
) -> list[str]:
    args: list[str] = []
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
