"""Opt-in foreground SSH integration for the independent ``aivm_secrets`` broker.

AIVM's whole role here is orchestration: it resolves who is asking, starts a
broker *as a separate process*, carries ciphertext into the guest, and ends
the session. The provider credential is resolved inside the broker child and
never exists in this process, in a command line, or in an AIVM log.

The child is ``aivm-secrets serve``, reached only through its documented
command line, one JSON line on its stdout, and the lifetime of its stdin. That
process contract -- not a Python import -- is the boundary, which is what
lets a verified Rust broker replace the Python one without touching AIVM.

Only this module knows ``ResolvedVMContext``. Nothing is added to the machine
store, existing deploy-key backends, or persistent SSH config.
"""

from __future__ import annotations

import json
import os
import select
import shlex
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from loguru import logger as log

from aivm_secrets.errors import SecretsError

from .commands import (
    CommandManager,
    CommandResult,
    Elided,
    SupervisedProcess,
)
from .errors import CommandControlError
from .runtime import require_ssh_identity, ssh_base_args
from .services import PreparedSession

WRITE_MODES = ('deny', 'approve', 'allow')
# A resolver such as a password-manager CLI may take a while to answer.
BROKER_START_TIMEOUT = 60.0
BROKER_STOP_TIMEOUT = 10.0
IDENTITY_POLL_SECONDS = 2.0
# A principal in one of these states may use the VM at all; see
# ``aivm.scoped_store.resolve_machine_context``. ``legacy`` is the synthetic
# identity of a single-user explicit ``--config`` store.
USABLE_STATES = frozenset({'active', 'legacy'})


@dataclass(frozen=True)
class BrokerSession:
    """What a started broker announced about itself. No secret is in here."""

    channel: str
    socket: Path
    capability_file: Path
    client: Path
    audit: Path
    service: str
    operations: tuple[str, ...]
    client_aliases: tuple[str, ...]
    writes: str
    lifetime_seconds: int


class BrokerProcess:
    """One ``aivm-secrets serve`` child bound to this process's lifetime.

    The child holds its stdin open as a liveness lease: releasing it -- or
    this process dying for any reason -- revokes the session and exits the
    broker.
    """

    def __init__(self, process: SupervisedProcess):
        self._process = process
        self._stopped = threading.Lock()
        self.audit_head = ''

    @classmethod
    def start(cls, manager: CommandManager, argv: list[str]) -> BrokerProcess:
        """Start the broker through the command manager, like any command."""
        process = manager.spawn(
            argv,
            role='modify',
            # The broker's runtime directory and audit file are AIVM's own
            # bookkeeping for a session the user asked for on this command
            # line; nothing the user authored is changed.
            ownership='tool',
            # Never the shared workspace: ``-P`` already keeps the current
            # directory off ``sys.path``; this keeps it out of the child too.
            cwd=str(Path.home()),
            summary='Start the secret-use broker for this session',
        )
        if process is None:
            raise SecretsError(
                'internal_error', detail='no broker is started in dry-run'
            )
        return cls(process)

    def announce(self) -> BrokerSession:
        """Wait for the broker's single readiness line, or its refusal."""
        stream = self._process.stdout
        deadline = time.monotonic() + BROKER_START_TIMEOUT
        data = b''
        while not data.endswith(b'\n'):
            remaining = deadline - time.monotonic()
            if (
                remaining <= 0
                or not select.select([stream], [], [], remaining)[0]
            ):
                raise SecretsError(
                    'internal_error', detail='broker did not start'
                )
            chunk = os.read(stream.fileno(), 65536)
            if not chunk:
                break
            data += chunk
        try:
            line = json.loads(data.decode('utf-8'))
            if 'error' in line:
                raise SecretsError(
                    line['error']['code'],
                    detail=line['error'].get('detail', ''),
                )
            return BrokerSession(
                channel=line['channel'],
                socket=Path(line['socket']),
                capability_file=Path(line['capability_file']),
                client=Path(line['client']),
                audit=Path(line['audit']),
                service=line['service'],
                operations=tuple(line['operations']),
                client_aliases=tuple(
                    alias for alias in line['client_aliases'] if alias.isalnum()
                ),
                writes=line['writes'],
                lifetime_seconds=int(line['lifetime_seconds']),
            )
        except (ValueError, KeyError, TypeError):
            raise SecretsError(
                'internal_error', detail='broker did not start'
            ) from None

    def stop(self) -> None:
        """Revoke by ending the lease. Idempotent; safe from any thread."""
        with self._stopped:
            process = self._process
            process.release()
            if process.wait(BROKER_STOP_TIMEOUT) is None:
                process.kill()
            stream = process.stdout
            if not stream.closed:
                # The broker's last word: the head of its sealed audit chain.
                try:
                    for line in stream.read().splitlines():
                        closing = json.loads(line)
                        if closing.get('closed') is True:
                            self.audit_head = str(closing.get('audit_head', ''))
                except (OSError, ValueError, AttributeError):
                    pass
                stream.close()

    @property
    def running(self) -> bool:
        return self._process.poll() is None


def broker_command(
    *,
    policy_path: Path,
    token_file: Path | None,
    writes: str,
    access_identity: str,
    vm: str,
    audit_dir: Path,
    untrusted: list[Path],
) -> list[str]:
    """The exact child command line. It never contains a credential."""
    argv = [
        sys.executable,
        '-P',
        '-m',
        'aivm_secrets',
        'serve',
        '--policy',
        str(policy_path),
        '--writes',
        writes,
        '--access-identity',
        access_identity,
        '--vm',
        vm,
        '--audit-dir',
        str(audit_dir),
        '--announce',
        'json',
        '--exit-on-stdin-eof',
    ]
    if token_file is not None:
        argv += ['--token-file', str(token_file)]
    for root in untrusted:
        argv += ['--untrusted-root', str(root)]
    return argv


def _watch_identity(
    broker: BrokerProcess,
    still_authorized: Callable[[], bool],
    done: threading.Event,
) -> None:
    """Revoke the session as soon as its access identity stops being usable.

    The grant was issued to an access identity. If that identity is disabled
    or removed while the shell is still open -- by this user or by an
    administrator in another terminal -- the broker must stop serving it,
    without waiting for the session to end or the grant to expire.
    """
    failures = 0
    while not done.wait(IDENTITY_POLL_SECONDS):
        try:
            authorized = still_authorized()
            failures = 0
        except Exception:
            # One unreadable sample is not a verdict; three in a row is.
            failures += 1
            authorized = failures < 3
        if not authorized:
            broker.stop()
            log.warning(
                'Secret session revoked: its access identity is no longer '
                'active. Service requests from this shell will now fail.'
            )
            return


def run_secrets_ssh(
    session: PreparedSession,
    ssh_cmd: list[str],
    *,
    policy_path: Path,
    token_file: Path | None = None,
    writes: str = 'deny',
    still_authorized: Callable[[], bool] | None = None,
) -> CommandResult:
    """Hold a broker exactly as long as this foreground SSH process is alive."""
    context = session.context
    principal = context.principal
    # Administrator access is not permission to borrow another principal's
    # provider identity: the kernel UID must be the identity's own.
    if (
        principal.host_uid != os.getuid()
        or principal.state not in USABLE_STATES
        or not principal.id
    ):
        raise SecretsError('wrong_owner')
    if writes not in WRITE_MODES:
        raise SecretsError('invalid_policy')
    if session.ip is None:
        raise SecretsError('guest_setup')
    manager = CommandManager.current()
    ident = require_ssh_identity(context.profile.ssh_identity_file)
    broker = BrokerProcess.start(
        manager,
        broker_command(
            policy_path=policy_path.expanduser(),
            token_file=token_file.expanduser() if token_file else None,
            writes=writes,
            access_identity=principal.id,
            vm=context.machine.vm.name,
            audit_dir=Path(context.profile.state_dir).expanduser()
            / 'secrets-audit',
            # Whatever the guest can write, the broker must not load, read
            # or execute. The broker enforces this on its own code as well.
            untrusted=[session.host_src, Path(session.share_source_dir)],
        ),
    )
    done = threading.Event()
    guest_dir = ''
    aliases: tuple[str, ...] = ()
    # No ambient multiplexing, proxies or forwarding. VM login credentials
    # and dedicated repository-agent options on the interactive command
    # are retained.
    isolated = [
        '-F',
        '/dev/null',
        '-o',
        'ControlMaster=no',
        '-o',
        'ControlPath=none',
        '-o',
        'ControlPersist=no',
    ]
    setup_ssh = [
        'ssh',
        *isolated,
        '-o',
        'ForwardAgent=no',
        *ssh_base_args(
            ident,
            strict_host_key_checking='yes',
            batch_mode=True,
            connect_timeout=10,
        ),
        context.ssh_target(session.ip),
    ]
    try:
        info = broker.announce()
        log.info(
            'Secret session {}: service={} operations={} writes={} TTL={}s',
            info.channel[:12],
            info.service,
            list(info.operations),
            info.writes,
            info.lifetime_seconds,
        )
        log.info('Secret session audit: {}', info.audit)
        if info.writes == 'approve':
            log.info(
                'Writes wait for approval. From another host terminal: '
                '`aivm-secrets pending`, then `aivm-secrets approve DIGEST`.'
            )
        directory = f'/tmp/aivm-secrets-{info.channel}'
        guest_socket = f'{directory}/broker.sock'
        client_path = f'{directory}/aivm-secrets'
        capability_path = f'{directory}/capability'
        quoted = shlex.quote(directory)
        # One round trip installs both files. The capability (ciphertext) and
        # the client travel on stdin: never on a command line, in the
        # environment, or in a command preview.
        install = (
            f'umask 077 && mkdir -- {quoted} && cd -- {quoted} && set -C && '
            'IFS= read -r capability && '
            'printf "%s\\n" "$capability" > capability && '
            'cat > aivm-secrets && chmod 700 aivm-secrets'
        )
        for alias in info.client_aliases:
            # e.g. the GitHub PR service also answers to a gh-shaped name.
            install += f' && ln -s aivm-secrets {shlex.quote(alias)}'
        guest_dir, aliases = directory, info.client_aliases
        payload = (
            info.capability_file.read_text(encoding='ascii').strip()
            + '\n'
            + info.client.read_text(encoding='utf-8')
        )
        result = manager.run(
            [*setup_ssh, Elided(install, 'install secret-session client')],
            input_text=payload,
            sudo=False,
            role='modify',
            # A session directory holding a client and ciphertext: tool-owned
            # bookkeeping the user never authored, removed when the session
            # ends.
            ownership='tool',
            check=False,
            capture=True,
            timeout=30,
            summary='Install the secret-session client and sealed capability',
        )
        if result.code:
            # A hostile guest can echo stdin: never log its output here.
            raise SecretsError('guest_setup')
        environment = (
            f'export AIVM_SECRETS_SOCKET={shlex.quote(guest_socket)} '
            f'AIVM_SECRETS_CAPABILITY_FILE={shlex.quote(capability_path)} '
            f'AIVM_SECRETS_CLIENT={shlex.quote(client_path)}; '
            f'export PATH={quoted}:"$PATH"; '
        )
        forwarded = [
            'ssh',
            *isolated,
            '-o',
            'ExitOnForwardFailure=yes',
            '-o',
            'StreamLocalBindUnlink=no',
            '-o',
            'StrictHostKeyChecking=yes',
            '-R',
            f'{guest_socket}:{info.socket}',
            *ssh_cmd[1:-1],
            Elided(
                environment + ssh_cmd[-1],
                'export AIVM_SECRETS_* for the session, then the login shell',
            ),
        ]
        log.info(
            'Guest client: {} (also on PATH as aivm-secrets). It cannot fall '
            'back to an unrestricted tool.',
            client_path,
        )
        if still_authorized is not None:
            threading.Thread(
                target=_watch_identity,
                args=(broker, still_authorized, done),
                daemon=True,
            ).start()
        return manager.run(
            forwarded, sudo=False, user_driven=True, check=False, capture=False
        )
    finally:
        # Stop authority BEFORE best-effort guest cleanup. Leftover
        # ciphertext is unusable once the broker and its key are gone, and
        # no guest response can delay revocation.
        done.set()
        broker.stop()
        if broker.audit_head:
            log.info('Secret session closed. Audit head: {}', broker.audit_head)
        if guest_dir:
            quoted = shlex.quote(guest_dir)
            names = ['broker.sock', 'capability', 'aivm-secrets', *aliases]
            cleanup = (
                'rm -f -- '
                + ' '.join(shlex.quote(f'{guest_dir}/{name}') for name in names)
                + f'; rmdir -- {quoted}'
            )
            try:
                manager.run(
                    [*setup_ssh, cleanup],
                    sudo=False,
                    role='modify',
                    ownership='tool',
                    check=False,
                    capture=True,
                    timeout=10,
                    summary='Remove the secret-session files from the guest',
                )
            except CommandControlError:
                # A refusal is the user's decision, not a failed cleanup.
                raise
            except Exception:
                log.warning(
                    'Guest secret-session cleanup failed; host authority '
                    'is already closed.'
                )
