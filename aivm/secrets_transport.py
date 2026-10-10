"""Opt-in foreground SSH integration for the independent aivm_secrets package.

Only this adapter knows ResolvedVMContext. Nothing is added to the machine
store, existing deploy-key backends, or persistent SSH config.
"""

from __future__ import annotations

import os
import secrets
import shlex
import tempfile
from pathlib import Path

from loguru import logger as log

from .commands import CommandManager, CommandResult
from .runtime import require_ssh_identity, ssh_base_args
from .services import PreparedSession


def _outside_workspace(path: Path, session: PreparedSession) -> None:
    from aivm_secrets.errors import SecretsError

    candidate = path.expanduser().resolve()
    for source in (session.host_src, Path(session.share_source_dir)):
        if candidate.is_relative_to(source.resolve()):
            raise SecretsError('shared_source')


def run_secrets_ssh(session: PreparedSession, ssh_cmd: list[str], *,
                    policy_path: Path, token_file: Path | None = None,
                    allow_writes: bool = False) -> CommandResult:
    """Hold the broker only while this foreground SSH process is alive."""
    from aivm_secrets import guest
    from aivm_secrets.broker import Broker
    from aivm_secrets.cli import load_policy
    from aivm_secrets.core import Binding
    from aivm_secrets.errors import SecretsError
    from aivm_secrets.files import private_directory
    from aivm_secrets.server import LocalServer
    from aivm_secrets.sources import credential_from_file, credential_from_gh

    context = session.context
    if (context.principal.host_uid != os.getuid()
            or context.principal.state != 'active' or not context.principal.id):
        raise SecretsError('wrong_owner')
    _outside_workspace(policy_path, session)
    if token_file is not None:
        _outside_workspace(token_file, session)
    policy = load_policy(policy_path.expanduser())
    manager = CommandManager.current()
    if session.ip is None:
        raise SecretsError('guest_setup')
    ident = require_ssh_identity(context.profile.ssh_identity_file)
    log.info('Secret session: repo={} PRs={} operations={} writes={} TTL={}s',
             policy.repository, list(policy.pr_numbers), list(policy.operations),
             allow_writes, policy.lifetime_seconds)
    if token_file is None:
        log.info('Read host GitHub credential with: gh auth token --hostname github.com (output withheld)')
        credential = credential_from_gh()
    else:
        log.info('Read host-only GitHub credential file: {} (contents withheld)', token_file)
        credential = credential_from_file(token_file.expanduser())
    channel = secrets.token_hex(16)
    binding = Binding(os.getuid(), context.principal.id,
                      context.machine.vm.name, channel)
    audit_dir = private_directory(Path(context.profile.state_dir) / 'secrets-audit')
    audit_path = audit_dir / f'{channel}.jsonl'
    broker = Broker(policy, binding, credential, audit_path, allow_writes=allow_writes)
    del credential
    log.info('Secret session audit: {}', audit_path)
    # No ambient multiplexing, proxies, or forwarding. VM login credentials and
    # dedicated repository-agent options on the interactive command are retained.
    isolated = ['-F', '/dev/null', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                '-o', 'ControlPersist=no']
    setup_ssh = ['ssh', *isolated, '-o', 'ForwardAgent=no',
                 *ssh_base_args(ident, strict_host_key_checking='yes', batch_mode=True,
                                connect_timeout=10), context.ssh_target(session.ip)]
    guest_dir = f'/tmp/aivm-secrets-{channel}'
    guest_socket = guest_dir + '/broker.sock'
    client_path = guest_dir + '/gh'
    capability_path = guest_dir + '/capability'
    created = False

    def setup(command: str, *, payload: str | None = None) -> None:
        result = manager.run([*setup_ssh, command], input_text=payload,
                             sudo=False, role='modify', user_driven=True,
                             check=False, capture=True, timeout=20)
        if result.code:
            # A hostile guest can echo stdin: never log its stdout/stderr here.
            raise SecretsError('guest_setup')

    try:
        with tempfile.TemporaryDirectory(prefix='aivm-secrets-', dir='/tmp') as runtime:
            socket_path = Path(runtime) / 'broker.sock'
            with LocalServer(broker, socket_path):
                setup(f'umask 077; mkdir -- {shlex.quote(guest_dir)}')
                created = True
                setup(f'umask 077; set -C; cat > {shlex.quote(client_path)} && '
                      f'chmod 700 -- {shlex.quote(client_path)}',
                      payload=Path(guest.__file__).read_text())
                setup(f'umask 077; set -C; cat > {shlex.quote(capability_path)}',
                      payload=broker.capability)
                # Ciphertext is carried on stdin above, never on the command
                # line, in environment variables, or in command preview logs.
                environment = (
                    f'export AIVM_SECRETS_SOCKET={shlex.quote(guest_socket)} '
                    f'AIVM_SECRETS_CAPABILITY_FILE={shlex.quote(capability_path)} '
                    f'AIVM_SECRETS_CLIENT={shlex.quote(client_path)}; '
                    f'export PATH={shlex.quote(guest_dir)}:"$PATH"; '
                )
                forwarded = ['ssh', *isolated,
                             '-o', 'ExitOnForwardFailure=yes',
                             '-o', 'StreamLocalBindUnlink=no',
                             '-o', 'StrictHostKeyChecking=yes',
                             '-R', f'{guest_socket}:{socket_path}',
                             *ssh_cmd[1:-1], environment + ssh_cmd[-1]]
                log.info('Restricted gh client: {}; unsupported commands do not fall back to stock gh.', client_path)
                log.info('Login shell profiles may reset PATH; $AIVM_SECRETS_CLIENT is the explicit client path.')
                return manager.run(forwarded, sudo=False, user_driven=True,
                                   check=False, capture=False)
    finally:
        # Stop authority BEFORE best-effort guest cleanup. Leftover ciphertext
        # is unusable once this broker/key is gone. No guest response can delay
        # revocation or authorize a different identity.
        try:
            broker.close()
        finally:
            if created:
                try:
                    manager.run([*setup_ssh, f'rm -f -- {shlex.quote(guest_socket)} '
                                 f'{shlex.quote(capability_path)} {shlex.quote(client_path)}; '
                                 f'rmdir -- {shlex.quote(guest_dir)}'],
                                sudo=False, user_driven=True, check=False,
                                capture=True, timeout=10)
                except Exception:
                    log.warning('Guest secret-session cleanup failed; host authority is closed.')
