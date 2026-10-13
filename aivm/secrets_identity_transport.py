"""Explicit AIVM↔Garrett P4a managed-VM integration.

This module is the ONLY part of the binding that imports both packages.
Identity is obtained from AIVM's machine store, owning access principal,
libvirt domain UUID and already-pinned SSH bootstrap channel. No guest field
is trusted to choose the subject. No default VM launch calls this module.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import stat
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any

from aivm_secrets.errors import SecretsError

from .commands import CommandManager
from .config_scopes import ResolvedVMContext
from .config_store import load_store
from .enrollment import BOOTSTRAP_GUEST_USER, require_bootstrap_identity
from .runtime import require_ssh_identity, ssh_base_args
from .scoped_store import resolve_store_scope
from .secrets_identity_vm import ManagedIdentity, resolve_managed_identity


def guest_writable_roots(store: Path) -> tuple[Path, ...]:
    """Conservatively forbid authority paths under *any* shared attachment."""
    registry = load_store(store)
    result: list[Path] = []
    for attachment in registry.attachments:
        if attachment.host_path:
            result.append(Path(attachment.host_path).expanduser().absolute())
        for alias in attachment.host_lexical_paths:
            if alias:
                result.append(Path(alias).expanduser().absolute())
    return tuple(result)


def _bootstrap_ssh(context: ResolvedVMContext, store: Path, ip: str) -> list[str]:
    scope = resolve_store_scope(str(store))
    if not scope.is_machine or scope.machine_layout is None:
        raise SecretsError('denied', detail='requires managed machine store')
    identity = require_bootstrap_identity(context.machine.vm.name,
                                          layout=scope.machine_layout)
    # Do not permit TOFU on the identity-provisioning channel. An unpinned or
    # rebuilt VM must go through the existing SSH enrollment reconciliation.
    if not identity.known_hosts.is_file() or not identity.known_hosts.stat().st_size:
        raise SecretsError('guest_setup', detail='bootstrap SSH host key not pinned')
    return [
        'ssh', '-F', '/dev/null', '-o', 'ForwardAgent=no',
        '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
        '-o', 'ClearAllForwardings=yes',
        *ssh_base_args(str(identity.private_key),
                       strict_host_key_checking='yes', batch_mode=True,
                       connect_timeout=10,
                       user_known_hosts_file=str(identity.known_hosts)),
        f'{BOOTSTRAP_GUEST_USER}@{ip}', 'identity-csr',
    ]


def _login_ssh(context: ResolvedVMContext, ip: str) -> list[str]:
    return ['ssh', '-F', '/dev/null', '-o', 'ForwardAgent=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            *ssh_base_args(require_ssh_identity(context.profile.ssh_identity_file),
                           strict_host_key_checking='yes', batch_mode=True,
                           connect_timeout=10), context.ssh_target(ip)]


def _identity_action(manager: CommandManager, *, action: str, root: Path | None,
                     untrusted: tuple[Path, ...] = (), extra: list[str] | None = None,
                     timeout: int = 30) -> dict[str, Any]:
    """Fixed JSON process protocol: AIVM never imports the secrets backend.

    Rust can implement these same verbs and output shapes without changing
    the VM adapter. No bearer credential or signing key crosses stdout.
    """
    from .secrets_transport import broker_environment, interpreter_flags

    cmd = [sys.executable, *interpreter_flags(), '-m', 'aivm_secrets',
           'identity', action]
    if root is not None:
        cmd += ['--root', str(Path(root).expanduser().absolute())]
        for path in untrusted:
            cmd += ['--untrusted-root', str(path)]
    cmd += list(extra or ())
    result = manager.run(
        cmd, sudo=False, role='modify', ownership='tool',
        env=broker_environment(), capture=True, check=False, timeout=timeout,
        summary=f'Run isolated identity service operation: {action}',
    )
    if result.code or len(result.stdout) > 196608:
        raise SecretsError('guest_setup', detail='identity service refused the operation')
    try:
        value = json.loads(result.stdout)
        if type(value) is not dict:
            raise ValueError('identity response must be an object')
        return value
    except (ValueError, TypeError):
        raise SecretsError('guest_setup', detail='invalid identity service reply') from None


def _isolated_enroll(manager: CommandManager, *, authority_root: Path,
                     subject: str, csr: bytes, replace: bool,
                     untrusted: tuple[Path, ...]) -> dict[str, Any]:
    """Certificate parsing and CA signing both occur in isolated processes."""
    with tempfile.NamedTemporaryFile(
        mode='wb', prefix='.csr-', suffix='.pem', dir=authority_root,
    ) as public_file:
        public_file.write(csr)
        public_file.flush()
        os.fsync(public_file.fileno())
        checked = _identity_action(manager, action='inspect-csr', root=None,
                                   extra=['--csr', public_file.name])
        fingerprint = checked.get('key_fingerprint')
        if (type(fingerprint) is not str or len(fingerprint) != 64 or
                any(char not in '0123456789abcdef' for char in fingerprint)):
            raise SecretsError('guest_setup', detail='invalid CSR fingerprint')
        options = ['--subject', subject, '--csr', public_file.name,
                   '--approve-key-fingerprint', fingerprint]
        if replace:
            options.append('--replace')
        value = _identity_action(manager, action='enroll', root=authority_root,
                                 untrusted=untrusted, extra=options)
    if (value.get('subject') != subject or
            type(value.get('certificate_sha256')) is not str or
            type(value.get('epoch')) is not int or
            type(value.get('not_after')) is not int):
        raise SecretsError('guest_setup', detail='invalid CA enrollment reply')
    return value


def _public_client(manager: CommandManager, *, root: Path, subject: str,
                   untrusted: tuple[Path, ...]) -> dict[str, Any]:
    result = _identity_action(manager, action='public-client', root=root,
                              untrusted=untrusted, extra=['--subject', subject])
    if (result.get('subject') != subject or
            type(result.get('certificate_sha256')) is not str or
            type(result.get('certificate_pem_b64')) is not str or
            type(result.get('ca_pem_b64')) is not str):
        raise SecretsError('guest_setup', detail='invalid public identity reply')
    for field in ('certificate_pem_b64', 'ca_pem_b64'):
        encoded = result[field]
        if len(encoded) > 16384:
            raise SecretsError('guest_setup', detail='oversized identity chain')
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError, binascii.Error):
            raise SecretsError('guest_setup', detail='invalid identity chain') from None
        if (not decoded.startswith(b'-----BEGIN CERTIFICATE-----\n') or
                b'-----END CERTIFICATE-----' not in decoded):
            raise SecretsError('guest_setup', detail='invalid identity certificate')
    return result


def _private_broker_file(path: Path, untrusted: tuple[Path, ...]) -> str:
    """Read the isolated broker's ciphertext-only output without importing it.

    The broker selects its own private per-session directory. Recheck the
    directory and final inode immediately before use; never follow symlinks.
    """
    path = Path(path).absolute()
    forms = [root for item in untrusted
             for root in (Path(os.path.abspath(item)),
                          Path(os.path.realpath(item)))]
    visited = (path, Path(os.path.realpath(path)))
    for part in visited:
        if any(part == root or root in part.parents for root in forms):
            raise SecretsError('shared_source')
    try:
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or
                parent.st_uid != os.getuid() or parent.st_mode & 0o077):
            raise SecretsError('unsafe_file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077
                    or info.st_size > 16384):
                raise SecretsError('unsafe_file')
            data = stream.read(16385)
            if len(data) > 16384:
                raise SecretsError('unsafe_file')
            return data.decode('ascii')
    except (OSError, UnicodeError):
        raise SecretsError('unsafe_file') from None


def enroll_managed_vm(*, context: ResolvedVMContext, store: Path, ip: str,
                      authority_root: Path, replace: bool = False,
                      uuid_reader=None) -> dict[str, Any]:
    """One explicitly requested and authenticated CSR enrollment transaction.

    The forced bootstrap private key is controlled by AIVM's machine store.
    `identity-csr` runs only fixed non-root commands in the guest and returns
    just a PKCS#10 CSR. Its host request includes a fresh nonce to reject stale
    replies. The subject is *not* taken from that reply or its CSR CN.
    """
    if uuid_reader is None:
        bound = resolve_managed_identity(context, store)
    else:
        bound = resolve_managed_identity(context, store, uuid_reader=uuid_reader)
    untrusted = guest_writable_roots(store)
    authority_root = Path(authority_root).expanduser().absolute()
    manager = CommandManager.current()
    _identity_action(manager, action='status', root=authority_root,
                     untrusted=untrusted)
    nonce = secrets.token_hex(16)
    request = {'operation': 'identity-csr', 'guest_user': bound.guest_user,
               'uid': bound.host_uid, 'nonce': nonce}
    scope = resolve_store_scope(str(store))
    assert scope.machine_layout is not None
    bootstrap = require_bootstrap_identity(bound.vm, layout=scope.machine_layout)
    result = manager.run(
        _bootstrap_ssh(context, store, ip),
        sudo=bootstrap.use_sudo, role='modify', capture=True, check=False,
        input_text=json.dumps(request, sort_keys=True) + '\n', timeout=60,
        summary='Retrieve guest-owned CSR over the forced bootstrap channel',
    )
    if result.code:
        # Existing guests may not yet have the updated forced helper. Do not
        # fall back to interactive SSH or unauthenticated CSR retrieval.
        raise SecretsError('guest_setup', detail='forced CSR bootstrap failed; '
                           'guest helper upgrade may be required')
    try:
        data = json.loads(result.stdout)
        if (type(data) is not dict or set(data) != {
                'status', 'operation', 'guest_user', 'uid', 'nonce', 'csr'} or
                data['status'] != 'ok' or data['operation'] != 'identity-csr' or
                data['guest_user'] != bound.guest_user or
                type(data['uid']) is not int or data['uid'] != bound.host_uid or
                data['nonce'] != nonce or type(data['csr']) is not str):
            raise ValueError('wrong bootstrap reply')
        csr = data['csr'].encode('ascii')
        if len(csr) > 8192:
            raise ValueError('oversized CSR')
    except (ValueError, KeyError, TypeError, UnicodeError, SecretsError):
        raise SecretsError('guest_setup', detail='invalid CSR bootstrap reply') from None
    # Check that domain incarnation and access ownership did not change while
    # the bootstrap roundtrip ran. This is a best-effort TOCTOU reduction, not
    # a proof against host administrators or guest snapshot attacks.
    check = (resolve_managed_identity(context, store) if uuid_reader is None else
             resolve_managed_identity(context, store, uuid_reader=uuid_reader))
    if check != bound:
        raise SecretsError('revoked', detail='VM identity changed during enrollment')
    record = _isolated_enroll(manager, authority_root=authority_root,
                              subject=bound.subject, csr=csr,
                              replace=replace, untrusted=untrusted)
    # Obtain only public certificate material from the separately isolated
    # authority. Never load CA keys or the certificate parser into AIVM.
    public = _public_client(manager, root=authority_root,
                            subject=bound.subject, untrusted=untrusted)
    if public['certificate_sha256'] != record['certificate_sha256']:
        raise SecretsError('revoked', detail='certificate changed during enrollment')
    script = (
        'umask 077 && set -e && '
        'install -d -m 700 "$HOME/.config/aivm/identity" && '
        'cd "$HOME/.config/aivm/identity" && '
        'IFS= read -r certificate && IFS= read -r ca && '
        'printf "%s" "$certificate" | base64 -d > client.pem.new && '
        'printf "%s" "$ca" | base64 -d > ca.pem.new && '
        'chmod 600 client.pem.new ca.pem.new && '
        'mv -f client.pem.new client.pem && mv -f ca.pem.new ca.pem'
    )
    payload = public['certificate_pem_b64'] + '\n' + public['ca_pem_b64'] + '\n'
    try:
        installed = manager.run(
            [*_login_ssh(context, ip), script], input_text=payload,
            sudo=False, role='modify', ownership='tool', capture=True,
            check=False, timeout=30,
            summary='Install public identity certificate and CA in guest',
        )
        if installed.code:
            raise SecretsError('guest_setup', detail='guest certificate install failed')
    except Exception:
        # A provisioned-but-unusable identity must not remain active. If
        # revocation also fails the original error remains visible in logs;
        # the operator must manually revoke before another attempt.
        _identity_action(manager, action='revoke', root=authority_root,
                         untrusted=untrusted, extra=['--subject', bound.subject])
        raise
    return {'vm': bound.vm, 'domain_uuid': bound.uuid,
            'subject': bound.subject, 'principal_id': bound.principal_id,
            'certificate_sha256': record['certificate_sha256'],
            'epoch': record['epoch'], 'not_after': record['not_after']}


def _bridge_process(manager: CommandManager, *, authority_root: Path,
                    broker_socket: Path, listen: Path,
                    untrusted: tuple[Path, ...], idle_seconds: int):
    """Run the credential-related bridge under a fresh isolated interpreter."""
    import select
    import sys
    import time
    from .secrets_transport import BrokerProcess, broker_environment, interpreter_flags

    cmd = [sys.executable, *interpreter_flags(), '-m', 'aivm_secrets',
           'identity', 'bridge', '--root', str(authority_root),
           '--broker-socket', str(broker_socket), '--listen', str(listen),
           '--idle-seconds', str(min(3600, max(60, idle_seconds))),
           '--max-connections', '256', '--exit-on-stdin-eof']
    for root in untrusted:
        cmd += ['--untrusted-root', str(root)]
    child = manager.spawn(
        cmd, role='modify', ownership='tool', env=broker_environment(),
        cwd=str(Path.home()),
        summary='Start certificate-bound identity bridge for this session',
    )
    if child is None:
        raise SecretsError('internal_error')
    wrapper = BrokerProcess(child)
    try:
        stream = child.stdout
        deadline = time.monotonic() + 20
        data = b''
        while not data.endswith(b'\n') and len(data) < 16384:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
                raise SecretsError('guest_setup', detail='identity bridge did not start')
            chunk = os.read(stream.fileno(), 16384 - len(data))
            if not chunk:
                raise SecretsError('guest_setup', detail='identity bridge exited')
            data += chunk
        ready = json.loads(data.decode('utf-8'))
        if type(ready) is not dict or ready.get('listening') != str(listen):
            raise SecretsError('guest_setup', detail='invalid identity bridge readiness')
        if child.poll() is not None:
            raise SecretsError('guest_setup', detail='identity bridge exited')
        return wrapper
    except Exception:
        wrapper.stop()
        raise


def _isolated_issue(manager: CommandManager, *, authority_root: Path,
                    bound: ManagedIdentity, original: Path, output: Path,
                    untrusted: tuple[Path, ...], lifetime: int) -> None:
    import sys
    from .secrets_transport import interpreter_flags, broker_environment

    cmd = [sys.executable, *interpreter_flags(), '-m', 'aivm_secrets',
           'identity', 'issue', '--root', str(authority_root),
           '--subject', bound.subject, '--capability-file', str(original),
           '--output', str(output), '--lifetime', str(lifetime)]
    for path in untrusted:
        cmd += ['--untrusted-root', str(path)]
    done = manager.run(
        cmd, sudo=False, role='modify', ownership='tool', check=False,
        capture=True, timeout=20, env=broker_environment(),
        summary='Issue a certificate-bound encrypted guest capability',
    )
    if done.code:
        raise SecretsError('guest_setup', detail='bound capability issuance failed')


def run_bound_secrets_ssh(
    session, ssh_cmd: list[str], *, policy_path: Path,
    identity_root: Path, token_file: Path | None = None,
    oauth_vault: Path | None = None,
    oauth_provider_config: Path | None = None,
    writes: str = 'deny', still_authorized=None, uuid_reader=None,
):
    """Only bridge mTLS; NEVER forward the original unbound broker socket.

    This is an explicit alternative to `run_secrets_ssh`, not an extension of
    its guest authority. All effects still pass the original reference monitor.
    """
    import threading
    from .commands import Elided
    from .secrets_transport import (BrokerProcess, WRITE_MODES,
                                     _watch_identity, broker_command)

    if writes not in WRITE_MODES or session.ip is None:
        raise SecretsError('invalid_policy')
    if oauth_vault is not None:
        if token_file is not None or oauth_provider_config is None:
            raise SecretsError('invalid_policy')
    elif oauth_provider_config is not None:
        raise SecretsError('invalid_policy')
    context = session.context
    store = Path(session.reg_path)
    lookup = {} if uuid_reader is None else {'uuid_reader': uuid_reader}
    bound = resolve_managed_identity(context, store, **lookup)
    untrusted = (*guest_writable_roots(store), session.host_src,
                 Path(session.share_source_dir))
    manager = CommandManager.current()
    authority_root = Path(identity_root).expanduser().absolute()
    _public_client(manager, root=authority_root, subject=bound.subject,
                   untrusted=untrusted)
    broker = None
    bridge = None
    guest_dir = ''
    aliases: tuple[str, ...] = ()
    jwt_file = None
    done = threading.Event()
    # Keep SSH isolated from ambient config and multiplexing. A caller
    # cannot smuggle an agent forward or another -R through ssh_cmd.
    ident = require_ssh_identity(context.profile.ssh_identity_file)
    isolated = ['-F', '/dev/null', '-o', 'ControlMaster=no',
                '-o', 'ControlPath=none', '-o', 'ControlPersist=no',
                '-o', 'ForwardAgent=no']
    setup_ssh = ['ssh', *isolated,
                 *ssh_base_args(ident, strict_host_key_checking='yes',
                                batch_mode=True, connect_timeout=10),
                 context.ssh_target(session.ip)]
    try:
        broker = BrokerProcess.start(manager, broker_command(
            policy_path=Path(policy_path).expanduser(),
            token_file=Path(token_file).expanduser() if token_file else None,
            writes=writes, access_identity=bound.principal_id, vm=bound.vm,
            audit_dir=Path(context.profile.state_dir).expanduser() / 'secrets-audit',
            untrusted=list(untrusted),
            oauth_vault=Path(oauth_vault).expanduser().absolute()
                if oauth_vault is not None else None,
            oauth_provider_config=Path(oauth_provider_config).expanduser().absolute()
                if oauth_provider_config is not None else None,
            oauth_subject=bound.subject if oauth_vault is not None else '',
        ))
        info = broker.announce()
        if info.writes != writes:
            raise SecretsError('internal_error')
        # A change between enrollment lookup and capability issuance revokes
        # the launch. The watcher below also checks throughout the session.
        if resolve_managed_identity(context, store, **lookup) != bound:
            raise SecretsError('revoked')
        jwt_file = info.socket.parent / 'bound.jwt'
        _isolated_issue(manager, authority_root=authority_root, bound=bound,
                        original=info.capability_file, output=jwt_file,
                        untrusted=untrusted, lifetime=min(900, info.lifetime_seconds))
        bound_socket = info.socket.parent / 'identity.sock'
        bridge = _bridge_process(
            manager, authority_root=authority_root, broker_socket=info.socket,
            listen=bound_socket, untrusted=untrusted,
            idle_seconds=info.lifetime_seconds + 60,
        )
        guest_dir = f'/tmp/aivm-bound-{info.channel}'
        guest_socket = guest_dir + '/identity.sock'
        capability_path = guest_dir + '/capability'
        client_path = guest_dir + '/aivm-secrets'
        quoted = shlex.quote(guest_dir)
        install = (
            f'umask 077 && mkdir -- {quoted} && cd -- {quoted} && set -C && '
            'IFS= read -r jwt && printf "%s\\n" "$jwt" > capability && '
            'cat > aivm-secrets && chmod 700 aivm-secrets'
        )
        for alias in info.client_aliases:
            install += f' && ln -s aivm-secrets {shlex.quote(alias)}'
        aliases = info.client_aliases
        token = _private_broker_file(jwt_file, untrusted)
        payload = token + '\n' + info.client.read_text(encoding='utf-8')
        installed = manager.run(
            [*setup_ssh, Elided(install, 'install bound identity client')],
            input_text=payload, sudo=False, role='modify', ownership='tool',
            check=False, capture=True, timeout=30,
            summary='Install encrypted, certificate-bound guest capability',
        )
        if installed.code:
            # A hostile guest can echo the input token. Never print output.
            raise SecretsError('guest_setup')
        environment = (
            f'export AIVM_SECRETS_SOCKET={shlex.quote(guest_socket)} '
            f'AIVM_SECRETS_CAPABILITY_FILE={shlex.quote(capability_path)} '
            f'AIVM_SECRETS_CLIENT={shlex.quote(client_path)} '
            'AIVM_SECRETS_IDENTITY_MODE=mtls-v1 '
            'AIVM_SECRETS_IDENTITY_CA="$HOME/.config/aivm/identity/ca.pem" '
            'AIVM_SECRETS_IDENTITY_CERT="$HOME/.config/aivm/identity/client.pem" '
            'AIVM_SECRETS_IDENTITY_KEY="$HOME/.config/aivm/identity/client.key"; '
            f'export PATH={quoted}:"$PATH"; '
        )
        forwarded = [
            'ssh', *isolated, '-o', 'ExitOnForwardFailure=yes',
            '-o', 'StreamLocalBindUnlink=no',
            '-o', 'StrictHostKeyChecking=yes',
            '-R', f'{guest_socket}:{bound_socket}',
            '-t', *ssh_base_args(ident, strict_host_key_checking='yes'),
            context.ssh_target(session.ip),
            Elided(environment + ssh_cmd[-1], 'start identity-only guest shell'),
        ]
        def authorized():
            if still_authorized is not None and not still_authorized():
                return False
            return resolve_managed_identity(context, store, **lookup) == bound
        threading.Thread(target=_watch_identity,
                         args=(broker, authorized, done), daemon=True).start()
        return manager.run(forwarded, sudo=False, user_driven=True,
                           check=False, capture=False)
    finally:
        done.set()
        # Both credential-owning children must be stopped even if one
        # raises during teardown. Never depend on guest cleanup for revocation.
        try:
            if bridge is not None:
                bridge.stop()
        finally:
            try:
                if broker is not None:
                    broker.stop()
            finally:
                if jwt_file is not None:
                    try:
                        jwt_file.unlink()
                    except FileNotFoundError:
                        pass
                if guest_dir:
                    quoted = shlex.quote(guest_dir)
                    names = ['identity.sock', 'capability', 'aivm-secrets', *aliases]
                    cleanup = ('rm -f -- ' + ' '.join(
                        shlex.quote(f'{guest_dir}/{name}') for name in names) +
                               f'; rmdir -- {quoted}')
                    try:
                        manager.run([*setup_ssh, cleanup], sudo=False, role='modify',
                                    ownership='tool', check=False, capture=True,
                                    timeout=10, summary='Remove bound secret-session guest files')
                    except Exception:
                        # Host authority is already closed; guest cleanup is best effort.
                        pass
