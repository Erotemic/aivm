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
from typing import Any, Callable

from loguru import logger as log

from aivm_secrets.errors import SecretsError

from .commands import CommandError, CommandManager, Elided
from .config_scopes import ResolvedVMContext
from .config_store import load_store
from .enrollment import BOOTSTRAP_GUEST_USER, require_bootstrap_identity
from .errors import CommandControlError
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


def _bootstrap_ssh(context: ResolvedVMContext, store: Path, ip: str,
                   *, operation: str = 'identity-csr') -> list[str]:
    if operation not in ('identity-csr', 'identity-key-rotate-csr'):
        raise SecretsError('invalid_request')
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
        f'{BOOTSTRAP_GUEST_USER}@{ip}', operation,
    ]


def _principal_known_hosts(context: ResolvedVMContext, store: Path) -> str | None:
    """The VM's pinned host-key file, when this caller is able to read it.

    The principal account reaches the same guest sshd as the forced bootstrap
    channel, so it is held to the same pinned key rather than to whatever
    ambient ``~/.ssh/known_hosts`` holds for a possibly reused address. A
    missing or empty pin refuses, exactly as the bootstrap channel does.

    On a *shared* machine store the bootstrap directory is ``root:<group>``
    ``0750`` (``BOOTSTRAP_DIRECTORY_MODE``) and ``known_hosts`` is written by
    ``ssh`` running under sudo, so its mode is whatever umask root had then:
    a trusted-group member can usually read it, but not always. Escalating
    an interactive principal login just to read a public file is not worth
    it, so then this returns ``None`` and the caller keeps
    ``StrictHostKeyChecking=yes`` against the principal's own known_hosts,
    which ``aivm vm access reconcile`` populated when it verified this
    principal's login. That is never trust-on-first-use: an unknown or
    changed host key still refuses the connection. A *personal* store is the
    caller's own, so an unreadable pin there is an error, not a fallback.
    """
    scope = resolve_store_scope(str(store))
    if not scope.is_machine or scope.machine_layout is None:
        raise SecretsError('denied', detail='requires managed machine store')
    identity = require_bootstrap_identity(context.machine.vm.name,
                                          layout=scope.machine_layout)
    try:
        info = identity.known_hosts.stat()
    except OSError:
        info = None
    if info is None or not stat.S_ISREG(info.st_mode) or not info.st_size:
        raise SecretsError('guest_setup', detail='bootstrap SSH host key not pinned')
    if os.access(identity.known_hosts, os.R_OK):
        return str(identity.known_hosts)
    if not identity.use_sudo:
        raise SecretsError('unsafe_file',
                           detail='pinned SSH host key file is not readable')
    log.info('The pinned host key for VM {} is root-only on this shared store; '
             'principal SSH checks the guest host key strictly against your '
             'own known_hosts instead.', context.machine.vm.name)
    return None


def _principal_ssh(context: ResolvedVMContext, store: Path, ip: str) -> list[str]:
    """Isolated, strictly host-key-checked SSH as the owning principal.

    Used for every principal-account step of identity enrollment: the CSR
    refresh before issuance and the public-material install after it.
    """
    known_hosts = _principal_known_hosts(context, store)
    return ['ssh', '-F', '/dev/null', '-o', 'ForwardAgent=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ClearAllForwardings=yes',
            *ssh_base_args(require_ssh_identity(context.profile.ssh_identity_file),
                           strict_host_key_checking='yes', batch_mode=True,
                           connect_timeout=10, user_known_hosts_file=known_hosts),
            context.ssh_target(ip)]


# ssh exits 255 when the channel itself fails: no route, or a host key that
# does not match the pin. Re-enrollment re-pins a *new address*; a changed
# key at the same address stays refused until the pin is deliberately reset.
_SSH_CHANNEL_HINT = ('if the VM address changed, run `aivm vm access '
                     'reconcile`; a changed host key stays refused')


def _principal_ssh_failure(code: int, what: str) -> SecretsError:
    """Say what failed; never echo guest output, which the guest controls."""
    if code == 255:
        return SecretsError('guest_setup', detail=(
            f'{what}: principal SSH to the guest failed; {_SSH_CHANNEL_HINT}'))
    return SecretsError('guest_setup', detail=f'{what} (guest exit status {code})')


def _identity_command(action: str, *, root: Path | None,
                      untrusted: tuple[Path, ...] = (),
                      extra: list[str] | None = None) -> list[str]:
    """The exact argv of one isolated identity-service operation."""
    from .secrets_transport import interpreter_flags

    cmd = [sys.executable, *interpreter_flags(), '-m', 'aivm_secrets',
           'identity', action]
    if root is not None:
        cmd += ['--root', str(Path(root).expanduser().absolute())]
        for path in untrusted:
            cmd += ['--untrusted-root', str(path)]
    cmd += list(extra or ())
    return cmd


def _guarded_revoke_extra(subject: str, epoch: int | str,
                          thumbprint: str) -> list[str]:
    # Each option and its value are one argv word. A base64url thumbprint
    # begins with '-' for about one certificate in 64, and argparse reads a
    # separate word like that as an option and refuses the whole command.
    return [f'--subject={subject}', f'--expected-epoch={epoch}',
            f'--expected-certificate-sha256={thumbprint}']


def _manual_revoke(*, authority_root: Path, untrusted: tuple[Path, ...],
                   subject: str, epoch: int | str, thumbprint: str) -> str:
    """The command an operator runs to fence one undelivered certificate.

    ``epoch`` and ``thumbprint`` may be placeholders when the certificate
    is not known yet.

    It is the same compare-and-swap revocation AIVM itself would run, so it
    can never revoke a later enrollment that replaced this one.
    """
    return shlex.join(_identity_command(
        'revoke-if-current', root=authority_root, untrusted=untrusted,
        extra=_guarded_revoke_extra(subject, epoch, thumbprint)))


def _manual_status(*, authority_root: Path, untrusted: tuple[Path, ...]) -> str:
    """The command an operator runs to read the identity registry."""
    return shlex.join(_identity_command('status', root=authority_root,
                                        untrusted=untrusted))


def _identity_action(manager: CommandManager, *, action: str, root: Path | None,
                     untrusted: tuple[Path, ...] = (), extra: list[str] | None = None,
                     timeout: int = 30) -> dict[str, Any]:
    """Fixed JSON process protocol: AIVM never imports the secrets backend.

    Rust can implement these same verbs and output shapes without changing
    the VM adapter. No bearer credential or signing key crosses stdout.
    """
    from .secrets_transport import broker_environment

    cmd = _identity_command(action, root=root, untrusted=untrusted, extra=extra)
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
                     untrusted: tuple[Path, ...],
                     renewal: tuple[int, str] | None = None,
                     rotate_key: bool = False,
                     observed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Certificate parsing and CA signing both occur in isolated processes.

    ``observed`` is the subject's registry row as read before this attempt
    (``None``: no row). Once the issuing child has been dispatched, a
    failure no longer proves that nothing was issued, so it is settled
    against that row (:func:`_settle_failed_issuance`) before it propagates.
    A failure before that point -- including a refused CSR inspection --
    issued nothing and propagates as it is.
    """
    if rotate_key and renewal is None:
        raise SecretsError('invalid_policy')
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
        options = [f'--subject={subject}', '--csr', public_file.name,
                   '--approve-key-fingerprint', fingerprint]
        if renewal is not None:
            epoch, thumbprint = renewal
            # One word each: a thumbprint may begin with '-' (see
            # _guarded_revoke_extra).
            options += [f'--expected-epoch={epoch}',
                        f'--expected-certificate-sha256={thumbprint}']
            action = 'rotate-client-key' if rotate_key else 'renew-client'
        else:
            if replace:
                options.append('--replace')
            action = 'enroll'
        try:
            value = _identity_action(manager, action=action, root=authority_root,
                                     untrusted=untrusted, extra=options)
            if (value.get('subject') != subject or
                    type(value.get('certificate_sha256')) is not str or
                    type(value.get('epoch')) is not int or
                    type(value.get('not_after')) is not int):
                raise SecretsError('guest_setup', detail='invalid CA enrollment reply')
        except (CommandError, SecretsError) as failure:
            # A refusal (CommandControlError) is not caught: the issuing
            # command was declined before it ran, so it issued nothing.
            _settle_failed_issuance(manager, authority_root=authority_root,
                                    untrusted=untrusted, subject=subject,
                                    observed=observed, failure=failure)
            raise
        except KeyboardInterrupt:
            # The interrupt reached the child too, which may already have
            # committed. Running another command would continue past it, so
            # only say how to find out, then re-raise unchanged.
            _warn_unsettled_issuance(authority_root=authority_root,
                                     untrusted=untrusted, subject=subject,
                                     observed=observed)
            raise
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


def _guest_install_script(*, rotate_key: bool) -> str:
    """Install public material only for the key the guest will present.

    All command text is fixed at development time. Before anything is moved
    into place the guest compares the SubjectPublicKeyInfo of the issued
    certificate with its private key: ``client.key`` for an enrollment or
    renewal, the staged ``client.rotate.key`` for a key rotation (which must
    also differ from the active key, to rule out a no-op). A mismatch exits
    nonzero and leaves the installed files untouched, and the host then
    fences the undelivered certificate with its guarded revocation. The new
    private key is created by the forced guest bootstrap helper under the
    guest UID, never conveyed over SSH or handled by the host; no credential
    fallback is attempted.
    """
    prefix = (
        'umask 077 && set -e && '
        'install -d -m 700 "$HOME/.config/aivm/identity" && '
        'cd "$HOME/.config/aivm/identity" && '
        'IFS= read -r certificate && IFS= read -r ca && '
        'printf "%s" "$certificate" | base64 -d > client.pem.new && '
        'printf "%s" "$ca" | base64 -d > ca.pem.new && '
        'chmod 600 client.pem.new ca.pem.new && '
        'test -f client.key && test ! -L client.key && '
        'scratch="$(mktemp -d ./.identity-check.XXXXXXXX)" && '
        'trap \'rm -rf -- "$scratch"\' EXIT && '
        'openssl x509 -in client.pem.new -pubkey -noout '
        '> "$scratch/cert.pub" && '
        'openssl pkey -pubin -in "$scratch/cert.pub" '
        '-outform DER -out "$scratch/cert.der" && '
        'openssl pkey -in client.key -pubout -outform DER '
        '-out "$scratch/active.der" && '
    )
    if not rotate_key:
        return prefix + (
            'cmp -s "$scratch/active.der" "$scratch/cert.der" && '
            'mv -f client.pem.new client.pem && mv -f ca.pem.new ca.pem'
        )
    # The host independently performs the *same-key* rejection against the
    # enrolled leaf. Activation moves the staged CSR over client.csr too, so
    # the cached request always belongs to the active key.
    return prefix + (
        'test -f client.rotate.key && test ! -L client.rotate.key && '
        'test -f client.rotate.csr && test ! -L client.rotate.csr && '
        'openssl pkey -in client.rotate.key -pubout -outform DER '
        '-out "$scratch/new.der" && '
        'cmp -s "$scratch/new.der" "$scratch/cert.der" && '
        '! cmp -s "$scratch/new.der" "$scratch/active.der" && '
        'cp client.rotate.key client.key.new && chmod 600 client.key.new && '
        'mv -f client.pem.new client.pem && mv -f ca.pem.new ca.pem && '
        'mv -f client.key.new client.key && '
        'mv -f client.rotate.csr client.csr && rm -f client.rotate.key'
    )


def _guest_csr_refresh_script() -> str:
    """Re-sign ``client.csr`` with the guest's active ``client.key``.

    Guests keep the forced helper they were created with until an explicit
    helper upgrade, and an older helper answers ``identity-csr`` by replaying
    ``client.csr`` verbatim. Every guest that ever ran identity_rotate_key
    under the old activation script still holds the CSR for its *retired*
    key there, so a renewal would re-certify the key rotation retired. This
    fixed step runs first, over the same strictly pinned principal SSH as the
    install, and regenerates the CSR as the guest user (scratch name, then
    rename) so any helper presents the active key. A guest with no
    ``client.key`` yet is left alone: the helper creates its first key.
    """
    return (
        'umask 077 && cd "$HOME" && '
        'if test -e .config/aivm/identity/client.key || '
        'test -L .config/aivm/identity/client.key; then '
        'cd .config/aivm/identity && test -f client.key && '
        'test ! -L client.key && '
        'scratch="$(mktemp ./.client.csr.XXXXXXXX)" && '
        'trap \'rm -f -- "$scratch"\' EXIT && '
        'openssl req -new -key client.key -subj /CN=aivm-guest '
        '-out "$scratch" && '
        'mv -f -- "$scratch" client.csr; fi'
    )


def _subject_row(status: dict[str, Any], subject: str) -> dict[str, Any] | None:
    subjects = status.get('subjects')
    row = subjects.get(subject) if type(subjects) is dict else None
    return row if type(row) is dict else None


def _active_certificate(row: dict[str, Any] | None) -> tuple[int, str] | None:
    """``(epoch, thumbprint)`` of an active, well-formed registry row."""
    if (row is None or row.get('active') is not True or
            type(row.get('epoch')) is not int or
            type(row.get('certificate_sha256')) is not str):
        return None
    return row['epoch'], row['certificate_sha256']


def _issued_since(observed: dict[str, Any] | None,
                  row: dict[str, Any] | None) -> tuple[int, str] | None:
    """The active certificate ``row`` holds that ``observed`` did not.

    Compared by certificate, not by epoch: epochs only increase while a row
    exists, and a row that is removed (pruned, forgotten, or erased by a CA
    rollover) and then enrolled again restarts at epoch 0.
    """
    current = _active_certificate(row)
    if current is None:
        return None
    before = _active_certificate(observed)
    if before is not None and before[1] == current[1]:
        return None
    return current


def _warn_unsettled_issuance(*, authority_root: Path,
                             untrusted: tuple[Path, ...], subject: str,
                             observed: dict[str, Any] | None) -> None:
    """Say how to find and fence an issuance that may have committed.

    Used when an interrupt or a refusal stops AIVM from checking. No further
    command may run then, so the operator is given the registry read and
    the guarded revocation (with placeholders) to run themselves.
    """
    before = _active_certificate(observed)
    unless = ('' if before is None else
              f' other than epoch {before[0]} (certificate {before[1]})')
    log.warning(
        'Certificate issuance for {} was interrupted or refused before its '
        'outcome was known, and may already have committed a certificate '
        'that no guest will receive. Read the registry with `{}`; if {} now '
        'holds an active certificate{} that is not another operator\'s '
        'enrollment, revoke it with: {}',
        subject, _manual_status(authority_root=authority_root,
                                untrusted=untrusted),
        subject, unless,
        _manual_revoke(authority_root=authority_root, untrusted=untrusted,
                       subject=subject, epoch='EPOCH',
                       thumbprint='CERTIFICATE_SHA256'))


def _settle_failed_issuance(manager: CommandManager, *, authority_root: Path,
                            untrusted: tuple[Path, ...], subject: str,
                            observed: dict[str, Any] | None,
                            failure: BaseException) -> None:
    """Raise ``outcome_unknown`` when a failed issuance may still have landed.

    The CA child commits the registry before it prints its reply, and it can
    fail after that commit: a timeout, a crash, a failed audit record or
    directory sync after the registry was replaced, or a malformed reply.
    Its exit status does not separate those from a refusal, so every
    failure of the issuing child is settled here. Re-read the registry: if
    the subject now holds an active certificate it did not hold before the
    attempt, report exactly which one and the compare-and-swap command that
    revokes it. That certificate is either this attempt's lost issuance or
    an enrollment another operator made meanwhile -- a competing renewal is
    also what makes a renewal fail its compare-and-swap -- and nothing here
    can tell which. So the operator is asked to check, and it is never
    revoked from here. Return (so the original error stands) when the
    registry shows nothing new.
    """
    after: dict[str, Any] = {}
    try:
        with manager.attempt('Re-read the identity registry after a failed issuance',
                             catch=(CommandError, SecretsError)) as rereading:
            after = _identity_action(manager, action='status',
                                     root=authority_root, untrusted=untrusted)
    except (CommandControlError, KeyboardInterrupt):
        # The re-read itself was refused: that decision stands, unchanged.
        _warn_unsettled_issuance(authority_root=authority_root,
                                 untrusted=untrusted, subject=subject,
                                 observed=observed)
        raise
    if rereading.failed:
        raise SecretsError('outcome_unknown', detail=(
            f'certificate issuance for {subject} did not return a usable reply '
            'and the registry could not be re-read to tell whether it '
            'committed; inspect it with: '
            + _manual_status(authority_root=authority_root, untrusted=untrusted))
        ) from failure
    issued = _issued_since(observed, _subject_row(after, subject))
    if issued is None:
        return
    epoch, thumbprint = issued
    command = _manual_revoke(authority_root=authority_root, untrusted=untrusted,
                             subject=subject, epoch=epoch, thumbprint=thumbprint)
    raise SecretsError('outcome_unknown', detail=(
        f'certificate issuance for {subject} did not return a usable reply, '
        'and the registry has changed since this command read it: it now '
        f'holds active epoch {epoch} (certificate {thumbprint}). That is '
        'either this attempt\'s certificate, committed but never delivered, '
        'or an enrollment another operator made meanwhile (a competing '
        'renewal also makes this one fail). Check which before revoking; '
        'only if it is not another operator\'s, revoke it with: '
        + command)) from failure


def _warn_undelivered(*, subject: str, epoch: int, command: str) -> None:
    log.warning(
        'Certificate epoch {} for {} was issued but never delivered to the '
        'guest, and the rest of the enrollment was refused or interrupted. '
        'It stays active until revoked; revoke it with: {}',
        epoch, subject, command)


def _revoke_undelivered(manager: CommandManager, *, authority_root: Path,
                        untrusted: tuple[Path, ...], subject: str,
                        record: dict[str, Any], failure: BaseException) -> None:
    """Fence a certificate that failed delivery, without touching a newer one.

    The revocation is host-locked and compare-and-swap on the exact epoch and
    thumbprint just issued, so it can never revoke an enrollment another
    operator has since replaced it with. Raises when the undo itself did not
    complete; returns so the caller re-raises the original failure otherwise.
    """
    command = _manual_revoke(authority_root=authority_root, untrusted=untrusted,
                             subject=subject, epoch=record['epoch'],
                             thumbprint=record['certificate_sha256'])
    answer: dict[str, Any] = {}
    try:
        with manager.attempt('Revoke the undelivered enrollment',
                             why='A certificate the guest never installed must '
                                 'not stay active.',
                             catch=(CommandError, SecretsError)) as undo:
            answer = _identity_action(
                manager, action='revoke-if-current', root=authority_root,
                untrusted=untrusted,
                extra=_guarded_revoke_extra(subject, record['epoch'],
                                            record['certificate_sha256']))
            if type(answer.get('revoked')) is not bool:
                raise SecretsError('guest_setup', detail='invalid cleanup result')
    except (CommandControlError, KeyboardInterrupt):
        # The user refused the undo itself: that decision stands, unchanged.
        _warn_undelivered(subject=subject, epoch=record['epoch'], command=command)
        raise
    if undo.failed:
        raise SecretsError('guest_setup', detail=(
            'guest identity delivery failed and the guarded revocation of '
            f'certificate epoch {record["epoch"]} for {subject} did not '
            'complete; revoke it with: ' + command)) from failure
    if answer.get('revoked') is True:
        log.info('Revoked undelivered certificate epoch {} for {}.',
                 record['epoch'], subject)
    else:
        log.info('Undelivered certificate epoch {} for {} was already replaced '
                 'or revoked; nothing to undo.', record['epoch'], subject)


def enroll_managed_vm(*, context: ResolvedVMContext, store: Path, ip: str,
                      authority_root: Path, replace: bool = False,
                      renew: bool = False, rotate_key: bool = False,
                      uuid_reader: Callable[[str], str] | None = None,
                      ) -> dict[str, Any]:
    """One explicitly requested and authenticated CSR enrollment transaction.

    The forced bootstrap private key is controlled by AIVM's machine store.
    `identity-csr` runs only fixed non-root commands in the guest and returns
    just a PKCS#10 CSR. Its host request includes a fresh nonce to reject stale
    replies. The subject is *not* taken from that reply or its CSR CN.

    Every principal-account step uses the VM's pinned host key (see
    :func:`_principal_known_hosts`). A failure after the CA issues the
    certificate is compensated by a guarded revocation of exactly that
    certificate; a *refusal* after issuance is never overridden by running
    that revocation, and is re-raised once the manual undo is logged.
    """
    if (type(renew) is not bool or type(rotate_key) is not bool or
            (renew and replace) or (rotate_key and not renew)):
        raise SecretsError('invalid_policy')
    lookup = {} if uuid_reader is None else {'uuid_reader': uuid_reader}
    bound = resolve_managed_identity(context, store, **lookup)
    untrusted = guest_writable_roots(store)
    authority_root = Path(authority_root).expanduser().absolute()
    manager = CommandManager.current()
    status = _identity_action(manager, action='status', root=authority_root,
                              untrusted=untrusted)
    row = _subject_row(status, bound.subject)
    renewal: tuple[int, str] | None = None
    if renew:
        if (row is None or row.get('active') is not True or
                type(row.get('epoch')) is not int or
                type(row.get('certificate_sha256')) is not str):
            raise SecretsError('revoked', detail='identity is not enrolled')
        renewal = (row['epoch'], row['certificate_sha256'])
    # Resolve the pinned principal channel before touching the guest, so an
    # unpinned VM is refused before anything runs, let alone gets issued.
    principal_ssh = _principal_ssh(context, store, ip)
    if not rotate_key:
        refreshed = manager.run(
            [*principal_ssh, Elided(_guest_csr_refresh_script(),
                                    're-sign guest CSR with its active key')],
            sudo=False, role='modify', ownership='tool', capture=True,
            check=False, timeout=30,
            summary='Re-sign the cached guest CSR with its active key',
        )
        if refreshed.code:
            raise _principal_ssh_failure(refreshed.code, 'guest CSR refresh failed')
    nonce = secrets.token_hex(16)
    csr_operation = 'identity-key-rotate-csr' if rotate_key else 'identity-csr'
    request = {'operation': csr_operation, 'guest_user': bound.guest_user,
               'uid': bound.host_uid, 'nonce': nonce}
    scope = resolve_store_scope(str(store))
    assert scope.machine_layout is not None
    bootstrap = require_bootstrap_identity(bound.vm, layout=scope.machine_layout)
    result = manager.run(
        _bootstrap_ssh(context, store, ip, operation=csr_operation),
        sudo=bootstrap.use_sudo, role='modify', capture=True, check=False,
        input_text=json.dumps(request, sort_keys=True) + '\n', timeout=60,
        summary='Retrieve guest-owned CSR over the forced bootstrap channel',
    )
    if result.code == 255:
        raise SecretsError('guest_setup', detail=(
            f'forced CSR bootstrap SSH failed; {_SSH_CHANNEL_HINT}'))
    if result.code:
        # Existing guests may not yet have the updated forced helper. Do not
        # fall back to interactive SSH or unauthenticated CSR retrieval.
        raise SecretsError('guest_setup', detail='forced CSR bootstrap failed; '
                           'guest helper upgrade may be required')
    try:
        data = json.loads(result.stdout)
        if (type(data) is not dict or set(data) != {
                'status', 'operation', 'guest_user', 'uid', 'nonce', 'csr'} or
                data['status'] != 'ok' or data['operation'] != csr_operation or
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
    if resolve_managed_identity(context, store, **lookup) != bound:
        raise SecretsError('revoked', detail='VM identity changed during enrollment')
    # A failure of the issuing child itself is settled against ``row`` in
    # there: it may have committed a certificate before failing (MISSING-8).
    record = _isolated_enroll(manager, authority_root=authority_root,
                              subject=bound.subject, csr=csr,
                              replace=replace, untrusted=untrusted,
                              renewal=renewal, rotate_key=rotate_key,
                              observed=row)
    try:
        if renewal is not None and record['epoch'] != renewal[0] + 1:
            raise SecretsError('guest_setup',
                               detail='unexpected certificate renewal epoch')
        # Obtain only public material from the isolated authority. Failure
        # after issuance must be compensated just like guest delivery failure.
        public = _public_client(manager, root=authority_root,
                                subject=bound.subject, untrusted=untrusted)
        if public['certificate_sha256'] != record['certificate_sha256']:
            raise SecretsError('revoked', detail='certificate changed during enrollment')
        script = Elided(_guest_install_script(rotate_key=rotate_key),
                        'SPKI-checked guest key activation' if rotate_key
                        else 'SPKI-checked guest certificate install')
        payload = public['certificate_pem_b64'] + '\n' + public['ca_pem_b64'] + '\n'
        installed = manager.run(
            [*principal_ssh, script], input_text=payload,
            sudo=False, role='modify', ownership='tool', capture=True,
            check=False, timeout=30,
            summary=('Activate guest key rotation and public certificate'
                     if rotate_key else 'Install public identity certificate and CA in guest'),
        )
        if installed.code:
            raise _principal_ssh_failure(installed.code,
                                         'guest certificate install failed')
    except (CommandControlError, KeyboardInterrupt):
        # The user declined (or could not approve) a step after the CA issued
        # this certificate. Running the revocation now would continue past
        # that decision, so only say how to undo it, and re-raise unchanged.
        _warn_undelivered(subject=bound.subject, epoch=record['epoch'],
                          command=_manual_revoke(
                              authority_root=authority_root, untrusted=untrusted,
                              subject=bound.subject, epoch=record['epoch'],
                              thumbprint=record['certificate_sha256']))
        raise
    except Exception as failure:
        # A delayed failure must NEVER revoke an enrollment that another
        # operator has already replaced: the undo is epoch+thumbprint CAS.
        _revoke_undelivered(manager, authority_root=authority_root,
                            untrusted=untrusted, subject=bound.subject,
                            record=record, failure=failure)
        raise
    return {'vm': bound.vm, 'domain_uuid': bound.uuid,
            'subject': bound.subject, 'principal_id': bound.principal_id,
            'certificate_sha256': record['certificate_sha256'],
            'epoch': record['epoch'], 'not_after': record['not_after']}


def _bridge_process(manager: CommandManager, *, authority_root: Path,
                    broker_socket: Path, listen: Path, subject: str,
                    untrusted: tuple[Path, ...], idle_seconds: int):
    """Run the credential-related bridge under a fresh isolated interpreter.

    The bridge serves exactly one VM, so it is pinned to that VM's subject: a
    presentation for any other enrolled subject is refused before dispatch.
    It has no connection cap -- its idle timeout and the stdin lease bound its
    lifetime -- because a cap would end a healthy session after a fixed
    number of guest commands.
    """
    import select
    import sys
    import time
    from .secrets_transport import BrokerProcess, broker_environment, interpreter_flags

    cmd = [sys.executable, *interpreter_flags(), '-m', 'aivm_secrets',
           'identity', 'bridge', '--root', str(authority_root),
           '--broker-socket', str(broker_socket), '--listen', str(listen),
           '--idle-seconds', str(min(3600, max(60, idle_seconds))),
           f'--subject={subject}', '--exit-on-stdin-eof']
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
        if (type(ready) is not dict or ready.get('listening') != str(listen)
                or ready.get('subject') != subject):
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
            listen=bound_socket, subject=bound.subject, untrusted=untrusted,
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
