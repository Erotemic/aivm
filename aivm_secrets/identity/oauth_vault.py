"""Encrypted, host-principal-owned OAuth credentials for the Garrett issuer.

The private vault key and encrypted token/refresh material never enter a VM.
Provider configuration is pinned by its SHA256 digest; host-selected service
policies independently limit which operations a broker may execute. A restore
of an older vault snapshot remains a trusted-host rollback risk (P4c).
"""
from __future__ import annotations

import fcntl
import hmac
from dataclasses import dataclass, field
import hashlib
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from ..errors import SecretsError
from ..host.files import private_directory, read_owned, write_new
from ..host.audit import AuditLog
from ..primitives import codec, grammar
from .garrett.oauth_contract import (AccessGrant, require_active,
                                     parse_grant, record_grant)
from .oauth_provider import OAuthProvider
from .oauth_transport import PinnedOAuthHTTP, refresh_token

AAD = b'aivm-secrets/oauth-vault/v1\0'
SCHEMA = 1
MAX_RECORD = 32768


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SecretsError('missing_crypto') from None
    return AESGCM


def _subject(value: str) -> str:
    return grammar.token(value, grammar.ALNUM, grammar.ALNUM + '-_.', 128,
                         code='credential_source')


def _account(provider: OAuthProvider, subject: str) -> str:
    _subject(subject)
    return hashlib.sha256((provider.name + '\x00' + subject).encode()).hexdigest()


@dataclass(frozen=True)
class CredentialLease:
    """Host-only snapshot; no repr or serialization of the bearer token."""
    credential: str = field(repr=False)
    epoch: int
    generation: int
    expires_at: int


class OAuthVault:
    def __init__(self, root: Path, *, untrusted: tuple[Path, ...] = ()):
        self.root = Path(root).expanduser().absolute()
        self.untrusted = tuple(Path(p).expanduser().absolute() for p in untrusted)
        if not self.root.is_dir():
            raise SecretsError('unsafe_file')
        private_directory(self.root, self.untrusted)
        key = read_owned(self.root / 'vault.aes256', private=True,
                         limit=64, untrusted=self.untrusted,
                         what='OAuth vault encryption key')
        if len(key) != 32:
            raise SecretsError('unsafe_file')
        self._aead = _crypto()(key)
        self._lock = self.root / '.vault.lock'
        read_owned(self._lock, private=True, limit=128,
                   untrusted=self.untrusted, what='OAuth vault lock')

    @classmethod
    def initialize(cls, root: Path, *, untrusted: tuple[Path, ...] = ()):
        root = Path(root).expanduser().absolute()
        private_directory(root.parent, untrusted)
        try:
            root.mkdir(mode=0o700, exist_ok=False)
        except OSError:
            raise SecretsError('unsafe_file') from None
        private_directory(root, untrusted)
        write_new(root / 'vault.aes256', secrets.token_bytes(32))
        write_new(root / '.vault.lock', b'')
        private_directory(root / 'audit', untrusted)
        return cls(root, untrusted=untrusted)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        # Lock before read / network refresh / write to prevent parallel use
        # of the same one-time refresh token. Lock path was pre-created O_EXCL.
        read_owned(self._lock, private=True, limit=128,
                   untrusted=self.untrusted, what='OAuth vault lock')
        fd = os.open(self._lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextmanager
    def _audit(self, event: str, provider: OAuthProvider, subject: str,
               now: int) -> Iterator[None]:
        """Durable, secret-free intent before an OAuth state mutation."""
        folder = private_directory(self.root / 'audit', self.untrusted)
        log = AuditLog(folder / (secrets.token_hex(16) + '.jsonl'),
                       secrets.token_hex(16))
        resource = {'subject': subject}
        digest = hashlib.sha256((provider.digest + subject).encode()).hexdigest()
        try:
            log.record(event, timestamp=now, resource=resource, digest=digest)
            yield
            log.record('oauth_recorded', timestamp=int(time.time()),
                       resource=resource, digest=digest)
        finally:
            log.close()

    def _path(self, provider: OAuthProvider, subject: str) -> Path:
        return self.root / (_account(provider, subject) + '.json')

    def _read(self, provider: OAuthProvider, subject: str) -> dict:
        path = self._path(provider, subject)
        raw = read_owned(path, private=True, limit=MAX_RECORD,
                         untrusted=self.untrusted, what='OAuth vault record')
        try:
            wrapper = grammar.exact_keys(codec.loads(raw,
                limit=MAX_RECORD, code='credential_source'),
                frozenset({'schema', 'nonce', 'ciphertext'}),
                code='credential_source')
            if type(wrapper['schema']) is not int or wrapper['schema'] != SCHEMA:
                raise ValueError('schema')
            import base64
            import binascii
            try:
                nonce = base64.b64decode(wrapper['nonce'], validate=True)
                encrypted = base64.b64decode(wrapper['ciphertext'], validate=True)
            except (binascii.Error, ValueError):
                raise ValueError('encoding') from None
            if len(nonce) != 12 or len(encrypted) > MAX_RECORD:
                raise ValueError('size')
            aad = AAD + _account(provider, subject).encode('ascii')
            try:
                data = codec.loads(self._aead.decrypt(nonce, encrypted, aad),
                                   limit=MAX_RECORD, code='credential_source')
            except Exception:
                # Never leak cryptographic or parser exception strings; a
                # corrupted record cannot yield a credential or be refreshed.
                raise SecretsError('credential_source') from None
            data = grammar.exact_keys(data, frozenset({
                'schema', 'provider_digest', 'subject', 'active', 'epoch', 'grant',
            }), code='credential_source')
            if (data['schema'] != 1 or type(data['schema']) is not int or
                    data['subject'] != subject or
                    data['provider_digest'] != provider.digest or
                    type(data['active']) is not bool):
                raise ValueError('profile or subject mismatch')
            grammar.integer(data['epoch'], 0, 2**31 - 1,
                            code='credential_source')
            if data['grant'] is not None:
                parse_grant(data['grant'])
            return data
        except (ValueError, TypeError, UnicodeError, SecretsError, KeyError):
            raise SecretsError('credential_source') from None

    def _write(self, provider: OAuthProvider, subject: str,
               *, grant: AccessGrant | None, active: bool, epoch: int) -> None:
        import base64
        data = codec.dumps({'schema': 1, 'provider_digest': provider.digest,
                            'subject': subject, 'active': active, 'epoch': epoch,
                            'grant': None if grant is None else record_grant(grant)})
        nonce = secrets.token_bytes(12)
        payload = codec.dumps({
            'schema': SCHEMA,
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'ciphertext': base64.b64encode(self._aead.encrypt(
                nonce, data, AAD + _account(provider, subject).encode('ascii'))
            ).decode('ascii'),
        })
        if len(payload) > MAX_RECORD:
            raise SecretsError('credential_source')
        path = self._path(provider, subject)
        # Atomic replacement with fsync; never fall back to an unencrypted
        # record or overwrite through a symlink.
        name = self.root / ('.vault-' + secrets.token_hex(12) + '.tmp')
        try:
            write_new(name, payload)
            if path.exists() or path.is_symlink():
                read_owned(path, private=True, limit=MAX_RECORD,
                           untrusted=self.untrusted, what='OAuth vault record')
            os.replace(name, path)
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            try:
                name.unlink()
            except FileNotFoundError:
                pass

    def enroll(self, provider: OAuthProvider, subject: str, grant: AccessGrant,
               *, replace: bool = False) -> dict:
        """Store a host-acquired OAuth grant; never return its tokens."""
        if type(grant) is not AccessGrant or type(replace) is not bool:
            raise SecretsError('credential_source')
        if not set(grant.scopes) <= set(provider.scopes):
            raise SecretsError('credential_source')
        with self._locked():
            path = self._path(provider, subject)
            epoch = 0
            if path.exists() or path.is_symlink():
                old = self._read(provider, subject)
                if old['active'] and not replace:
                    raise SecretsError('denied')
                epoch = old['epoch'] + 1
                if epoch > 2**31 - 1:
                    raise SecretsError('revoked')
            with self._audit('oauth_enroll_intent', provider, subject, int(time.time())):
                self._write(provider, subject, grant=grant, active=True, epoch=epoch)
        return {'provider': provider.name, 'subject': subject,
                'expires_at': grant.expires_at, 'epoch': epoch,
                'scopes': list(grant.scopes)}

    def revoke(self, provider: OAuthProvider, subject: str) -> dict:
        with self._locked():
            old = self._read(provider, subject)
            epoch = old['epoch'] + 1 if old['active'] else old['epoch']
            if epoch > 2**31 - 1:
                raise SecretsError('revoked')
            if old['active']:
                with self._audit('oauth_revoke_intent', provider, subject, int(time.time())):
                    self._write(provider, subject, grant=None, active=False, epoch=epoch)
        return {'provider': provider.name, 'subject': subject,
                'active': False, 'epoch': epoch}

    def status(self, provider: OAuthProvider, subject: str) -> dict:
        with self._locked():
            row = self._read(provider, subject)
        return {'provider': provider.name, 'subject': subject,
                'active': row['active'], 'epoch': row['epoch'],
                'expires_at': (row['grant'] or {}).get('expires_at'),
                'scopes': (row['grant'] or {}).get('scopes', [])}

    def session_snapshot(self, provider: OAuthProvider, subject: str,
                         *, resource_host: str, now: int | None = None,
                         transport: Any = None,
                         force_refresh: bool = False) -> CredentialLease:
        """Atomically acquire an access token and its revocable lease witness."""
        if resource_host != provider.resource_host:
            raise SecretsError('invalid_policy')
        stamp = int(time.time()) if now is None else now
        with self._locked():
            row = self._read(provider, subject)
            if not row['active'] or row['grant'] is None:
                raise SecretsError('revoked')
            grant = parse_grant(row['grant'])
            if force_refresh or stamp + 60 >= grant.expires_at:
                if grant.refresh_token is None:
                    raise SecretsError('expired')
                with self._audit('oauth_refresh_intent', provider, subject, stamp):
                    successor = refresh_token(provider, grant, now=stamp,
                                              transport=transport or PinnedOAuthHTTP(),
                                              untrusted=self.untrusted)
                    # Never automatically retry a potentially consumed rotating
                    # refresh token following an ambiguous provider failure.
                    self._write(provider, subject, grant=successor,
                                active=True, epoch=row['epoch'])
                grant = successor
            token = require_active(grant, now=stamp, leeway=0)
            return CredentialLease(token, row['epoch'], grant.generation,
                                   grant.expires_at)

    @contextmanager
    def active_lease(self, provider: OAuthProvider, subject: str,
                     snapshot: CredentialLease) -> Iterator[None]:
        """Hold the vault lock across each broker request (including egress).

        A completed `revoke` or `refresh` cannot race ahead of an authorized
        effect and then leave an old session acting on its previous token.
        In-flight operations may finish *before* the mutation returns.
        """
        if type(snapshot) is not CredentialLease:
            raise SecretsError('credential_source')
        with self._locked():
            row = self._read(provider, subject)
            if not row['active'] or row['epoch'] != snapshot.epoch or row['grant'] is None:
                raise SecretsError('revoked')
            grant = parse_grant(row['grant'])
            if (grant.generation != snapshot.generation or
                    not hmac.compare_digest(grant.access_token,
                                            snapshot.credential)):
                raise SecretsError('revoked')
            require_active(grant, now=int(time.time()), leeway=0)
            yield

    def credential_for_session(self, provider: OAuthProvider, subject: str,
                               *, resource_host: str, now: int | None = None,
                               transport: Any = None,
                               force_refresh: bool = False) -> str:
        """Host-only compatibility facade: do not print to an agent."""
        return self.session_snapshot(provider, subject,
            resource_host=resource_host, now=now, transport=transport,
            force_refresh=force_refresh).credential


__all__ = ['OAuthVault', 'CredentialLease']
