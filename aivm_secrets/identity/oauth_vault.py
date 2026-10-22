"""Encrypted, host-principal-owned OAuth credentials for the Garrett issuer.

The private vault key and encrypted token/refresh material never enter a VM.
Provider configuration is pinned by its SHA256 digest; host-selected service
policies independently limit which operations a broker may execute. A restore
of an older vault snapshot remains a trusted-host rollback risk (P4c).

A record (schema 2) carries ``refresh_state``:

``none``             usable; a refresh may be attempted when needed
``in_doubt``         a refresh request may have reached the provider and its
                     outcome is unknown. The refresh token it presented may
                     already be spent, so nothing presents it again until the
                     operator asks for one deliberate retry
                     (``oauth-refresh --retry-in-doubt``), reauthorizes
                     (``oauth-login --replace``) or abandons the grant
                     without presenting it (``oauth-revoke``)
``reauth_required``  the provider answered ``invalid_grant``; only
                     ``oauth-login --replace`` (or ``oauth-revoke``) helps

``in_doubt`` is made durable *before* the refresh request is sent, and the
successor grant replaces it in the same single atomic replacement, so a lost
reply or a crash at any point can never lead to a silent replay. While the
process runs, a refresh that ends in doubt -- including one whose successor
could not be stored -- is audited as ``oauth_refresh_in_doubt``. A process
that is killed or interrupted mid-request records nothing more: its
``oauth_refresh_intent`` simply has no outcome event after it, and the record
on disk still says ``in_doubt``.

Using a record for a session requires the current provider profile. An
edited profile (same name, so the same record file) can still inspect,
revoke and replace the AEAD-authenticated record; doing so adopts it under
the new profile, advances its epoch and keeps a prefix of the old digest.
"""
from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Generator, Iterator

from ..errors import SecretsError
from ..host.audit import AuditLog
from ..host.files import private_directory, read_owned, replace_durable, write_new
from ..primitives import codec, grammar
from .garrett.oauth_contract import (AccessGrant, parse_grant, record_grant,
                                     require_active)
from .oauth_provider import OAuthProvider
from .oauth_transport import (REFRESH_IN_DOUBT, REFRESH_NOT_SENT,
                              REFRESH_REJECTED, PinnedOAuthHTTP,
                              assess_refresh, refresh_form)

AAD = b'aivm-secrets/oauth-vault/v1\0'
SCHEMA = 2
MAX_RECORD = 32768
MAX_EPOCH = 2**31 - 1
DIGEST_PREFIX = 16
REFRESH_STATES = ('none', 'in_doubt', 'reauth_required')
REAUTH_REQUIRED = 'reauth_required'
PROFILE_CHANGED = 'profile_changed'
_RECORD_KEYS = frozenset({'schema', 'provider_digest', 'subject', 'active',
                          'epoch', 'grant', 'refresh_state', 'previous_digest'})


def _crypto() -> Any:
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


def _require_settled(row: dict) -> None:
    """Refuse a record whose refresh token must not be presented again."""
    state = row['refresh_state']
    if state == 'in_doubt':
        raise SecretsError('credential_source', detail=REFRESH_IN_DOUBT)
    if state == 'reauth_required':
        raise SecretsError('credential_source', detail=REAUTH_REQUIRED)


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
    def initialize(cls, root: Path, *, untrusted: tuple[Path, ...] = ()
                   ) -> 'OAuthVault':
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
               now: int) -> Generator[Callable[[str, str], None], None, None]:
        """Durable, secret-free intent before an OAuth state mutation.

        Yields ``note(event, code)``, which records a follow-up event of the
        same intent (an outcome other than plain completion).
        """
        folder = private_directory(self.root / 'audit', self.untrusted)
        log = AuditLog(folder / (secrets.token_hex(16) + '.jsonl'),
                       secrets.token_hex(16))
        resource = {'subject': subject}
        digest = hashlib.sha256((provider.digest + subject).encode()).hexdigest()

        def note(follow: str, code: str = '') -> None:
            log.record(follow, timestamp=int(time.time()), code=code,
                       resource=resource, digest=digest)
        try:
            log.record(event, timestamp=now, resource=resource, digest=digest)
            yield note
            note('oauth_recorded', '')
        finally:
            log.close()

    def _path(self, provider: OAuthProvider, subject: str) -> Path:
        return self.root / (_account(provider, subject) + '.json')

    def _exists(self, provider: OAuthProvider, subject: str) -> bool:
        path = self._path(provider, subject)
        return path.exists() or path.is_symlink()

    def _read(self, provider: OAuthProvider, subject: str,
              *, any_profile: bool = False) -> dict:
        """Decrypt and validate one record.

        Only the current provider profile may *use* a record. ``any_profile``
        accepts one written under another profile of the same name -- still
        authenticated by the vault key and bound to this account -- for the
        operations that inspect, retire or replace it.
        """
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
            data = grammar.exact_keys(data, _RECORD_KEYS,
                                      code='credential_source')
            if (type(data['schema']) is not int or data['schema'] != SCHEMA or
                    data['subject'] != subject or
                    type(data['active']) is not bool or
                    data['refresh_state'] not in REFRESH_STATES):
                raise ValueError('malformed record')
            grammar.hex_string(data['provider_digest'], 64,
                               code='credential_source')
            if data['previous_digest'] != '':
                grammar.hex_string(data['previous_digest'], DIGEST_PREFIX,
                                   code='credential_source')
            grammar.integer(data['epoch'], 0, MAX_EPOCH,
                            code='credential_source')
            if data['grant'] is not None:
                parse_grant(data['grant'])
        except (ValueError, TypeError, UnicodeError, SecretsError, KeyError):
            raise SecretsError('credential_source') from None
        if not any_profile and data['provider_digest'] != provider.digest:
            # A policy or manifest edit never silently inherits an old grant.
            raise SecretsError('credential_source', detail=PROFILE_CHANGED)
        return data

    def _write(self, provider: OAuthProvider, subject: str, row: dict) -> None:
        """Seal ``row`` under the current profile and replace the record.

        Durable before it returns (data, rename and directory are synced),
        so an ``in_doubt`` marker exists on disk before the request it marks.
        """
        data = codec.dumps({
            'schema': SCHEMA, 'provider_digest': provider.digest,
            'subject': subject, 'active': row['active'], 'epoch': row['epoch'],
            'grant': row['grant'], 'refresh_state': row['refresh_state'],
            'previous_digest': row['previous_digest'],
        })
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
        # Never fall back to an unencrypted record or overwrite through a
        # symlink: an existing target must itself be a safe private file.
        if path.exists() or path.is_symlink():
            read_owned(path, private=True, limit=MAX_RECORD,
                       untrusted=self.untrusted, what='OAuth vault record')
        replace_durable(path, payload, prefix='.vault')

    def _successor_epoch(self, provider: OAuthProvider, subject: str,
                         replace: bool) -> tuple[int, str]:
        """Epoch and previous-digest note for a new enrollment, or raise."""
        if not self._exists(provider, subject):
            return 0, ''
        old = self._read(provider, subject, any_profile=True)
        if old['active'] and not replace:
            raise SecretsError('denied')
        if old['epoch'] >= MAX_EPOCH:
            raise SecretsError('exhausted')
        previous = old['previous_digest']
        if old['provider_digest'] != provider.digest:
            previous = old['provider_digest'][:DIGEST_PREFIX]
        return old['epoch'] + 1, previous

    def can_enroll(self, provider: OAuthProvider, subject: str,
                   *, replace: bool = False) -> None:
        """Raise exactly when :meth:`enroll` would refuse this subject now.

        A login checks this before any browser flow, so a refusal costs
        nothing upstream. ``enroll`` still decides under its own lock.
        """
        if type(replace) is not bool:
            raise SecretsError('credential_source')
        with self._locked():
            self._successor_epoch(provider, subject, replace)

    def enroll(self, provider: OAuthProvider, subject: str, grant: AccessGrant,
               *, replace: bool = False) -> dict:
        """Store a host-acquired OAuth grant; never return its tokens."""
        if type(grant) is not AccessGrant or type(replace) is not bool:
            raise SecretsError('credential_source')
        if not set(grant.scopes) <= set(provider.scopes):
            raise SecretsError('credential_source')
        with self._locked():
            epoch, previous = self._successor_epoch(provider, subject, replace)
            with self._audit('oauth_enroll_intent', provider, subject, int(time.time())):
                self._write(provider, subject, {
                    'active': True, 'epoch': epoch, 'grant': record_grant(grant),
                    'refresh_state': 'none', 'previous_digest': previous})
        return {'provider': provider.name, 'subject': subject,
                'expires_at': grant.expires_at, 'epoch': epoch,
                'scopes': list(grant.scopes), 'previous_digest': previous}

    def revoke(self, provider: OAuthProvider, subject: str) -> dict:
        """Deactivate the record; this always succeeds on a readable record.

        At the maximum epoch the record is deactivated *without* advancing:
        revocation must never fail open. A later enrollment then refuses
        with ``exhausted``.
        """
        with self._locked():
            old = self._read(provider, subject, any_profile=True)
            adopted = old['provider_digest'] != provider.digest
            epoch = old['epoch']
            previous = old['previous_digest']
            if old['active'] or adopted:
                if epoch < MAX_EPOCH:
                    epoch += 1
                if adopted:
                    previous = old['provider_digest'][:DIGEST_PREFIX]
                with self._audit('oauth_revoke_intent', provider, subject, int(time.time())):
                    self._write(provider, subject, {
                        'active': False, 'epoch': epoch, 'grant': None,
                        'refresh_state': 'none', 'previous_digest': previous})
        return {'provider': provider.name, 'subject': subject,
                'active': False, 'epoch': epoch, 'previous_digest': previous}

    def status(self, provider: OAuthProvider, subject: str) -> dict:
        """Nonsecret metadata, readable even after the profile was edited."""
        with self._locked():
            row = self._read(provider, subject, any_profile=True)
        grant = row['grant']
        return {'provider': provider.name, 'subject': subject,
                'active': row['active'], 'epoch': row['epoch'],
                'refresh_state': row['refresh_state'],
                'expires_at': None if grant is None else grant['expires_at'],
                'scopes': [] if grant is None else grant['scopes'],
                'generation': None if grant is None else grant['generation'],
                'has_refresh': (grant is not None and
                                grant['refresh_token'] is not None),
                'profile_current': row['provider_digest'] == provider.digest,
                'previous_digest': row['previous_digest']}

    def _refresh_locked(self, provider: OAuthProvider, subject: str,
                        row: dict, grant: AccessGrant, stamp: int,
                        transport: Any) -> AccessGrant:
        """Present the refresh token once; record what is known afterwards.

        Caller holds the lock. Everything that can fail without contacting
        the provider (client secret, trust anchors) happens before the
        ``in_doubt`` marker; once it is durable, only a definite answer
        moves the record out of it.
        """
        form = refresh_form(provider, grant, untrusted=self.untrusted)
        sender = (transport if transport is not None
                  else PinnedOAuthHTTP(untrusted=self.untrusted))
        prior = row['refresh_state']
        with self._audit('oauth_refresh_intent', provider, subject, stamp) as note:
            self._write(provider, subject, {**row, 'refresh_state': 'in_doubt'})
            try:
                response = sender.post(provider, form, untrusted=self.untrusted)
                successor = assess_refresh(provider, grant, response, now=stamp)
            except Exception as error:
                raise self._settle(provider, subject, row, prior, error,
                                   note) from None
            try:
                self._write(provider, subject, {
                    **row, 'grant': record_grant(successor),
                    'refresh_state': 'none'})
            except Exception:
                # The provider has rotated the token and the successor could
                # not be made durable (a full disk, say). What survives on
                # disk is the in_doubt marker, or at best an unsynced
                # successor: report and audit the conservative one.
                raise self._in_doubt(note, 0) from None
        return successor

    @staticmethod
    def _in_doubt(note: Callable[[str, str], None], status: int) -> SecretsError:
        """Audit that the durable in_doubt marker stays, and say so."""
        note('oauth_refresh_in_doubt', 'credential_source')
        return SecretsError('credential_source', status=status,
                            detail=REFRESH_IN_DOUBT)

    def _settle(self, provider: OAuthProvider, subject: str, row: dict,
                prior: str, error: Exception,
                note: Callable[[str, str], None]) -> SecretsError:
        """Move a failed refresh to what its definite outcome allows.

        Audit records carry the closed code ``credential_source``; the event
        names the outcome. If the record cannot be moved out of in_doubt, it
        stays there and is reported as in doubt.
        """
        reason = error.detail if type(error) is SecretsError else ''
        status = error.status if type(error) is SecretsError else 0
        settled = {REFRESH_NOT_SENT: (prior, 'oauth_refresh_not_sent'),
                   REFRESH_REJECTED: ('reauth_required', 'oauth_refresh_rejected')}
        if reason in settled:
            # not_sent: nothing left the host, so the record is exactly as
            # before. rejected: the grant is definitely unusable.
            state, event = settled[reason]
            try:
                self._write(provider, subject, {**row, 'refresh_state': state})
            except Exception:
                return self._in_doubt(note, status)
            note(event, 'credential_source')
            return SecretsError('credential_source', status=status,
                                detail=reason)
        # Anything else -- a lost reply, a 5xx, an unusable answer, an error
        # no one classified -- leaves the durable in_doubt marker in place.
        return self._in_doubt(note, status)

    def refresh(self, provider: OAuthProvider, subject: str,
                *, now: int | None = None, transport: Any = None,
                retry_in_doubt: bool = False) -> dict:
        """Explicitly refresh now (``oauth-refresh``); return the status.

        ``retry_in_doubt`` is the operator's deliberate decision to present
        an in-doubt refresh token exactly once more. It never overrides
        ``reauth_required``.
        """
        if type(retry_in_doubt) is not bool:
            raise SecretsError('credential_source')
        stamp = int(time.time()) if now is None else now
        with self._locked():
            row = self._read(provider, subject)
            if not row['active'] or row['grant'] is None:
                raise SecretsError('revoked')
            if not (retry_in_doubt and row['refresh_state'] == 'in_doubt'):
                _require_settled(row)
            self._refresh_locked(provider, subject, row,
                                 parse_grant(row['grant']), stamp, transport)
        return self.status(provider, subject)

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
            _require_settled(row)
            grant = parse_grant(row['grant'])
            if force_refresh or stamp + 60 >= grant.expires_at:
                grant = self._refresh_locked(provider, subject, row, grant,
                                             stamp, transport)
            token = require_active(grant, now=stamp, leeway=0)
            return CredentialLease(token, row['epoch'], grant.generation,
                                   grant.expires_at)

    @contextmanager
    def active_lease(self, provider: OAuthProvider, subject: str,
                     snapshot: CredentialLease) -> Iterator[None]:
        """Hold the vault lock across each broker request (including egress).

        A completed `revoke` or `refresh` cannot race ahead of an authorized
        effect and then leave an old session acting on its previous token.
        In-flight operations may finish *before* the mutation returns. A
        record whose refresh is in doubt or rejected ends every lease.
        """
        if type(snapshot) is not CredentialLease:
            raise SecretsError('credential_source')
        with self._locked():
            row = self._read(provider, subject)
            if not row['active'] or row['epoch'] != snapshot.epoch or row['grant'] is None:
                raise SecretsError('revoked')
            _require_settled(row)
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
