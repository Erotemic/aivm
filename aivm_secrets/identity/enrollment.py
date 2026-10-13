"""Host-controlled, opt-in certificate enrollment for P4a identity binding.

This module never contacts a provider or a VM. An operator associates a
proof-of-possession CSR with a named VM *out of band*. A CSR proves possession
of its software key, NOT which VM created it. The host CA, JWT signer and AEAD
key never cross that trust boundary. Disk state is principal-owned and every
bridge request re-reads the current enrollment (including revocation epoch).

The wire/state grammar is deliberately closed and straightforward to port to
Rust. Certificate signing, filesystem access, concurrency and the wall clock
remain explicit trusted I/O, not part of the pure Rust/Lean theorem target.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import os
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..errors import SecretsError
from ..host.audit import AuditLog
from ..host.files import private_directory, read_owned, write_new
from ..primitives import codec, grammar
from .garrett.claims import IdentityExpectation, MAX_EPOCH, MAX_IDENTITY_LIFETIME
from .garrett import registry as registry_model
from .garrett.protocol import prepare_issue
from .garrett import authority as authority_model
from .token import (IdentityTokenIssuer, certificate_thumbprint,
                    _crypto as _token_crypto)
from .certificates import (
    _x509, _key_pem, _certificate_pem, _certificate_der,
    _key_fingerprint, _leaf_certificate, _read_csr, create_ca,
)

SCHEMA = authority_model.SCHEMA
MAX_REGISTRY_BYTES = 131072
MAX_SUBJECTS = 128
CA_DAYS = 365
SERVER_DAYS = 30
CLIENT_DAYS = 7
MANIFEST = 'authority.json'
REGISTRY = 'enrollments.json'
CA_DIRECTORY = 'ca-generations'
LOCK = '.enrollment.lock'
KEYRING = 'issuer-keyring.json'
KEY_DIRECTORY = 'issuer-keys'
MAX_ISSUER_KEYS = 8
SERVER_DIRECTORY = 'server-generations'
MAX_SERVER_GENERATIONS = authority_model.MAX_SERVER_GENERATIONS
MAX_CA_GENERATIONS = authority_model.MAX_CA_GENERATIONS


def _subject(value: str) -> str:
    return IdentityExpectation.parse({
        'issuer': 'aivm.local', 'audience': 'aivm-secrets.identity',
        'subject': value, 'epoch': 0,
    }).subject


def _stamp(now: int | None = None) -> int:
    result = int(dt.datetime.now(dt.timezone.utc).timestamp()) if now is None else now
    if type(result) is not int or result < 0 or result > 2**63 - 1:
        raise SecretsError('invalid_capability')
    return result


class IdentityAuthority:
    """Private, per-host-principal CA, enrollment registry and JWT issuer.

    No issuance API is exposed to the guest. The operator must deliberately
    transport the public CSR and confirm which VM identity it belongs to.
    """

    def __init__(self, root: Path, *, untrusted: tuple[Path, ...] = ()):
        self.root = Path(root).expanduser().absolute()
        self.untrusted = tuple(Path(p).expanduser().absolute() for p in untrusted)
        if not self.root.exists():
            raise SecretsError('unsafe_file', detail='authority not initialized')
        private_directory(self.root, self.untrusted)
        manifest = self._manifest()
        self.issuer = manifest['issuer']
        self.audience = manifest['audience']
        self.ca_sha256 = manifest['ca']['sha256']
        self.ca_generation = manifest['ca']['generation']
        # Do not trust an authority manifest without validating its selected
        # immutable root. No legacy root paths or implicit migration exist.
        ca = self._certificate_for_active_ca()
        if hashlib.sha256(_certificate_der(ca)).hexdigest() != self.ca_sha256:
            raise SecretsError('invalid_capability')

    @classmethod
    def initialize(cls, root: Path, *, issuer: str, audience: str,
                   untrusted: tuple[Path, ...] = (), now: int | None = None):
        """Create a new private authority; never adopt or reset an old one."""
        _, _, _, ec, _, _ = _x509()
        Private, _, _ = _token_crypto()
        expected = IdentityExpectation.parse({
            'issuer': issuer, 'audience': audience, 'subject': 'init', 'epoch': 0,
        })
        root = Path(root).expanduser().absolute()
        untrusted = tuple(Path(p).expanduser().absolute() for p in untrusted)
        # Private parent plus O_EXCL-style mkdir means an already initialized
        # authority can never be silently reset or replaced.
        private_directory(root.parent, untrusted)
        try:
            root.mkdir(mode=0o700, exist_ok=False)
        except OSError:
            raise SecretsError('unsafe_file', detail='authority directory exists') from None
        private_directory(root, untrusted)
        stamp = _stamp(now)
        ca_key, ca = create_ca(now=stamp, days=CA_DAYS)
        server_key = ec.generate_private_key(ec.SECP256R1())
        server = _leaf_certificate(ca_key, ca, server_key.public_key(),
                                   name='localhost', now=stamp,
                                   days=SERVER_DAYS, server=True)
        signer = Private.generate()
        ca_hash = hashlib.sha256(_certificate_der(ca)).hexdigest()
        # This pre-deployment v2 format has no fallback to the original flat
        # authority files. Each identity belongs to exactly one active root.
        for folder in (CA_DIRECTORY, SERVER_DIRECTORY, KEY_DIRECTORY,
                       'clients', 'audit'):
            private_directory(root / folder, untrusted)
        authority_manifest = authority_model.initial(
            issuer=expected.issuer, audience=expected.audience,
            created_at=stamp, ca_sha256=ca_hash)
        entries = {
            f'{CA_DIRECTORY}/ca-1.key': _key_pem(ca_key),
            f'{CA_DIRECTORY}/ca-1.pem': _certificate_pem(ca),
            f'{SERVER_DIRECTORY}/server-1.key': _key_pem(server_key),
            f'{SERVER_DIRECTORY}/server-1.pem': _certificate_pem(server),
            f'{KEY_DIRECTORY}/local-1.key': _key_pem(signer),
            f'{KEY_DIRECTORY}/local-1.pub': signer.public_key().public_bytes(
                _x509()[2].Encoding.PEM,
                _x509()[2].PublicFormat.SubjectPublicKeyInfo),
            f'{KEY_DIRECTORY}/local-1.aes256': secrets.token_bytes(32),
            MANIFEST: codec.dumps(authority_manifest),
            REGISTRY: codec.dumps({'schema': registry_model.SCHEMA, 'subjects': {}}),
            KEYRING: codec.dumps({'schema': 1, 'active': 'local-1',
                                  'enabled': ['local-1'], 'next_number': 2}),
            LOCK: b'',
        }
        for name, data in entries.items():
            write_new(root / name, data)
        return cls(root, untrusted=untrusted)

    def _read(self, name: str, limit: int = 65536) -> bytes:
        return read_owned(self.root / name, private=True, limit=limit,
                          untrusted=self.untrusted, what='identity authority')

    @contextmanager
    def _locked(self) -> Iterator[None]:
        # The directory is private. Hold a pre-created regular lock inode;
        # forbid links and validate before opening it.
        self._read(LOCK, limit=128)
        fd = os.open(self.root / LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _registry(self) -> dict[str, Any]:
        value = codec.loads(self._read(REGISTRY, MAX_REGISTRY_BYTES),
                            limit=MAX_REGISTRY_BYTES, code='invalid_capability')
        return registry_model.validate(value, issuer=self.issuer,
                                       audience=self.audience)

    def _update(self, state: dict[str, Any]) -> None:
        data = codec.dumps(state)
        if len(data) > MAX_REGISTRY_BYTES:
            raise SecretsError('invalid_capability')
        name = f'.registry-{secrets.token_hex(12)}.tmp'
        tmp = self.root / name
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.root / REGISTRY)
            parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            raise SecretsError('audit_failed') from None
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    @contextmanager
    def _audit(self, event: str, subject: str, now: int,
               fingerprint: str) -> Iterator[None]:
        log = AuditLog(self.root / 'audit' / f'{secrets.token_hex(16)}.jsonl',
                       secrets.token_hex(16))
        try:
            log.record(event, timestamp=now, resource={'subject': subject},
                       digest=fingerprint)
            yield
            log.record('identity_recorded', timestamp=now,
                       resource={'subject': subject}, digest=fingerprint)
        finally:
            log.close()

    def _manifest(self) -> dict[str, Any]:
        return authority_model.validate(codec.loads(
            self._read(MANIFEST, 4096), limit=4096,
            code='invalid_capability'))

    def _assert_current_ca(self) -> dict[str, Any]:
        """Fence an already-running TLS bridge after host CA cutover.

        An old bridge can still complete an mTLS handshake against the old
        root until stopped, but it must not authorize another broker request.
        """
        current = self._manifest()
        if (current['ca']['generation'] != self.ca_generation or
                current['ca']['sha256'] != self.ca_sha256):
            raise SecretsError('revoked')
        return current

    @staticmethod
    def _ca_names(generation: int) -> tuple[str, str]:
        return (f'{CA_DIRECTORY}/ca-{generation}.key',
                f'{CA_DIRECTORY}/ca-{generation}.pem')

    @staticmethod
    def _server_names(generation: int) -> tuple[str, str]:
        return (f'{SERVER_DIRECTORY}/server-{generation}.key',
                f'{SERVER_DIRECTORY}/server-{generation}.pem')

    def _certificate_for_active_ca(self):
        x509, _, _, _, _, _ = _x509()
        _, cert_path = self._ca_names(self.ca_generation)
        try:
            return x509.load_pem_x509_certificate(self._read(cert_path))
        except ValueError:
            raise SecretsError('invalid_capability') from None

    def _load_ca(self):
        self._assert_current_ca()
        x509, _, serialization, _, _, _ = _x509()
        key_path, cert_path = self._ca_names(self.ca_generation)
        try:
            key = serialization.load_pem_private_key(
                self._read(key_path), password=None)
            cert = x509.load_pem_x509_certificate(self._read(cert_path))
            if (_key_fingerprint(key.public_key()) !=
                    _key_fingerprint(cert.public_key()) or
                    hashlib.sha256(_certificate_der(cert)).hexdigest() !=
                    self.ca_sha256):
                raise ValueError('CA identity differs from active manifest')
            return key, cert
        except (ValueError, TypeError):
            raise SecretsError('invalid_capability') from None

    def _write_selected_manifest(self, state: dict[str, Any]) -> None:
        """Single atomic trust+server selection; no split selection files."""
        data = codec.dumps(authority_model.validate(state))
        tmp = self.root / ('.authority-' + secrets.token_hex(12) + '.tmp')
        try:
            write_new(tmp, data)
            self._fsync_file(tmp)
            os.replace(tmp, self.root / MANIFEST)
            self._fsync_dir(self.root)
        except OSError:
            raise SecretsError('audit_failed') from None
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _fsync_file(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _stage_pair(self, first: Path, first_data: bytes,
                    second: Path, second_data: bytes) -> None:
        """Stage immutable credential material before pointer publication."""
        write_new(first, first_data)
        self._fsync_file(first)
        write_new(second, second_data)
        self._fsync_file(second)
        self._fsync_dir(first.parent)
        if second.parent != first.parent:
            self._fsync_dir(second.parent)

    def _next_generation(self, directory: str, label: str,
                         previous: int, maximum: int) -> int:
        # Never reuse a partially written, non-selected generation.
        generation = previous + 1
        while generation <= maximum:
            prefix = self.root / directory / f'{label}-{generation}'
            if not (os.path.lexists(str(prefix) + '.key') or
                    os.path.lexists(str(prefix) + '.pem')):
                return generation
            generation += 1
        raise SecretsError('exhausted')

    def rotate_ca(self, *, now: int | None = None) -> dict[str, Any]:
        """Fail-closed root rollover; all enrolled identities are revoked.

        There is deliberately no dual-anchor overlap. The host operator must
        stop/restart bound sessions, redistribute the public CA and explicitly
        re-enroll guests. No VM has been enrolled in this pre-deployment format.

        Commit order matters: stage private CA/server material, revoke every
        client in the registry, then atomically activate the new trust pointer.
        A crash at any stage cannot authorize an old client under a new root.
        """
        stamp = _stamp(now)
        _, _, _, ec, _, _ = _x509()
        with self._locked():
            current = self._assert_current_ca()
            ca_number = self._next_generation(
                CA_DIRECTORY, 'ca', self.ca_generation, MAX_CA_GENERATIONS)
            server_number = self._next_generation(
                SERVER_DIRECTORY, 'server',
                current['server']['generation'], MAX_SERVER_GENERATIONS)
            ca_key, ca = create_ca(now=stamp, days=CA_DAYS)
            leaf_key = ec.generate_private_key(ec.SECP256R1())
            leaf_cert = _leaf_certificate(
                ca_key, ca, leaf_key.public_key(), name='localhost',
                now=stamp, days=SERVER_DAYS, server=True)
            root_hash = hashlib.sha256(_certificate_der(ca)).hexdigest()
            selection = authority_model.activate_ca(
                current, ca_generation=ca_number, ca_sha256=root_hash,
                server_generation=server_number)
            ca_key_name, ca_cert_name = self._ca_names(ca_number)
            leaf_key_name, leaf_cert_name = self._server_names(server_number)
            with self._audit('identity_ca_rotate_intent', 'issuer', stamp,
                             root_hash):
                self._stage_pair(self.root / ca_key_name, _key_pem(ca_key),
                                 self.root / ca_cert_name, _certificate_pem(ca))
                self._stage_pair(self.root / leaf_key_name, _key_pem(leaf_key),
                                 self.root / leaf_cert_name,
                                 _certificate_pem(leaf_cert))
                # Retire the entire enrollment set before trust activation.
                # A partial transaction fails closed; never restore old rows.
                self._update({'schema': registry_model.SCHEMA, 'subjects': {}})
                self._write_selected_manifest(selection)
            return {'ca_generation': ca_number, 'ca_sha256': root_hash,
                    'server_generation': server_number,
                    'enrollments_revoked': True, 'restart_required': True}

    def enroll(self, *, subject: str, csr: bytes, approve_fingerprint: str,
               replace: bool = False, now: int | None = None) -> dict[str, Any]:
        """Host operator attests CSR provenance out of band; never trust CSR CN."""
        _subject(subject)
        request, fp = _read_csr(csr)
        if type(approve_fingerprint) is not str or fp != approve_fingerprint:
            raise SecretsError('denied', detail='CSR key fingerprint not confirmed')
        stamp = _stamp(now)
        with self._locked():
            state = self._registry()
            ca_key, ca_cert = self._load_ca()
            if stamp + CLIENT_DAYS * 86400 >= int(ca_cert.not_valid_after_utc.timestamp()):
                raise SecretsError('expired', detail='host CA requires renewal')
            cert = _leaf_certificate(ca_key, ca_cert, request.public_key(),
                                     name='aivm-guest', now=stamp,
                                     days=CLIENT_DAYS, server=False)
            der = _certificate_der(cert)
            thumb = certificate_thumbprint(der)
            state = registry_model.enroll(
                state, issuer=self.issuer, audience=self.audience,
                subject=subject, thumbprint=thumb,
                not_after=int(cert.not_valid_after_utc.timestamp()),
                replace=replace,
            )
            record = state['subjects'][subject]
            path = self.root / 'clients' / (hashlib.sha256(der).hexdigest() + '.pem')
            with self._audit('identity_enroll_intent', subject, stamp,
                             hashlib.sha256(der).hexdigest()):
                write_new(path, _certificate_pem(cert))
                self._update(state)
            return {'subject': subject, 'epoch': record['epoch'],
                    'certificate': str(path), 'certificate_sha256': thumb,
                    'not_after': record['not_after']}

    def renew_client(self, *, subject: str, csr: bytes,
                     approve_fingerprint: str, expected_epoch: int,
                     expected_thumbprint: str, require_new_key: bool = False,
                     now: int | None = None) -> dict[str, Any]:
        """Renew one client certificate with an epoch+thumbprint CAS.

        A current enrollment, trusted CSR transport and explicit key-fingerprint
        confirmation are prerequisites. The new certificate invalidates old
        JWTs/peer certificates immediately via the enrollment registry. This
        does NOT rotate a reused guest key or attest where it was generated.
        """
        _subject(subject)
        request, fp = _read_csr(csr)
        if type(approve_fingerprint) is not str or fp != approve_fingerprint:
            raise SecretsError('denied', detail='CSR key fingerprint not confirmed')
        if type(require_new_key) is not bool:
            raise SecretsError('invalid_capability')
        stamp = _stamp(now)
        with self._locked():
            state = self._registry()
            # Check state before performing expensive crypto and again in the
            # pure renewal transition below, under the same host lock.
            row = state['subjects'].get(subject)
            if (type(expected_epoch) is not int or
                    type(expected_thumbprint) is not str):
                raise SecretsError('invalid_capability')
            if (row is None or not row['active'] or
                    row['epoch'] != expected_epoch or
                    row['certificate_sha256'] != expected_thumbprint):
                raise SecretsError('revoked')
            if require_new_key:
                # The host validates that a different key is being enrolled,
                # not just that the CA issued a different certificate.
                from .garrett.key_rotation import authorize_key_rotation
                enrolled_cert = self._current_client_certificate(row)
                authorize_key_rotation(
                    expected_epoch=expected_epoch, actual_epoch=row['epoch'],
                    expected_thumbprint=expected_thumbprint,
                    actual_thumbprint=row['certificate_sha256'],
                    enrolled_key_fingerprint=_key_fingerprint(
                        enrolled_cert.public_key()),
                    candidate_key_fingerprint=fp,
                )
            ca_key, ca_cert = self._load_ca()
            if stamp + CLIENT_DAYS * 86400 >= int(ca_cert.not_valid_after_utc.timestamp()):
                raise SecretsError('expired', detail='host CA requires renewal')
            cert = _leaf_certificate(ca_key, ca_cert, request.public_key(),
                                     name='aivm-guest', now=stamp,
                                     days=CLIENT_DAYS, server=False)
            der = _certificate_der(cert)
            thumb = certificate_thumbprint(der)
            updated = registry_model.renew(
                state, issuer=self.issuer, audience=self.audience,
                subject=subject, expected_epoch=expected_epoch,
                expected_thumbprint=expected_thumbprint,
                thumbprint=thumb, not_after=int(cert.not_valid_after_utc.timestamp()),
                now=stamp)
            record = updated['subjects'][subject]
            path = self.root / 'clients' / (hashlib.sha256(der).hexdigest() + '.pem')
            with self._audit('identity_rekey_intent' if require_new_key
                             else 'identity_renew_intent', subject, stamp,
                             hashlib.sha256(der).hexdigest()):
                write_new(path, _certificate_pem(cert))
                self._update(updated)
            return {'subject': subject, 'epoch': record['epoch'],
                    'certificate': str(path), 'certificate_sha256': thumb,
                    'not_after': record['not_after']}

    def revoke(self, subject: str, *, now: int | None = None) -> dict[str, Any]:
        _subject(subject)
        stamp = _stamp(now)
        with self._locked():
            state = self._registry()
            record = state['subjects'].get(subject)
            if record is None:
                raise SecretsError('denied', detail='unknown identity')
            if record['active']:
                state = registry_model.revoke(
                    state, issuer=self.issuer,
                    audience=self.audience, subject=subject,
                )
                with self._audit('identity_revoke_intent', subject, stamp,
                                 record['certificate_sha256']):
                    self._update(state)
                record = state['subjects'][subject]
            return {'subject': subject, 'epoch': record['epoch'], 'active': False}

    def revoke_if_current(self, *, subject: str, expected_epoch: int,
                          expected_thumbprint: str,
                          now: int | None = None) -> dict[str, Any]:
        """Rollback compensation that cannot revoke another writer's grant.

        This is deliberately distinct from the operator's unconditional
        `revoke`: the caller may be handling a delayed installation failure.
        """
        _subject(subject)
        stamp = _stamp(now)
        with self._locked():
            state, revoked = registry_model.revoke_if_current(
                self._registry(), issuer=self.issuer,
                audience=self.audience, subject=subject,
                expected_epoch=expected_epoch,
                expected_thumbprint=expected_thumbprint,
            )
            if revoked:
                with self._audit('identity_revoke_intent', subject, stamp,
                                 expected_thumbprint):
                    self._update(state)
            current = state['subjects'].get(subject)
            return {'subject': subject, 'revoked': revoked,
                    'epoch': current['epoch'] if current is not None else None}

    def status(self) -> dict[str, Any]:
        selection = self._assert_current_ca()
        return {'issuer': self.issuer, 'audience': self.audience,
                'ca_sha256': self.ca_sha256,
                'ca_generation': self.ca_generation,
                'server_generation': selection['server']['generation'],
                'subjects': self._registry()['subjects']}

    def _current_client_certificate(self, row: dict[str, Any]):
        """Read the current leaf using its registry-validated thumbprint."""
        import base64
        thumb = row['certificate_sha256']
        try:
            digest = base64.urlsafe_b64decode(thumb + '=' * (-len(thumb) % 4))
            if len(digest) != 32:
                raise ValueError('invalid thumbprint')
            cert = _x509()[0].load_pem_x509_certificate(
                self._read('clients/' + digest.hex() + '.pem'))
            if certificate_thumbprint(_certificate_der(cert)) != thumb:
                raise ValueError('certificate/registry mismatch')
            return cert
        except (ValueError, OSError, TypeError, SecretsError):
            raise SecretsError('invalid_capability') from None

    def rotate_client_key(self, *, subject: str, csr: bytes,
                          approve_fingerprint: str, expected_epoch: int,
                          expected_thumbprint: str,
                          now: int | None = None) -> dict[str, Any]:
        """Require a fresh public key under the same epoch-CAS renewal gate."""
        return self.renew_client(
            subject=subject, csr=csr,
            approve_fingerprint=approve_fingerprint,
            expected_epoch=expected_epoch,
            expected_thumbprint=expected_thumbprint,
            require_new_key=True, now=now,
        )

    def public_client(self, subject: str) -> dict[str, Any]:
        """Return ONLY currently active public chain material for delivery.

        This is exposed as an isolated host-service command, so AIVM never
        loads the private authority implementation into its own process.
        """
        _subject(subject)
        with self._locked():
            row = self._registry()['subjects'].get(subject)
            stamp = _stamp()
            if row is None or not row['active'] or stamp >= row['not_after']:
                raise SecretsError('revoked')
            thumb = row['certificate_sha256']
            import base64
            try:
                digest = base64.urlsafe_b64decode(thumb + '=' * (-len(thumb) % 4))
                if len(digest) != 32:
                    raise ValueError('invalid certificate thumbprint')
                cert_pem = self._read('clients/' + digest.hex() + '.pem')
                cert = _x509()[0].load_pem_x509_certificate(cert_pem)
                if certificate_thumbprint(_certificate_der(cert)) != thumb:
                    raise ValueError('client certificate differs from registry')
            except (ValueError, OSError, TypeError, SecretsError):
                raise SecretsError('invalid_capability') from None
            self._assert_current_ca()
            _, ca_file = self._ca_names(self.ca_generation)
            ca_pem = self._read(ca_file)
        return {
            'subject': subject, 'certificate_sha256': thumb,
            'certificate_pem_b64': base64.b64encode(cert_pem).decode('ascii'),
            'ca_pem_b64': base64.b64encode(ca_pem).decode('ascii'),
            'epoch': row['epoch'], 'not_after': row['not_after'],
        }

    def expectation_for_peer(self, der: bytes, now: int) -> IdentityExpectation:
        """Reload current enrollment on EACH request; reject stale certs.

        Call only with a real, CA-validated mTLS peer cert DER. This is not a
        certificate validator, and cannot authenticate caller-supplied bytes.
        """
        stamp = _stamp(now)
        self._assert_current_ca()
        thumb = certificate_thumbprint(der)
        state = self._registry()
        return registry_model.expectation(
            state, issuer=self.issuer, audience=self.audience,
            thumbprint=thumb, now=stamp,
        )

    def _keyring(self) -> dict[str, Any]:
        """Exactly one canonical keyring format; pre-deployment migration is not supported."""
        self._assert_current_ca()
        state = codec.loads(self._read(KEYRING, 4096),
                            limit=4096, code='invalid_capability')
        state = grammar.exact_keys(state, frozenset({
            'schema', 'active', 'enabled', 'next_number',
        }), code='invalid_capability')
        if state['schema'] != 1 or type(state['schema']) is not int:
            raise SecretsError('invalid_capability')
        n = grammar.integer(state['next_number'], 2, 100000,
                            code='invalid_capability')
        enabled = state['enabled']
        if type(enabled) is not list or not 1 <= len(enabled) <= MAX_ISSUER_KEYS:
            raise SecretsError('invalid_capability')
        seen = set()
        for kid in enabled:
            if type(kid) is not str or kid in seen or not kid.startswith('local-'):
                raise SecretsError('invalid_capability')
            grammar.token(kid, grammar.ALNUM, grammar.ALNUM + '-_', 32,
                          code='invalid_capability')
            seen.add(kid)
        if state['active'] not in seen:
            raise SecretsError('invalid_capability')
        return {'schema': 1, 'active': state['active'], 'enabled': enabled,
                'next_number': n}

    def _keys_for(self, kid: str) -> tuple[bytes, bytes, bytes]:
        # Values never become path segments without validation against the
        # host-owned, canonical keyring.
        grammar.token(kid, grammar.ALNUM, grammar.ALNUM + '-_', 32,
                      code='invalid_capability')
        prefix = f'{KEY_DIRECTORY}/{kid}'
        return (self._read(prefix + '.key'), self._read(prefix + '.pub'),
                self._read(prefix + '.aes256'))

    def _commit_keyring(self, state: dict[str, Any]) -> None:
        data = codec.dumps(state)
        tmp = self.root / ('.keyring-' + secrets.token_hex(12) + '.tmp')
        try:
            write_new(tmp, data)
            os.replace(tmp, self.root / KEYRING)
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    def rotate_issuer(self) -> dict[str, Any]:
        """Rotate JWT signing/AEAD keys; preserve old verification until retired.

        Fresh token issuance switches atomically after all key files are
        durable. Running bridges re-read the active keyring per request.
        """
        Private, _, _ = _token_crypto()
        _, _, serialization, _, _, _ = _x509()
        with self._locked():
            state = self._keyring()
            if len(state['enabled']) >= MAX_ISSUER_KEYS:
                raise SecretsError('exhausted')
            kid = f'local-{state["next_number"]}'
            folder = self.root / KEY_DIRECTORY
            if not folder.exists():
                private_directory(folder, self.untrusted)
            else:
                private_directory(folder, self.untrusted)
            signer = Private.generate()
            prefix = folder / kid
            with self._audit('identity_key_rotate_intent', 'issuer', _stamp(),
                             hashlib.sha256(kid.encode()).hexdigest()):
                write_new(Path(str(prefix) + '.key'), _key_pem(signer))
                write_new(Path(str(prefix) + '.pub'), signer.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))
                write_new(Path(str(prefix) + '.aes256'), secrets.token_bytes(32))
                state['enabled'].append(kid)
                state['active'] = kid
                state['next_number'] += 1
                self._commit_keyring(state)
            return {'active': kid, 'enabled': state['enabled']}

    def retire_issuer(self, kid: str) -> dict[str, Any]:
        """Stop accepting an old issuer key on the next presentation."""
        with self._locked():
            state = self._keyring()
            if kid == state['active'] or kid not in state['enabled']:
                raise SecretsError('denied')
            with self._audit('identity_key_retire_intent', 'issuer', _stamp(),
                             hashlib.sha256(kid.encode()).hexdigest()):
                state['enabled'].remove(kid)
                self._commit_keyring(state)
            return {'active': state['active'], 'enabled': state['enabled']}

    def issue(self, *, subject: str, broker_capability: str,
              output: Path, lifetime: int = 900,
              now: int | None = None) -> dict[str, Any]:
        """Issue an encrypted token for an already-enrolled host principal.

        Only a trusted host operator with access to the original `aivs1`
        capability may invoke this method. `output` is a protected HOST file;
        copying it to the guest is a separate explicit operation.
        """
        _subject(subject)
        stamp = _stamp(now)
        if (type(lifetime) is not int or
                not 1 <= lifetime <= MAX_IDENTITY_LIFETIME):
            raise SecretsError('invalid_capability')
        with self._locked():
            self._assert_current_ca()
            state = self._registry()
            row = state['subjects'].get(subject)
            if row is None or not row['active'] or stamp >= row['not_after']:
                raise SecretsError('invalid_capability')
            exp = min(stamp + lifetime, row['not_after'])
            if exp <= stamp:
                raise SecretsError('invalid_capability')
            claims = prepare_issue(
                state, issuer=self.issuer, audience=self.audience,
                subject=subject, token_id=secrets.token_hex(16),
                now=stamp, lifetime=lifetime,
            ).claims
            _, _, serialization, _, _, _ = _x509()
            active_key = self._keyring()['active']
            private_pem, _, aead_bytes = self._keys_for(active_key)
            try:
                key = serialization.load_pem_private_key(private_pem, password=None)
            except (ValueError, TypeError):
                raise SecretsError('invalid_capability') from None
            issuer = IdentityTokenIssuer(key, aead_bytes, key_id=active_key)
            sealed = issuer.issue(claims, broker_capability)
            output = Path(output).expanduser().absolute()
            private_directory(output.parent, self.untrusted)
            with self._audit('identity_token_issue_intent', subject, stamp,
                             hashlib.sha256(claims.token_id.encode()).hexdigest()):
                write_new(output, sealed.encode('ascii'))
            return {'subject': subject, 'expires_at': exp, 'output': str(output),
                    'certificate_sha256': row['certificate_sha256']}

    def token_verifier(self, expected: IdentityExpectation):
        """Return a revocation-aware verifier that reads live key selection."""
        return _AuthorityTokenVerifier(self, expected)

    def renew_server(self, *, now: int | None = None) -> dict[str, Any]:
        """Stage an immutable leaf under the current CA and switch one pointer.

        A running TLS context keeps the previous leaf until restarted. A root
        cutover, in contrast, fences *every* old authority process on its next
        broker request.
        """
        stamp = _stamp(now)
        _, _, _, ec, _, _ = _x509()
        with self._locked():
            current = self._assert_current_ca()
            generation = self._next_generation(
                SERVER_DIRECTORY, 'server', current['server']['generation'],
                MAX_SERVER_GENERATIONS)
            ca_key, ca_cert = self._load_ca()
            if stamp + SERVER_DAYS * 86400 >= int(ca_cert.not_valid_after_utc.timestamp()):
                raise SecretsError('expired', detail='host CA requires rotation')
            private = ec.generate_private_key(ec.SECP256R1())
            cert = _leaf_certificate(ca_key, ca_cert, private.public_key(),
                                     name='localhost', now=stamp,
                                     days=SERVER_DAYS, server=True)
            selection = authority_model.activate_server(
                current, server_generation=generation)
            key_name, cert_name = self._server_names(generation)
            with self._audit('identity_server_renew_intent', 'localhost', stamp,
                             hashlib.sha256(_certificate_der(cert)).hexdigest()):
                self._stage_pair(self.root / key_name, _key_pem(private),
                                 self.root / cert_name, _certificate_pem(cert))
                self._write_selected_manifest(selection)
            return {'generation': generation,
                    'certificate_sha256': certificate_thumbprint(_certificate_der(cert)),
                    'not_after': int(cert.not_valid_after_utc.timestamp()),
                    'restart_required': True}

    def tls_paths(self) -> tuple[Path, Path, Path]:
        selection = self._assert_current_ca()
        key, cert = self._server_names(selection['server']['generation'])
        _, ca = self._ca_names(self.ca_generation)
        for name in (cert, key, ca):
            self._read(name)
        return (self.root / cert, self.root / key, self.root / ca)


class _AuthorityTokenVerifier:
    """Key rotation/retirement takes effect at the next mTLS request.

    The untrusted `kid` merely selects one of the host's allowlisted keys;
    the matching verifier validates the *whole* JWT signature and AEAD.
    """

    def __init__(self, authority: IdentityAuthority,
                 expected: IdentityExpectation):
        self.authority = authority
        self.expected = expected

    def open(self, token: str, *, authenticated_peer_der: bytes, now: int,
             expected: IdentityExpectation | None = None):
        from .token import IdentityTokenVerifier, _trusted_kid
        _, _, serialization, _, _, _ = _x509()
        try:
            kid = _trusted_kid(token)
            if kid not in self.authority._keyring()['enabled']:
                raise SecretsError('invalid_capability')
            _, public_pem, aead = self.authority._keys_for(kid)
            public = serialization.load_pem_public_key(public_pem)
            return IdentityTokenVerifier(public, aead, key_id=kid,
                expected=self.expected).open(token,
                authenticated_peer_der=authenticated_peer_der, now=now,
                expected=expected)
        except Exception:
            raise SecretsError('invalid_capability') from None
