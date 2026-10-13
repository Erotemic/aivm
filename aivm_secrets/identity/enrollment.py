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
from .model import IdentityExpectation, MAX_EPOCH, MAX_IDENTITY_LIFETIME
from . import registry_model
from .garrett.protocol import prepare_issue
from .token import (IdentityTokenIssuer, certificate_thumbprint,
                    _crypto as _token_crypto)

SCHEMA = 1
MAX_CSR_BYTES = 8192
MAX_REGISTRY_BYTES = 131072
MAX_SUBJECTS = 128
CA_DAYS = 365
SERVER_DAYS = 30
CLIENT_DAYS = 7
MANIFEST = 'authority.json'
REGISTRY = 'enrollments.json'
CA_CERT = 'ca.pem'
CA_KEY = 'ca.key'
SERVER_CERT = 'server.pem'
SERVER_KEY = 'server.key'
JWT_KEY = 'issuer.key'
JWT_PUBLIC = 'issuer.pub'
AEAD_KEY = 'issuer.aes256'
LOCK = '.enrollment.lock'
KEYRING = 'issuer-keyring.json'
KEY_DIRECTORY = 'issuer-keys'
MAX_ISSUER_KEYS = 8
SERVER_SELECTION = 'server-selection.json'
SERVER_DIRECTORY = 'server-generations'
MAX_SERVER_GENERATIONS = 64


def _x509():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        raise SecretsError('missing_crypto') from None
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


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


def _utc(value: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(value, dt.timezone.utc)


def _key_pem(key: Any) -> bytes:
    _, _, serialization, _, _, _ = _x509()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _certificate_pem(cert: Any) -> bytes:
    _, _, serialization, _, _, _ = _x509()
    return cert.public_bytes(serialization.Encoding.PEM)


def _certificate_der(cert: Any) -> bytes:
    _, _, serialization, _, _, _ = _x509()
    return cert.public_bytes(serialization.Encoding.DER)


def _key_fingerprint(public_key: Any) -> str:
    _, _, serialization, _, _, _ = _x509()
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()


def _name(value: str):
    x509, _, _, _, _, NameOID = _x509()
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value[:64])])


def _leaf_certificate(ca_key: Any, ca_cert: Any, public_key: Any,
                      *, name: str, now: int, days: int, server: bool):
    x509, hashes, _, _, ExtendedKeyUsageOID, _ = _x509()
    builder = (x509.CertificateBuilder()
        .subject_name(_name(name)).issuer_name(ca_cert.subject)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(_utc(now - 60))
        .not_valid_after(_utc(now + days * 86400))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_key.public_key()), False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server
            else ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), False))
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
    return builder.sign(ca_key, hashes.SHA256())


def _read_csr(data: bytes):
    x509, _, _, ec, _, _ = _x509()
    if type(data) is not bytes or not 1 <= len(data) <= MAX_CSR_BYTES:
        raise SecretsError('invalid_capability')
    try:
        request = x509.load_pem_x509_csr(data)
        key = request.public_key()
        if (not request.is_signature_valid or
                not isinstance(key, ec.EllipticCurvePublicKey) or
                not isinstance(key.curve, ec.SECP256R1) or
                len(request.extensions)):
            raise ValueError('unsupported or unauthenticated CSR')
        return request, _key_fingerprint(key)
    except (ValueError, TypeError, x509.DuplicateExtension):
        raise SecretsError('invalid_capability') from None


def inspect_csr(data: bytes) -> str:
    """A public P-256 CSR key fingerprint for out-of-band operator confirmation."""
    return _read_csr(data)[1]


def create_csr(*, private_key: Path, request_file: Path) -> str:
    """Generate an EXPORTABLE guest software key, and a CSR signed by it.

    Both destinations must not exist. This does not enroll the key and cannot
    attest the VM; the user must compare its fingerprint out of band.
    """
    x509, hashes, _, ec, _, _ = _x509()
    key = ec.generate_private_key(ec.SECP256R1())
    request = (x509.CertificateSigningRequestBuilder()
               .subject_name(_name('aivm-untrusted-request'))
               .sign(key, hashes.SHA256()))
    # Never return the secret; never overwrite an existing identity key.
    write_new(Path(private_key).expanduser().absolute(), _key_pem(key))
    write_new(Path(request_file).expanduser().absolute(),
              request.public_bytes(_x509()[2].Encoding.PEM))
    return _key_fingerprint(key.public_key())


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
        manifest = codec.loads(self._read(MANIFEST), code='invalid_capability')
        manifest = grammar.exact_keys(manifest, frozenset({
            'schema', 'issuer', 'audience', 'ca_sha256', 'created_at',
        }), code='invalid_capability')
        if type(manifest['schema']) is not int or manifest['schema'] != SCHEMA:
            raise SecretsError('invalid_capability')
        self.issuer = IdentityExpectation.parse({
            'issuer': manifest['issuer'], 'audience': manifest['audience'],
            'subject': 'init', 'epoch': 0,
        }).issuer
        self.audience = manifest['audience']
        IdentityExpectation.parse({
            'issuer': self.issuer, 'audience': self.audience,
            'subject': 'init', 'epoch': 0,
        })
        # Compare the immutable trust anchor before trusting the registry.
        x509, _, _, _, _, _ = _x509()
        try:
            ca = x509.load_pem_x509_certificate(self._read(CA_CERT))
        except ValueError:
            raise SecretsError('invalid_capability') from None
        self.ca_sha256 = hashlib.sha256(_certificate_der(ca)).hexdigest()
        if self.ca_sha256 != manifest['ca_sha256']:
            raise SecretsError('invalid_capability')

    @classmethod
    def initialize(cls, root: Path, *, issuer: str, audience: str,
                   untrusted: tuple[Path, ...] = (), now: int | None = None):
        """Create a new private authority; never adopt or reset an old one."""
        x509, hashes, _, ec, _, _ = _x509()
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
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = (x509.CertificateBuilder().subject_name(_name('aivm-secrets host CA'))
              .issuer_name(_name('aivm-secrets host CA'))
              .public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(_utc(stamp - 60))
              .not_valid_after(_utc(stamp + CA_DAYS * 86400))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                  ca_key.public_key()), False)
              .add_extension(x509.KeyUsage(
                  digital_signature=True, content_commitment=False,
                  key_encipherment=False, data_encipherment=False,
                  key_agreement=False, key_cert_sign=True, crl_sign=True,
                  encipher_only=False, decipher_only=False), True)
              .sign(ca_key, hashes.SHA256()))
        server_key = ec.generate_private_key(ec.SECP256R1())
        server = _leaf_certificate(ca_key, ca, server_key.public_key(),
                                   name='localhost', now=stamp,
                                   days=SERVER_DAYS, server=True)
        signer = Private.generate()
        entries = {
            CA_KEY: _key_pem(ca_key), CA_CERT: _certificate_pem(ca),
            SERVER_KEY: _key_pem(server_key), SERVER_CERT: _certificate_pem(server),
            JWT_KEY: _key_pem(signer),
            JWT_PUBLIC: signer.public_key().public_bytes(
                _x509()[2].Encoding.PEM,
                _x509()[2].PublicFormat.SubjectPublicKeyInfo),
            AEAD_KEY: secrets.token_bytes(32),
            MANIFEST: codec.dumps({
                'schema': SCHEMA, 'issuer': expected.issuer,
                'audience': expected.audience, 'created_at': stamp,
                'ca_sha256': hashlib.sha256(_certificate_der(ca)).hexdigest(),
            }),
            REGISTRY: codec.dumps({'schema': SCHEMA, 'subjects': {}}),
            LOCK: b'',
        }
        for name, data in entries.items():
            write_new(root / name, data)
        private_directory(root / 'clients', untrusted)
        private_directory(root / 'audit', untrusted)
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

    def _load_ca(self):
        x509, _, serialization, _, _, _ = _x509()
        try:
            key = serialization.load_pem_private_key(self._read(CA_KEY), password=None)
            cert = x509.load_pem_x509_certificate(self._read(CA_CERT))
            if _key_fingerprint(key.public_key()) != _key_fingerprint(cert.public_key()):
                raise ValueError('wrong CA key')
            return key, cert
        except (ValueError, TypeError):
            raise SecretsError('invalid_capability') from None

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
                     expected_thumbprint: str,
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
            with self._audit('identity_renew_intent', subject, stamp,
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

    def status(self) -> dict[str, Any]:
        return {'issuer': self.issuer, 'audience': self.audience,
                'ca_sha256': self.ca_sha256,
                'subjects': self._registry()['subjects']}

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
            ca_pem = self._read(CA_CERT)
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
        thumb = certificate_thumbprint(der)
        state = self._registry()
        return registry_model.expectation(
            state, issuer=self.issuer, audience=self.audience,
            thumbprint=thumb, now=stamp,
        )

    def _keyring(self) -> dict[str, Any]:
        """Legacy authorities start with `local-1` and no keyring file."""
        path = self.root / KEYRING
        if path.is_symlink():
            raise SecretsError('unsafe_file')
        if not path.exists():
            return {'schema': 1, 'active': 'local-1', 'enabled': ['local-1'],
                    'next_number': 2}
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
        if kid == 'local-1':
            return self._read(JWT_KEY), self._read(JWT_PUBLIC), self._read(AEAD_KEY)
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

    def _server_selection(self) -> tuple[str, str, int]:
        """Resolve one immutable TLS keypair from an atomic selection file.

        Authorities created before server-key rotation use server.pem/key.
        A malformed or missing selected generation fails closed, never falls
        back to legacy host identity or silently regenerates certificates.
        """
        path = self.root / SERVER_SELECTION
        if path.is_symlink():
            raise SecretsError('unsafe_file')
        if not path.exists():
            return SERVER_CERT, SERVER_KEY, 2
        value = codec.loads(self._read(SERVER_SELECTION, 4096),
                            limit=4096, code='invalid_capability')
        value = grammar.exact_keys(value, frozenset({
            'schema', 'active', 'next_number',
        }), code='invalid_capability')
        if (type(value['schema']) is not int or value['schema'] != 1 or
                type(value['active']) is not int or
                not 2 <= value['active'] <= MAX_SERVER_GENERATIONS or
                type(value['next_number']) is not int or
                value['next_number'] != value['active'] + 1):
            raise SecretsError('invalid_capability')
        prefix = f'{SERVER_DIRECTORY}/server-{value["active"]}'
        return prefix + '.pem', prefix + '.key', value['next_number']

    def _commit_server_selection(self, *, active: int) -> None:
        payload = codec.dumps({'schema': 1, 'active': active,
                               'next_number': active + 1})
        tmp = self.root / ('.server-' + secrets.token_hex(12) + '.tmp')
        try:
            write_new(tmp, payload)
            os.replace(tmp, self.root / SERVER_SELECTION)
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

    def renew_server(self, *, now: int | None = None) -> dict[str, Any]:
        """Rotate the host TLS leaf key and certificate under the existing CA.

        Each generation is immutable and installed before a single atomic
        selection commit. New bridge processes read that selection; running
        TLS contexts retain their previous leaf until explicitly restarted.
        """
        stamp = _stamp(now)
        x509, _, _, ec, _, _ = _x509()
        with self._locked():
            _, _, generation = self._server_selection()
            directory = self.root / SERVER_DIRECTORY
            private_directory(directory, self.untrusted)
            # An interrupted rotation can leave an unselected immutable
            # generation. Never overwrite it or strand future rotations.
            while generation <= MAX_SERVER_GENERATIONS:
                prefix = directory / f'server-{generation}'
                if not (os.path.lexists(str(prefix) + '.key') or
                        os.path.lexists(str(prefix) + '.pem')):
                    break
                generation += 1
            if generation > MAX_SERVER_GENERATIONS:
                raise SecretsError('exhausted')
            ca_key, ca_cert = self._load_ca()
            if stamp + SERVER_DAYS * 86400 >= int(ca_cert.not_valid_after_utc.timestamp()):
                raise SecretsError('expired', detail='host CA requires renewal')
            private = ec.generate_private_key(ec.SECP256R1())
            cert = _leaf_certificate(ca_key, ca_cert, private.public_key(),
                                     name='localhost', now=stamp,
                                     days=SERVER_DAYS, server=True)
            prefix = directory / f'server-{generation}'
            with self._audit('identity_server_renew_intent', 'localhost', stamp,
                             hashlib.sha256(_certificate_der(cert)).hexdigest()):
                write_new(Path(str(prefix) + '.key'), _key_pem(private))
                write_new(Path(str(prefix) + '.pem'), _certificate_pem(cert))
                self._commit_server_selection(active=generation)
            return {'generation': generation,
                    'certificate_sha256': certificate_thumbprint(_certificate_der(cert)),
                    'not_after': int(cert.not_valid_after_utc.timestamp()),
                    'restart_required': True}

    def tls_paths(self) -> tuple[Path, Path, Path]:
        # Read the selected immutable pair and CA; the authority tree is
        # host-owned and declared guest-writable roots are forbidden.
        cert, key, _ = self._server_selection()
        for name in (cert, key, CA_CERT):
            self._read(name)
        return (self.root / cert, self.root / key, self.root / CA_CERT)


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
