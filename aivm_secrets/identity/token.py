"""Experimental locally issued signed/encrypted certificate-bound JWT.

The JWT has an Ed25519 signature and a private AES-GCM claim containing an
existing ``aivs1`` broker capability. The actual provider credential remains
inside the latter, encrypted under the broker's own key. The JWT does NOT
confer permission to call a provider without the existing reference monitor.

This is a deliberately narrow P4a token profile, not full Garrett-style OAuth,
interoperable token exchange, portable key custody or durable issuance. All
signature, encryption and certificate hashing primitives are from established
libraries, not handwritten algorithms. Never use this as an unprotected bearer
credential; the TLS bridge MUST verify the actual client certificate.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

from ..errors import SecretsError
from ..primitives import codec, grammar
from .model import (IdentityClaims, IdentityExpectation)
from .garrett.protocol import present

TOKEN_TYPE = 'aivm-bound+jwt'
ALGORITHM = 'EdDSA'
MAX_JWT_BYTES = 65536
MAX_EMBEDDED = 16384
AAD_PREFIX = b'aivm-secrets/identity/aes-gcm/v1\x00'


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SecretsError('missing_crypto') from None
    return Ed25519PrivateKey, Ed25519PublicKey, AESGCM


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _decode(text: Any, limit: int) -> bytes:
    try:
        if type(text) is not str or not text or len(text) > limit:
            raise ValueError('size')
        # Verify exact RFC 4648 canonical unpadded base64url spelling.
        if any(char not in grammar.ALNUM + '-_' for char in text):
            raise ValueError('alphabet')
        raw = base64.b64decode(text + '=' * (-len(text) % 4),
                               altchars=b'-_', validate=True)
        if _encode(raw) != text:
            raise ValueError('noncanonical')
        return raw
    except (ValueError, UnicodeError):
        raise SecretsError('invalid_capability') from None


def certificate_thumbprint(der: bytes) -> str:
    """RFC 8705 `cnf.x5t#S256`: base64url(SHA256(DER certificate))."""
    if type(der) is not bytes or not 1 <= len(der) <= 65536:
        raise SecretsError('invalid_capability')
    return _encode(hashlib.sha256(der).digest())


def _public_payload(claims: IdentityClaims) -> dict[str, Any]:
    # Reparse, including bounds, even when callers construct a dataclass.
    return IdentityClaims.parse(claims.to_dict()).to_dict()


@dataclass(frozen=True)
class OpenedIdentityToken:
    claims: IdentityClaims
    broker_capability: str = field(repr=False)


class IdentityTokenIssuer:
    """Host-held private signing and AEAD keys; explicit identity inputs."""

    def __init__(self, signing_key: Any, encryption_key: bytes, *, key_id: str):
        Private, _, AESGCM = _crypto()
        if not isinstance(signing_key, Private):
            raise SecretsError('invalid_capability')
        if type(encryption_key) is not bytes or len(encryption_key) != 32:
            raise SecretsError('invalid_capability')
        self.key_id = grammar.token(key_id, grammar.ALNUM,
                                    grammar.ALNUM + '-_', 32,
                                    code='invalid_capability')
        self._signer = signing_key
        self._sealer = AESGCM(encryption_key)

    def issue(self, claims: IdentityClaims, broker_capability: str) -> str:
        """Mint one token. Claims must follow trusted certificate enrollment."""
        try:
            public = _public_payload(claims)
            if (type(broker_capability) is not str or
                    not broker_capability.startswith('aivs1.') or
                    not 1 <= len(broker_capability) <= MAX_EMBEDDED):
                raise ValueError('not a bounded broker capability')
            nonce = os.urandom(12)
            # Signed public claims are also the AEAD associated data, to bind
            # any decrypted inner capability to this particular identity.
            ciphertext = nonce + self._sealer.encrypt(
                nonce, broker_capability.encode('ascii'),
                AAD_PREFIX + codec.dumps(public),
            )
            payload = {**public, 'enc': _encode(ciphertext)}
            header = {'alg': ALGORITHM, 'typ': TOKEN_TYPE, 'kid': self.key_id}
            body = _encode(codec.dumps(header)) + '.' + _encode(codec.dumps(payload))
            signature = self._signer.sign(body.encode('ascii'))
            token = body + '.' + _encode(signature)
            if len(token) > MAX_JWT_BYTES:
                raise ValueError('token too large')
            return token
        except (ValueError, UnicodeError, TypeError, SecretsError):
            raise SecretsError('invalid_capability') from None


class IdentityTokenVerifier:
    """Verify Ed25519 signature, mTLS thumbprint, epoch and AEAD before use."""

    def __init__(self, signing_public_key: Any, encryption_key: bytes,
                 *, key_id: str, expected: IdentityExpectation):
        _, Public, AESGCM = _crypto()
        if not isinstance(signing_public_key, Public):
            raise SecretsError('invalid_capability')
        if type(encryption_key) is not bytes or len(encryption_key) != 32:
            raise SecretsError('invalid_capability')
        self.key_id = grammar.token(key_id, grammar.ALNUM,
                                    grammar.ALNUM + '-_', 32,
                                    code='invalid_capability')
        self._verifier = signing_public_key
        self._sealer = AESGCM(encryption_key)
        self.expected = IdentityExpectation.parse(expected.to_dict())

    def open(self, token: str, *, authenticated_peer_der: bytes,
             now: int, expected: IdentityExpectation | None = None
             ) -> OpenedIdentityToken:
        """Only a trusted caller may supply a certificate from verified mTLS.

        This method does NOT validate certificate chains. The host TLS bridge
        must supply bytes obtained from getpeercert(binary_form=True) after a
        successful CERT_REQUIRED handshake. Never accept these bytes from JSON.
        """
        try:
            if type(token) is not str or len(token) > MAX_JWT_BYTES:
                raise ValueError('bad token')
            chunks = token.split('.')
            if len(chunks) != 3:
                raise ValueError('parts')
            h, p, sig = (_decode(part, MAX_JWT_BYTES) for part in chunks)
            header = grammar.exact_keys(codec.loads(h),
                                        frozenset({'alg', 'typ', 'kid'}),
                                        code='invalid_capability')
            if header != {'alg': ALGORITHM, 'typ': TOKEN_TYPE, 'kid': self.key_id}:
                raise ValueError('header')
            if codec.dumps(header) != h:
                raise ValueError('header canonicalization')
            self._verifier.verify(sig, (chunks[0] + '.' + chunks[1]).encode('ascii'))
            parsed = grammar.exact_keys(codec.loads(p), frozenset({
                'iss', 'aud', 'sub', 'jti', 'iat', 'exp', 'epoch', 'cnf', 'enc',
            }), code='invalid_capability')
            if codec.dumps(parsed) != p:
                raise ValueError('payload canonicalization')
            ciphertext_text = parsed.pop('enc')
            claims = IdentityClaims.parse(parsed)
            # A host enrollment registry can supply a fresh expectation for
            # *each* request. It is not supplied by the guest or a JWT claim.
            expectation = self.expected if expected is None else expected
            present(claims, expectation,
                    certificate_thumbprint(authenticated_peer_der), now=now)
            encrypted = _decode(ciphertext_text, MAX_JWT_BYTES)
            if len(encrypted) < 29:
                raise ValueError('ciphertext size')
            inner = self._sealer.decrypt(
                encrypted[:12], encrypted[12:],
                AAD_PREFIX + codec.dumps(_public_payload(claims)),
            ).decode('ascii')
            if (not inner.startswith('aivs1.') or
                    len(inner) > MAX_EMBEDDED):
                raise ValueError('inner capability')
            return OpenedIdentityToken(claims, inner)
        except Exception:
            # Rejects all signatures, bindings, crypto failures and decodes
            # with the same public response, without reflecting input bytes.
            raise SecretsError('invalid_capability') from None


def _trusted_kid(token: str) -> str:
    """Extract *only* a bounded key-selection hint from an untrusted JWT."""
    try:
        if type(token) is not str or len(token) > MAX_JWT_BYTES:
            raise ValueError('size')
        h, _, _ = token.split('.')
        header_bytes = _decode(h, 4096)
        header = grammar.exact_keys(codec.loads(header_bytes),
                                    frozenset({'alg', 'typ', 'kid'}),
                                    code='invalid_capability')
        if (codec.dumps(header) != header_bytes or header['alg'] != ALGORITHM
                or header['typ'] != TOKEN_TYPE):
            raise ValueError('header')
        return grammar.token(header['kid'], grammar.ALNUM,
                             grammar.ALNUM + '-_', 32,
                             code='invalid_capability')
    except Exception:
        raise SecretsError('invalid_capability') from None
