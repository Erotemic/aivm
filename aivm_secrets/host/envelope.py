"""Versioned, AEAD-sealed capabilities inspired by Garrett's token broker.

The local ``aivs1`` profile uses one ephemeral AES-256-GCM key per session.
The guest carries ciphertext; the provider credential and the key stay on the
host. This is not JWT, JOSE, mTLS or RFC 8705 -- see the design document for
the interoperable profile planned for remote deployment.

Because the key lives only in this process, a restarted broker cannot open an
old capability (RESTART-01). Cryptographic primitives come from the
``cryptography`` library; none is implemented here.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from ..errors import SecretsError
from ..kernel import codec, grammar
from ..kernel.model import Claims
from ..kernel.wire import MAX_CAPABILITY

PREFIX = 'aivs1.'
AAD = b'aivm-secrets/local-session/service-neutral/v1'


@dataclass(frozen=True)
class OpenedCapability:
    claims: Claims
    credential: str = field(repr=False)


class EnvelopeCodec:
    def __init__(self, key: bytes | None = None):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise SecretsError('missing_crypto') from None
        self._aead = AESGCM(os.urandom(32) if key is None else key)

    def seal(self, claims: Claims, credential: str) -> str:
        grammar.credential(credential)
        nonce = os.urandom(12)
        payload = codec.dumps(
            {'claims': claims.to_dict(), 'credential': credential}
        )
        sealed = nonce + self._aead.encrypt(nonce, payload, AAD)
        encoded = base64.urlsafe_b64encode(sealed).rstrip(b'=')
        return PREFIX + encoded.decode('ascii')

    def open(self, capability: str) -> OpenedCapability:
        try:
            if type(capability) is not str:
                raise ValueError('not text')
            if not capability.startswith(PREFIX):
                raise ValueError('bad version')
            if len(capability) > MAX_CAPABILITY:
                raise ValueError('too long')
            encoded = capability[len(PREFIX) :].encode('ascii')
            sealed = base64.b64decode(
                encoded + b'=' * (-len(encoded) % 4),
                altchars=b'-_',
                validate=True,
            )
            canonical = base64.urlsafe_b64encode(sealed).rstrip(b'=')
            if canonical != encoded or len(sealed) < 29:
                raise ValueError('non-canonical')
            data = self._aead.decrypt(sealed[:12], sealed[12:], AAD)
            payload = grammar.exact_keys(
                codec.loads(data), frozenset({'claims', 'credential'})
            )
            return OpenedCapability(
                Claims.parse(payload['claims']),
                grammar.credential(payload['credential']),
            )
        except Exception:
            # Cryptographic, schema, and decoding failures have one public code.
            raise SecretsError('invalid_capability') from None
