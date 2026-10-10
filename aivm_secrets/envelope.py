"""Versioned, AEAD-sealed capabilities inspired by Garrett's token broker.

This local prototype uses one ephemeral AES-256-GCM key per session, not JWT
or RFC 8705. The guest carries ciphertext; the upstream token stays host-side.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import asdict, dataclass, field

from .kernel import Claims, exact_keys
from .errors import SecretsError
from .wire import dumps, loads

PREFIX = 'aivs1.'
AAD = b'aivm-secrets/local-session/service-neutral/v1'
MAX_CAPABILITY = 32768


def validate_credential(value: str) -> str:
    if type(value) is not str or not re.fullmatch(r'[!-~]{16,4096}', value):
        raise SecretsError('credential_source')
    return value


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
        validate_credential(credential)
        nonce = os.urandom(12)
        payload = dumps({'claims': asdict(claims), 'credential': credential})
        sealed = nonce + self._aead.encrypt(nonce, payload, AAD)
        return PREFIX + base64.urlsafe_b64encode(sealed).rstrip(b'=').decode('ascii')

    def open(self, capability: str) -> OpenedCapability:
        try:
            if type(capability) is not str or not capability.startswith(PREFIX):
                raise ValueError('bad version')
            if len(capability) > MAX_CAPABILITY:
                raise ValueError('too long')
            encoded = capability[len(PREFIX):].encode('ascii')
            sealed = base64.b64decode(encoded + b'=' * (-len(encoded) % 4),
                                      altchars=b'-_', validate=True)
            if base64.urlsafe_b64encode(sealed).rstrip(b'=') != encoded or len(sealed) < 29:
                raise ValueError('non-canonical')
            data = self._aead.decrypt(sealed[:12], sealed[12:], AAD)
            payload = exact_keys(loads(data), {'claims', 'credential'})
            return OpenedCapability(Claims.parse(payload['claims']),
                                    validate_credential(payload['credential']))
        except Exception:
            # Cryptographic, schema, and decoding failures have one public code.
            raise SecretsError('invalid_capability') from None
