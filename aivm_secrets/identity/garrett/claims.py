"""Pure, provider-independent certificate-binding decision contract (P4a).

No clock, key, certificate, socket or randomness is read here. All values are
explicit inputs, intentionally shaped for a line-for-line safe-Rust port.
A separate trusted transport authenticates the certificate and a separate
cryptographic codec authenticates the claims BEFORE this decision is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...errors import SecretsError
from ...primitives import grammar, binding, epochs, validity

MAX_IDENTITY_LIFETIME = 3600
MAX_EPOCH = 2**31 - 1
B64URL = grammar.ALNUM + '-_'


def _word(value: Any, limit: int) -> str:
    # URI audience/issuer syntax is intentionally narrower than arbitrary URLs.
    return grammar.token(value, grammar.ALNUM, grammar.ALNUM + ':./_-', limit,
                         code='invalid_capability')


def _thumbprint(value: Any) -> str:
    if type(value) is not str or len(value) != 43:
        raise SecretsError('invalid_capability')
    if not grammar.within(value, B64URL):
        raise SecretsError('invalid_capability')
    # The last unpadded base64url character of a 32-byte digest has 4 data
    # bits. The other two bits must be zero (canonical encoding).
    if value[-1] not in 'AEIMQUYcgkosw048':
        raise SecretsError('invalid_capability')
    return value


@dataclass(frozen=True)
class IdentityClaims:
    """Public portion of a signed identity token, excluding its ciphertext."""

    issuer: str
    audience: str
    subject: str
    token_id: str
    issued_at: int
    expires_at: int
    epoch: int
    certificate_sha256: str

    @classmethod
    def parse(cls, data: Any) -> IdentityClaims:
        data = grammar.exact_keys(data, frozenset({
            'iss', 'aud', 'sub', 'jti', 'iat', 'exp', 'epoch', 'cnf',
        }), code='invalid_capability')
        cnf = grammar.exact_keys(data['cnf'], frozenset({'x5t#S256'}),
                                 code='invalid_capability')
        issued_at = grammar.integer(data['iat'], 0, 2**63 - MAX_IDENTITY_LIFETIME,
                                    code='invalid_capability')
        expires_at = grammar.integer(data['exp'], issued_at + 1,
                                     issued_at + MAX_IDENTITY_LIFETIME,
                                     code='invalid_capability')
        return cls(
            _word(data['iss'], 128),
            _word(data['aud'], 128),
            _word(data['sub'], 128),
            grammar.hex_string(data['jti'], 32, code='invalid_capability'),
            issued_at,
            expires_at,
            grammar.integer(data['epoch'], 0, MAX_EPOCH,
                            code='invalid_capability'),
            _thumbprint(cnf['x5t#S256']),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'iss': self.issuer,
            'aud': self.audience,
            'sub': self.subject,
            'jti': self.token_id,
            'iat': self.issued_at,
            'exp': self.expires_at,
            'epoch': self.epoch,
            'cnf': {'x5t#S256': self.certificate_sha256},
        }


@dataclass(frozen=True)
class IdentityExpectation:
    """Trusted verifier configuration. None of these values comes from the guest."""

    issuer: str
    audience: str
    subject: str
    epoch: int

    @classmethod
    def parse(cls, data: Any) -> IdentityExpectation:
        data = grammar.exact_keys(data,
                                  frozenset({'issuer', 'audience', 'subject', 'epoch'}),
                                  code='invalid_capability')
        return cls(_word(data['issuer'], 128), _word(data['audience'], 128),
                   _word(data['subject'], 128),
                   grammar.integer(data['epoch'], 0, MAX_EPOCH,
                                   code='invalid_capability'))

    def to_dict(self) -> dict[str, Any]:
        return {'issuer': self.issuer, 'audience': self.audience,
                'subject': self.subject, 'epoch': self.epoch}


def assess_binding(claims: IdentityClaims, expected: IdentityExpectation,
                   peer_thumbprint: str, now: int) -> bool:
    """Return True only for an authenticated, current, correctly bound claim.

    The caller MUST verify the signature and the actual mTLS peer certificate
    before supplying these values. This pure function makes no such claims.
    The epoch is an explicit input; a persisted epoch/revocation store is P4c.
    """
    if type(claims) is not IdentityClaims or type(expected) is not IdentityExpectation:
        raise SecretsError('invalid_capability')
    if type(now) is not int or not 0 <= now <= 2**63 - 1:
        raise SecretsError('invalid_capability')
    _thumbprint(peer_thumbprint)
    binding.require_match(claims.issuer, expected.issuer)
    binding.require_match(claims.audience, expected.audience)
    binding.require_match(claims.subject, expected.subject)
    binding.require_match(claims.certificate_sha256, peer_thumbprint)
    epochs.require_current(claims.epoch, expected.epoch)
    validity.require_active(now, claims.issued_at, claims.expires_at)
    return True
