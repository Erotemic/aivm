"""Garrett-style issuance and presentation decisions, with no I/O.

This model *does not* sign, encrypt, authenticate a TLS peer, issue a provider
credential or dispatch an authorized effect. The trusted adapter must supply
an authoritative enrollment snapshot, a genuinely verified peer and a CSPRNG
identifier, and must delegate every provider effect to the existing broker.

The return values are intents only. This module is suitable for an independent
safe-Rust implementation and later extracted compositional proofs.
"""
from __future__ import annotations

from dataclasses import dataclass

from ...errors import SecretsError
from ...primitives import grammar
from .claims import (
    IdentityClaims, IdentityExpectation, MAX_IDENTITY_LIFETIME, assess_binding,
)
from . import registry


@dataclass(frozen=True)
class IssueIntent:
    claims: IdentityClaims


@dataclass(frozen=True)
class Presentation:
    subject: str
    token_id: str
    epoch: int
    certificate_sha256: str


def prepare_issue(state: object, *, issuer: str, audience: str, subject: str,
                  token_id: str, now: int, lifetime: int) -> IssueIntent:
    """Issue only for a current enrollment with bounded remaining lifetime.

    A host-only caller chooses `subject`, `token_id`, `now` and `lifetime`.
    This is a pure decision; it does not return a signing key or capability.
    """
    current = registry.validate(state, issuer=issuer, audience=audience)
    IdentityExpectation.parse({
        'issuer': issuer, 'audience': audience, 'subject': subject, 'epoch': 0,
    })
    grammar.hex_string(token_id, 32, code='invalid_capability')
    grammar.integer(now, 0, registry.MAX_TIME, code='invalid_capability')
    grammar.integer(lifetime, 1, MAX_IDENTITY_LIFETIME,
                    code='invalid_capability')
    record = current['subjects'].get(subject)
    if record is None or not record['active'] or now >= record['not_after']:
        raise SecretsError('invalid_capability')
    expires = min(now + lifetime, record['not_after'])
    if expires <= now:
        raise SecretsError('invalid_capability')
    claims = IdentityClaims.parse({
        'iss': issuer, 'aud': audience, 'sub': subject, 'jti': token_id,
        'iat': now, 'exp': expires, 'epoch': record['epoch'],
        'cnf': {'x5t#S256': record['certificate_sha256']},
    })
    return IssueIntent(claims)


def present(claims: IdentityClaims, expected: IdentityExpectation,
            authenticated_peer_thumbprint: str, *, now: int) -> Presentation:
    """Require authentic input claims/peer and return a bounded identity intent.

    The actual Ed25519 signature, AEAD and TLS certificate are verified by
    separate adapters BEFORE this function is called. This function alone
    cannot authenticate an arbitrary input, authorize a service operation or
    confer access to a host credential.
    """
    assess_binding(claims, expected, authenticated_peer_thumbprint, now)
    return Presentation(claims.subject, claims.token_id, claims.epoch,
                        claims.certificate_sha256)


__all__ = ['IssueIntent', 'Presentation', 'prepare_issue', 'present']
