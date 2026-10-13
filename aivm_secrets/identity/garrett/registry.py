"""Pure, deterministic enrollment state machine for Python/Rust parity.

No file I/O, wall clock, randomness, certificate parsing, or TLS. Functions
accept bounded JSON-shaped immutable-by-contract inputs and return NEW state.
The operator side performs locked, audited, atomic persistence separately.
"""

from __future__ import annotations

from typing import Any

from ...errors import SecretsError
from ...primitives import grammar, epochs
from .claims import IdentityClaims, IdentityExpectation, MAX_EPOCH

SCHEMA = 1
MAX_SUBJECTS = 128
MAX_TIME = 2**63 - 1


def _name(issuer: str, audience: str, subject: str, epoch: int):
    return IdentityExpectation.parse({
        'issuer': issuer, 'audience': audience,
        'subject': subject, 'epoch': epoch,
    })


def validate(value: object, *, issuer: str, audience: str) -> dict[str, Any]:
    _name(issuer, audience, 'init', 0)
    state = grammar.exact_keys(value, frozenset({'schema', 'subjects'}),
                               code='invalid_capability')
    if type(state['schema']) is not int or state['schema'] != SCHEMA:
        raise SecretsError('invalid_capability')
    entries = state['subjects']
    if type(entries) is not dict or len(entries) > MAX_SUBJECTS:
        raise SecretsError('invalid_capability')
    for subject, entry in entries.items():
        entry = grammar.exact_keys(entry, frozenset({
            'epoch', 'active', 'certificate_sha256', 'not_after',
        }), code='invalid_capability')
        if (type(entry['epoch']) is not int or
                not 0 <= entry['epoch'] <= MAX_EPOCH or
                type(entry['active']) is not bool or
                type(entry['not_after']) is not int or
                not 0 <= entry['not_after'] <= MAX_TIME):
            raise SecretsError('invalid_capability')
        _name(issuer, audience, subject, entry['epoch'])
        # Apply exactly the same canonical thumbprint rules as bound tokens.
        IdentityClaims.parse({
            'iss': issuer, 'aud': audience, 'sub': subject,
            'jti': '0' * 32, 'iat': 0, 'exp': 1,
            'epoch': entry['epoch'],
            'cnf': {'x5t#S256': entry['certificate_sha256']},
        })
    return state


def enroll(value: object, *, issuer: str, audience: str, subject: str,
           thumbprint: str, not_after: int, replace: bool) -> dict[str, Any]:
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    if (type(replace) is not bool or type(not_after) is not int or
            not 0 <= not_after <= MAX_TIME):
        raise SecretsError('invalid_capability')
    prior = state['subjects'].get(subject)
    if prior and prior['active'] and not replace:
        raise SecretsError('denied')
    next_epoch = (None if prior is None else
                  epochs.advance(prior['epoch'], maximum=MAX_EPOCH))
    if prior is None and len(state['subjects']) >= MAX_SUBJECTS:
        raise SecretsError('exhausted')
    result = {'schema': SCHEMA,
              'subjects': {k: dict(v) for k, v in state['subjects'].items()}}
    result['subjects'][subject] = {
        'epoch': 0 if next_epoch is None else next_epoch,
        'active': True, 'certificate_sha256': thumbprint,
        'not_after': not_after,
    }
    return validate(result, issuer=issuer, audience=audience)


def renew(value: object, *, issuer: str, audience: str, subject: str,
          expected_epoch: int, expected_thumbprint: str,
          thumbprint: str, not_after: int, now: int) -> dict[str, Any]:
    """Compare-and-swap a current enrollment into its next epoch.

    A valid new CSR is verified by the caller. This pure transition cannot
    authenticate a CSR, certify a VM, or persist the new state. Reject revoked
    identities, concurrent replacement and same-certificate replay. The
    trusted host adapter performs the transition under its registry lock.
    """
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    if (type(expected_epoch) is not int or
            not 0 <= expected_epoch <= MAX_EPOCH or
            type(expected_thumbprint) is not str or
            type(now) is not int or not 0 <= now <= MAX_TIME or
            type(not_after) is not int or not now < not_after <= MAX_TIME):
        raise SecretsError('invalid_capability')
    prior = state['subjects'].get(subject)
    if (prior is None or not prior['active'] or
            prior['epoch'] != expected_epoch or
            prior['certificate_sha256'] != expected_thumbprint):
        raise SecretsError('revoked')
    if thumbprint == expected_thumbprint:
        raise SecretsError('denied')
    return enroll(state, issuer=issuer, audience=audience,
                  subject=subject, thumbprint=thumbprint,
                  not_after=not_after, replace=True)


def revoke(value: object, *, issuer: str, audience: str,
           subject: str) -> dict[str, Any]:
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    prior = state['subjects'].get(subject)
    if prior is None:
        raise SecretsError('denied')
    if not prior['active']:
        return {'schema': SCHEMA, 'subjects': {k: dict(v)
                 for k, v in state['subjects'].items()}}
    next_epoch = epochs.advance(prior['epoch'], maximum=MAX_EPOCH)
    result = {'schema': SCHEMA,
              'subjects': {k: dict(v) for k, v in state['subjects'].items()}}
    result['subjects'][subject]['active'] = False
    result['subjects'][subject]['epoch'] = next_epoch
    return result


def revoke_if_current(value: object, *, issuer: str, audience: str,
                      subject: str, expected_epoch: int,
                      expected_thumbprint: str) -> tuple[dict[str, Any], bool]:
    """Revoke only the exact enrollment installed by an in-flight transaction.

    Return the original validated state and False after concurrent replacement.
    A failed guest install must never revoke a *newer* enrollment.
    """
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    if (type(expected_epoch) is not int or not 0 <= expected_epoch <= MAX_EPOCH
            or type(expected_thumbprint) is not str):
        raise SecretsError('invalid_capability')
    row = state['subjects'].get(subject)
    if (row is None or row['active'] is not True or
            row['epoch'] != expected_epoch or
            row['certificate_sha256'] != expected_thumbprint):
        return {'schema': SCHEMA,
                'subjects': {name: dict(row)
                             for name, row in state['subjects'].items()}}, False
    return revoke(state, issuer=issuer, audience=audience,
                  subject=subject), True


def expectation(value: object, *, issuer: str, audience: str,
                thumbprint: str, now: int) -> IdentityExpectation:
    state = validate(value, issuer=issuer, audience=audience)
    if type(now) is not int or not 0 <= now <= MAX_TIME:
        raise SecretsError('invalid_capability')
    # `thumbprint` is never taken from an untrusted JSON envelope; it is the
    # SHA256 of the real CA-validated mTLS peer DER.
    matches = [(subject, row) for subject, row in state['subjects'].items()
               if row['active'] and row['certificate_sha256'] == thumbprint
               and now < row['not_after']]
    if len(matches) != 1:
        raise SecretsError('invalid_capability')
    subject, row = matches[0]
    return _name(issuer, audience, subject, row['epoch'])
