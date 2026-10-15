"""Pure, deterministic enrollment state machine for Python/Rust parity.

No file I/O, wall clock, randomness, certificate parsing, or TLS. Functions
accept bounded JSON-shaped immutable-by-contract inputs and return NEW state.
The operator side performs locked, audited, atomic persistence separately.

Each row records the certificate the authority last issued for a subject
(``certificate_sha256``), the SHA-256 fingerprint of the public key that
certificate certifies (``key_sha256``, lowercase hexadecimal, the format
``inspect_csr`` prints), and a bounded, oldest-first list of key fingerprints
that were replaced for that subject (``retired_keys``). The key rules are:

* a key retired for a subject is never certified for it again (until the
  row itself is forgotten, or the fingerprint ages out of the bounded list);
* a key certified for one ACTIVE subject is never certified for another, so
  a cloned VM's copied key cannot gain a second subject;
* revocation always deactivates, even when the epoch cannot advance;
* a subject is forgotten only once it is inactive and its certificate has
  expired, so the forgotten certificate can never be presented again.

The adapter must supply ``key_sha256`` from the authenticated CSR it signs;
this model cannot tell whether a fingerprint is honest.
"""

from __future__ import annotations

from typing import Any

from ...errors import SecretsError
from ...primitives import grammar, epochs
from .claims import IdentityClaims, IdentityExpectation, MAX_EPOCH

SCHEMA = 1
MAX_SUBJECTS = 128
MAX_TIME = 2**63 - 1
MAX_RETIRED_KEYS = 8
_ROW = frozenset({
    'epoch', 'active', 'certificate_sha256', 'not_after', 'key_sha256',
    'retired_keys',
})


def _name(issuer: str, audience: str, subject: str,
          epoch: int) -> IdentityExpectation:
    return IdentityExpectation.parse({
        'issuer': issuer, 'audience': audience,
        'subject': subject, 'epoch': epoch,
    })


def _key(value: object) -> str:
    return grammar.hex_string(value, 64, code='invalid_capability')


def _thumbprint(issuer: str, audience: str, subject: str, epoch: int,
                value: object) -> None:
    # Apply exactly the same canonical thumbprint rules as bound tokens.
    IdentityClaims.parse({
        'iss': issuer, 'aud': audience, 'sub': subject,
        'jti': '0' * 32, 'iat': 0, 'exp': 1, 'epoch': epoch,
        'cnf': {'x5t#S256': value},
    })


def _time(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TIME:
        raise SecretsError('invalid_capability')
    return value


def _row_copy(row: dict[str, Any]) -> dict[str, Any]:
    return {'epoch': row['epoch'], 'active': row['active'],
            'certificate_sha256': row['certificate_sha256'],
            'not_after': row['not_after'], 'key_sha256': row['key_sha256'],
            'retired_keys': list(row['retired_keys'])}


def _copy(state: dict[str, Any]) -> dict[str, Any]:
    subjects = {}
    for subject, row in state['subjects'].items():
        subjects[subject] = _row_copy(row)
    return {'schema': SCHEMA, 'subjects': subjects}


def validate(value: object, *, issuer: str, audience: str) -> dict[str, Any]:
    _name(issuer, audience, 'init', 0)
    state = grammar.exact_keys(value, frozenset({'schema', 'subjects'}),
                               code='invalid_capability')
    if type(state['schema']) is not int or state['schema'] != SCHEMA:
        raise SecretsError('invalid_capability')
    entries = state['subjects']
    if type(entries) is not dict or len(entries) > MAX_SUBJECTS:
        raise SecretsError('invalid_capability')
    active_keys = set()
    for subject, entry in entries.items():
        entry = grammar.exact_keys(entry, _ROW, code='invalid_capability')
        if (type(entry['epoch']) is not int or
                not 0 <= entry['epoch'] <= MAX_EPOCH or
                type(entry['active']) is not bool or
                type(entry['not_after']) is not int or
                not 0 <= entry['not_after'] <= MAX_TIME):
            raise SecretsError('invalid_capability')
        _name(issuer, audience, subject, entry['epoch'])
        _thumbprint(issuer, audience, subject, entry['epoch'],
                    entry['certificate_sha256'])
        current = _key(entry['key_sha256'])
        retired = entry['retired_keys']
        if type(retired) is not list or len(retired) > MAX_RETIRED_KEYS:
            raise SecretsError('invalid_capability')
        seen = set()
        for item in retired:
            if _key(item) == current or item in seen:
                raise SecretsError('invalid_capability')
            seen.add(item)
        # Transitions never certify one key for two active subjects; a state
        # that does is corrupt, not merely ambiguous.
        if entry['active']:
            if current in active_keys:
                raise SecretsError('invalid_capability')
            active_keys.add(current)
    return state


def _require_key_custody(state: dict[str, Any], *, subject: str,
                         key_sha256: str) -> None:
    """Refuse a retired key, or a key another active subject holds.

    The details are fixed operator context (the code is what a client and
    the corpus see); the second names no other subject.
    """
    prior = state['subjects'].get(subject)
    if prior is not None and key_sha256 in prior['retired_keys']:
        raise SecretsError('denied', detail='key is retired for this subject')
    for name, row in state['subjects'].items():
        if name != subject and row['active'] and row['key_sha256'] == key_sha256:
            raise SecretsError('denied', detail=(
                'key is certified for another active subject'))


def _retired_after(prior: dict[str, Any], key_sha256: str) -> list[str]:
    """Retire the prior key iff it is being replaced; keep the newest N."""
    kept = list(prior['retired_keys'])
    if prior['key_sha256'] != key_sha256:
        kept.append(prior['key_sha256'])
    if len(kept) > MAX_RETIRED_KEYS:
        kept = kept[len(kept) - MAX_RETIRED_KEYS:]
    return kept


def _deactivated(row: dict[str, Any]) -> dict[str, Any]:
    """Revocation always deactivates; the epoch advances unless saturated.

    An exhausted epoch cannot advance, but leaving the row active would let
    `expectation` keep accepting a certificate the operator revoked. The
    saturated row stays inactive; a later enrollment of it is 'exhausted'.
    """
    result = _row_copy(row)
    result['active'] = False
    if row['epoch'] != MAX_EPOCH:
        result['epoch'] = epochs.advance(row['epoch'], maximum=MAX_EPOCH)
    return result


def enroll(value: object, *, issuer: str, audience: str, subject: str,
           thumbprint: str, key_sha256: str, not_after: int,
           replace: bool) -> dict[str, Any]:
    """Enroll a subject, or with `replace` re-enroll an active one.

    Refusals, in this order: malformed input ('invalid_capability'); an
    active row without `replace` ('denied'); a key retired for the subject
    or certified for another active subject ('denied'); a row whose epoch
    cannot advance, or a new subject in a full registry ('exhausted'). A
    key replaced by a different one is retired for the subject.
    """
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    if (type(replace) is not bool or type(not_after) is not int or
            not 0 <= not_after <= MAX_TIME):
        raise SecretsError('invalid_capability')
    _thumbprint(issuer, audience, subject, 0, thumbprint)
    _key(key_sha256)
    prior = state['subjects'].get(subject)
    if prior is not None and prior['active'] and not replace:
        raise SecretsError('denied')
    _require_key_custody(state, subject=subject, key_sha256=key_sha256)
    if prior is not None and prior['epoch'] == MAX_EPOCH:
        raise SecretsError('exhausted')
    if prior is None and len(state['subjects']) >= MAX_SUBJECTS:
        raise SecretsError('exhausted')
    result = _copy(state)
    result['subjects'][subject] = {
        'epoch': (0 if prior is None else
                  epochs.advance(prior['epoch'], maximum=MAX_EPOCH)),
        'active': True, 'certificate_sha256': thumbprint,
        'not_after': not_after, 'key_sha256': key_sha256,
        'retired_keys': [] if prior is None else _retired_after(prior, key_sha256),
    }
    return validate(result, issuer=issuer, audience=audience)


def replace_if_current(value: object, *, issuer: str, audience: str,
                       subject: str, expected_epoch: int,
                       expected_thumbprint: str, thumbprint: str,
                       key_sha256: str, not_after: int) -> dict[str, Any]:
    """`enroll --replace` guarded by a compare-and-swap on the row version.

    The CAS names the row the caller inspected by its epoch and certificate
    thumbprint, whether or not that row is still active: a replacement after
    `rotate-ca` or `revoke` targets an inactive row. Any concurrent enroll,
    renewal, rotation or revocation changes the epoch, so a stale caller is
    refused ('revoked') instead of overwriting the newer enrollment.
    """
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    if (type(expected_epoch) is not int or
            not 0 <= expected_epoch <= MAX_EPOCH or
            type(expected_thumbprint) is not str or
            type(not_after) is not int or not 0 <= not_after <= MAX_TIME):
        raise SecretsError('invalid_capability')
    _thumbprint(issuer, audience, subject, 0, thumbprint)
    _key(key_sha256)
    prior = state['subjects'].get(subject)
    if (prior is None or prior['epoch'] != expected_epoch or
            prior['certificate_sha256'] != expected_thumbprint):
        raise SecretsError('revoked')
    return enroll(state, issuer=issuer, audience=audience, subject=subject,
                  thumbprint=thumbprint, key_sha256=key_sha256,
                  not_after=not_after, replace=True)


def renew(value: object, *, issuer: str, audience: str, subject: str,
          expected_epoch: int, expected_thumbprint: str,
          thumbprint: str, key_sha256: str, not_after: int,
          now: int) -> dict[str, Any]:
    """Compare-and-swap a current enrollment into its next epoch.

    A valid new CSR is verified by the caller. This pure transition cannot
    authenticate a CSR, certify a VM, or persist the new state. Reject revoked
    identities, concurrent replacement and same-certificate replay. The
    trusted host adapter performs the transition under its registry lock,
    and separately decides whether the key must stay the same (renewal,
    REN-07) or must change (rotation); both obey the key custody rules here.
    """
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    if (type(expected_epoch) is not int or
            not 0 <= expected_epoch <= MAX_EPOCH or
            type(expected_thumbprint) is not str or
            type(now) is not int or not 0 <= now <= MAX_TIME or
            type(not_after) is not int or not now < not_after <= MAX_TIME):
        raise SecretsError('invalid_capability')
    _key(key_sha256)
    prior = state['subjects'].get(subject)
    if (prior is None or not prior['active'] or
            prior['epoch'] != expected_epoch or
            prior['certificate_sha256'] != expected_thumbprint):
        raise SecretsError('revoked')
    if thumbprint == expected_thumbprint:
        raise SecretsError('denied')
    if prior['epoch'] == MAX_EPOCH:
        # An enrollment that cannot advance cannot be renewed: it is over.
        raise SecretsError('revoked')
    return enroll(state, issuer=issuer, audience=audience,
                  subject=subject, thumbprint=thumbprint,
                  key_sha256=key_sha256, not_after=not_after, replace=True)


def revoke(value: object, *, issuer: str, audience: str,
           subject: str) -> dict[str, Any]:
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    prior = state['subjects'].get(subject)
    if prior is None:
        raise SecretsError('denied')
    result = _copy(state)
    if prior['active']:
        result['subjects'][subject] = _deactivated(prior)
    return result


def revoke_all(value: object, *, issuer: str,
               audience: str) -> dict[str, Any]:
    """Deactivate every active row and advance its epoch (saturating).

    This is the registry half of a CA rotation. Keeping the rows, instead of
    committing an empty registry, keeps every subject's epoch monotonic: a
    re-enrollment after the rotation gets a strictly higher epoch than any
    certificate or token issued before it, unless the row is forgotten in
    between (`forget`, only once its certificate has expired), which
    restarts the subject at epoch 0.
    """
    state = validate(value, issuer=issuer, audience=audience)
    result = _copy(state)
    for subject, row in state['subjects'].items():
        if row['active']:
            result['subjects'][subject] = _deactivated(row)
    return result


def _forgettable(row: dict[str, Any], now: int) -> bool:
    return not row['active'] and now >= row['not_after']


def forget(value: object, *, issuer: str, audience: str, subject: str,
           now: int) -> dict[str, Any]:
    """Remove one inactive row whose certificate has expired.

    Its certificate can never be presented again, and every token bound to
    it expired no later than the certificate, so restarting that subject's
    epoch at 0 cannot revive anything.

    The row's key custody is forgotten with it: a later enrollment of the
    same subject starts with no retired keys, so a key once rotated away
    from that subject can be certified for it again. Managed-VM subjects
    embed the libvirt domain UUID, so a *recreated* VM never reuses one; but
    a VM that still exists keeps its subject across revocation and CA
    rotation, and re-enrolling it after its row was forgotten certifies
    whatever key its CSR carries. That is a limit of this model, documented
    for operators, not something it can detect.
    """
    state = validate(value, issuer=issuer, audience=audience)
    _name(issuer, audience, subject, 0)
    _time(now)
    row = state['subjects'].get(subject)
    if row is None or not _forgettable(row, now):
        raise SecretsError('denied')
    result = _copy(state)
    del result['subjects'][subject]
    return result


def prune(value: object, *, issuer: str, audience: str,
          now: int) -> dict[str, Any]:
    """Forget every row `forget` would accept; keep all others unchanged."""
    state = validate(value, issuer=issuer, audience=audience)
    _time(now)
    result = _copy(state)
    for subject, row in state['subjects'].items():
        if _forgettable(row, now):
            del result['subjects'][subject]
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
        return _copy(state), False
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
