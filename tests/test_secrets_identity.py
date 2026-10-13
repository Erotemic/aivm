"""P4a token authenticity, encryption and pure identity-decision tests.

No real provider credentials, VM keys or network endpoints are used.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.garrett.claims import (
    IdentityClaims, IdentityExpectation, assess_binding,
)
from aivm_secrets.identity.runner import evaluate
from aivm_secrets.identity.token import (
    IdentityTokenIssuer, IdentityTokenVerifier, certificate_thumbprint,
)
from aivm_secrets.kernel import codec


def pair(der=b'fake DER certificate 1'):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    secret = Ed25519PrivateKey.generate()
    key = secrets.token_bytes(32)
    thumb = certificate_thumbprint(der)
    claims = IdentityClaims.parse({
        'iss': 'aivm.test', 'aud': 'aivm-secrets.remote',
        'sub': 'instance-7', 'jti': 'a' * 32, 'iat': 100,
        'exp': 200, 'epoch': 3, 'cnf': {'x5t#S256': thumb},
    })
    expected = IdentityExpectation.parse({
        'issuer': 'aivm.test', 'audience': 'aivm-secrets.remote',
        'subject': 'instance-7', 'epoch': 3,
    })
    issuer = IdentityTokenIssuer(secret, key, key_id='local-1')
    verifier = IdentityTokenVerifier(secret.public_key(), key, key_id='local-1',
                                     expected=expected)
    return issuer, verifier, claims, expected, der


def denial(call):
    with pytest.raises(SecretsError) as caught:
        call()
    assert caught.value.code == 'invalid_capability'


def alter_segment(token, i, raw):
    parts = token.split('.')
    parts[i] = base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
    return '.'.join(parts)


def test_real_ed25519_jwt_with_sealed_inner_capability():
    issuer, verifier, claims, _, der = pair()
    inner = 'aivs1.' + 'A' * 48
    token = issuer.issue(claims, inner)
    assert token.count('.') == 2
    assert inner not in token
    assert 'fake DER' not in token
    decoded_payload = json.loads(base64.urlsafe_b64decode(
        token.split('.')[1] + '==='))
    assert decoded_payload['cnf']['x5t#S256'] == certificate_thumbprint(der)
    assert decoded_payload['enc'] != inner
    assert 'credential' not in decoded_payload
    opened = verifier.open(token, authenticated_peer_der=der, now=150)
    assert opened.claims == claims
    assert opened.broker_capability == inner
    assert inner not in repr(opened)
    assert assess_binding(opened.claims, verifier.expected,
                          certificate_thumbprint(der), 150)


def test_each_token_has_a_fresh_nonce_even_with_same_identity():
    issuer, verifier, claims, _, der = pair()
    first = issuer.issue(claims, 'aivs1.' + 'A' * 48)
    second = issuer.issue(claims, 'aivs1.' + 'A' * 48)
    assert first != second
    assert verifier.open(first, authenticated_peer_der=der, now=150)
    assert verifier.open(second, authenticated_peer_der=der, now=150)


def test_wrong_certificate_and_expiry_and_epoch_all_fail_closed():
    issuer, verifier, claims, expected, der = pair()
    token = issuer.issue(claims, 'aivs1.XYZ')
    for changed_der, now in [(b'different cert', 150), (der, 99), (der, 200),
                             (der, 500)]:
        denial(lambda d=changed_der, n=now: verifier.open(
            token, authenticated_peer_der=d, now=n))
    other = IdentityTokenVerifier(verifier._verifier, b'B' * 32,
                                  key_id='local-1', expected=expected)
    denial(lambda: other.open(token, authenticated_peer_der=der, now=150))
    verifier.expected = replace(expected, epoch=4)
    denial(lambda: verifier.open(token, authenticated_peer_der=der, now=150))
    verifier.expected = expected
    assert verifier.open(token, authenticated_peer_der=der, now=150)


def test_mutating_signed_public_claims_and_ciphertext_fails():
    issuer, verifier, claims, _, der = pair()
    token = issuer.issue(claims, 'aivs1.' + 'X' * 32)
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==='))
    for field, value in [('sub', 'different-instance'), ('aud', 'another'),
                         ('epoch', 4), ('enc', 'AAAA')]:
        changed = dict(payload)
        changed[field] = value
        denial(lambda c=changed: verifier.open(
            alter_segment(token, 1, codec.dumps(c)),
            authenticated_peer_der=der, now=150))
    denial(lambda: verifier.open(alter_segment(token, 2, b'\0' * 64),
                                 authenticated_peer_der=der, now=150))
    h = {'alg': 'none', 'typ': 'JWT', 'kid': 'local-1'}
    denial(lambda: verifier.open(alter_segment(token, 0, codec.dumps(h)),
                                 authenticated_peer_der=der, now=150))


def test_other_issuer_signing_key_is_refused():
    _, verifier, claims, _, der = pair()
    b, _, _, _, _ = pair()
    token = b.issue(claims, 'aivs1.XYZ')
    denial(lambda: verifier.open(token, authenticated_peer_der=der, now=150))


def test_claims_fail_on_unknown_fields_or_bool_epoch():
    _, _, claims, _, _ = pair()
    original = claims.to_dict()
    for case in [{**original, 'extra': True}, {**original, 'epoch': True},
                 {**original, 'exp': original['iat'] + 3601},
                 {**original, 'cnf': {'x5t#S256': '!' * 43}},
                 {**original, 'cnf': {'x5t#S256': 'A' * 43, 'extra': 'x'}}]:
        denial(lambda c=case: IdentityClaims.parse(c))
    with pytest.raises(FrozenInstanceError):
        claims.epoch = 4


def test_token_size_and_bad_shapes_refused():
    issuer, verifier, claims, _, der = pair()
    denial(lambda: issuer.issue(claims, 'plaintext-not-sealed'))
    denial(lambda: issuer.issue(claims, 'aivs1.' + 'X' * 40000))
    token = issuer.issue(claims, 'aivs1.abc')
    for garbage in ['', 'x', 'eyJhbGciOiJub25lIn0.e30.', token + '!',
                    token + '=']:
        denial(lambda t=garbage: verifier.open(
            t, authenticated_peer_der=der, now=150))


def test_pure_parity_corpus():
    path = Path(__file__).parent / 'secrets_vectors' / 'identity-v1.jsonl'
    cases = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(cases) >= 35
    assert sum(case['expected_result']['ok'] for case in cases) >= 5
    assert sum(not case['expected_result']['ok'] for case in cases) >= 25
    for case in cases:
        assert evaluate(case['input']) == case['expected_result'], case['name']
