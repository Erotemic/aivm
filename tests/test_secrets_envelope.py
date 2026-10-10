"""AEAD-sealed capabilities: the guest carries ciphertext, never a credential."""

from __future__ import annotations

import base64

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.envelope import PREFIX, EnvelopeCodec
from aivm_secrets.kernel import codec
from aivm_secrets.kernel.model import Binding, Claims
from tests.secrets_helpers import TOKEN


def claims():
    return Claims(Binding(1000, 'p', 'v', 'c'), 'a' * 64, 'b' * 32, 100, 200)


def unseal(capability: str) -> bytes:
    body = capability[len(PREFIX) :]
    return base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))


def reseal(data: bytes) -> str:
    return PREFIX + base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def test_sealed_round_trip_and_no_plaintext_repr():
    envelope = EnvelopeCodec()
    cap = envelope.seal(claims(), TOKEN)
    assert TOKEN not in cap and TOKEN.encode() not in unseal(cap)
    opened = envelope.open(cap)
    assert opened.claims == claims()
    assert opened.credential == TOKEN
    assert TOKEN not in repr(opened)
    assert TOKEN not in repr(envelope)
    assert envelope.seal(claims(), TOKEN) != cap  # fresh nonce


def test_every_ciphertext_byte_is_authenticated():
    envelope = EnvelopeCodec()
    sealed = unseal(envelope.seal(claims(), TOKEN))
    for index in range(len(sealed)):
        changed = bytearray(sealed)
        changed[index] ^= 1
        with pytest.raises(SecretsError, match='Capability authentication'):
            envelope.open(reseal(bytes(changed)))
    for cut in (0, 1, 12, 28, len(sealed) - 1):
        with pytest.raises(SecretsError):
            envelope.open(reseal(sealed[:cut]))
    with pytest.raises(SecretsError):
        envelope.open(reseal(sealed + b'\x00'))


def test_wrong_key_and_noncanonical_encoding():
    envelope = EnvelopeCodec()
    cap = envelope.seal(claims(), TOKEN)
    with pytest.raises(SecretsError):
        EnvelopeCodec().open(cap)
    for bad in [
        cap + '=', cap + '\n', ' ' + cap, cap + 'A', 'aivs2.' + cap[6:],
        'AIVS1.' + cap[6:], cap[6:], 'eyJWT', '', None, [], 7, b'bytes',
        'x' * 40000, PREFIX, PREFIX + '!!!!',
        cap.replace('-', '+').replace('_', '/'),
    ]:  # fmt: skip
        with pytest.raises(SecretsError) as caught:
            envelope.open(bad)
        assert caught.value.code == 'invalid_capability'


def test_authentic_ciphertext_with_a_foreign_payload_is_still_refused():
    """A valid tag is not enough: the plaintext must be exactly a capability."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from aivm_secrets.host.envelope import AAD

    key = bytes(range(32))
    envelope = EnvelopeCodec(key)
    good = {'claims': claims().to_dict(), 'credential': TOKEN}
    payloads = [
        b'not json',
        codec.dumps([]),
        codec.dumps({'claims': good['claims']}),
        codec.dumps({**good, 'admin': True}),
        codec.dumps({**good, 'credential': 'short'}),
        codec.dumps({**good, 'credential': 'has space ' + 'x' * 16}),
        codec.dumps({**good, 'claims': {**good['claims'], 'expires_at': 100}}),
        b'{"claims":1,"claims":2,"credential":"' + TOKEN.encode() + b'"}',
    ]
    for payload in payloads:
        nonce = b'n' * 12
        forged = reseal(nonce + AESGCM(key).encrypt(nonce, payload, AAD))
        with pytest.raises(SecretsError) as caught:
            envelope.open(forged)
        assert caught.value.code == 'invalid_capability'
    # Same key and plaintext under different associated data: a different
    # protocol's token is not this protocol's capability.
    nonce = b'n' * 12
    other = reseal(
        nonce + AESGCM(key).encrypt(nonce, codec.dumps(good), b'other')
    )
    with pytest.raises(SecretsError):
        envelope.open(other)
    assert (
        envelope.open(
            reseal(nonce + AESGCM(key).encrypt(nonce, codec.dumps(good), AAD))
        ).credential
        == TOKEN
    )


@pytest.mark.parametrize(
    'token',
    ['short', 'x' * 4097, 'x' * 20 + '\r\nHeader: evil', 'x ' * 20, 'α' * 20,
     'x' * 20 + '\x00', '', None, 12345678901234567890],
)  # fmt: skip
def test_credentials_cannot_inject_headers(token):
    with pytest.raises(SecretsError) as caught:
        EnvelopeCodec().seal(claims(), token)
    assert caught.value.code == 'credential_source'


def test_missing_crypto_is_a_named_error(monkeypatch):
    import builtins

    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name.startswith('cryptography'):
            raise ImportError(name)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', refuse)
    with pytest.raises(SecretsError) as caught:
        EnvelopeCodec()
    assert caught.value.code == 'missing_crypto'
