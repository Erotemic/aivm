import base64

import pytest

from aivm_secrets.core import Binding, Claims
from aivm_secrets.envelope import EnvelopeCodec, PREFIX
from aivm_secrets.errors import SecretsError
from tests.secrets_helpers import TOKEN


def claims():
    return Claims(Binding(1000, 'p', 'v', 'c'), 'a' * 64, 'b' * 32, 100, 200)


def test_sealed_round_trip_and_no_plaintext_repr():
    codec = EnvelopeCodec()
    cap = codec.seal(claims(), TOKEN)
    assert TOKEN not in cap
    opened = codec.open(cap)
    assert opened.claims == claims()
    assert opened.credential == TOKEN
    assert TOKEN not in repr(opened)
    assert TOKEN not in repr(codec)
    assert codec.seal(claims(), TOKEN) != cap  # fresh nonce


def test_every_ciphertext_byte_is_authenticated():
    codec = EnvelopeCodec()
    cap = codec.seal(claims(), TOKEN)
    body = cap[len(PREFIX):]
    sealed = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
    for index in range(len(sealed)):
        changed = bytearray(sealed)
        changed[index] ^= 1
        bad = PREFIX + base64.urlsafe_b64encode(changed).rstrip(b'=').decode('ascii')
        with pytest.raises(SecretsError, match='Capability authentication'):
            codec.open(bad)


def test_wrong_key_and_noncanonical_encoding():
    codec = EnvelopeCodec()
    cap = codec.seal(claims(), TOKEN)
    with pytest.raises(SecretsError):
        EnvelopeCodec().open(cap)
    for bad in [cap + '=', cap + '\n', 'aivs2.' + cap[6:], 'eyJWT', '', None, [], 'x' * 40000]:
        with pytest.raises(SecretsError):
            codec.open(bad)


@pytest.mark.parametrize('token', ['short', 'x' * 4097, 'x' * 20 + '\r\nHeader: evil', 'x ' * 20, '\u03b1' * 20])
def test_credentials_cannot_inject_headers(token):
    with pytest.raises(SecretsError):
        EnvelopeCodec().seal(claims(), token)
