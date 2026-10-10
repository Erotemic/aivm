"""Strict JSON: accepted bytes have exactly one meaning (CODEC-01)."""

from __future__ import annotations

import hashlib

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel import codec


@pytest.mark.parametrize(
    'data',
    [
        b'{"x":1,"x":2}',
        b'{"a":{"x":1,"x":1}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1e999}',
        b'{"x":-1e999}',
        b'{"x":"\xff"}',
        b'[] trailing',
        b'{}{}',
        b'',
        b'{',
        b"{'x':1}",
        b'[' * 2000 + b']' * 2000,
        b'[' * 65 + b']' * 65,
        b'{"x":' + b'9' * 5000 + b'}',
    ],
    ids=[
        'duplicate', 'nested-duplicate', 'nan', 'infinity', 'negative-infinity',
        'float-overflow', 'negative-float-overflow', 'invalid-utf8',
        'trailing', 'two-documents', 'empty', 'truncated', 'single-quotes',
        'deep-nesting', 'one-level-too-deep', 'huge-integer',
    ],
)  # fmt: skip
def test_wire_strict_json(data):
    with pytest.raises(SecretsError) as caught:
        codec.loads(data)
    assert caught.value.code == 'invalid_request'


def test_depth_and_size_bounds_are_exact():
    assert codec.loads(b'[' * 64 + b']' * 64)
    # Brackets inside strings are text, not structure.
    assert codec.loads(b'["' + b'[' * 500 + b'"]') == ['[' * 500]
    assert codec.loads(b'["\\"[[[[\\\\"]') == ['"[[[[\\']
    exact = b'"' + b'x' * (codec.MAX_FRAME - 2) + b'"'
    assert len(codec.loads(exact)) == codec.MAX_FRAME - 2
    with pytest.raises(SecretsError):
        codec.loads(exact + b' ')
    assert codec.loads(b'[1]', limit=3) == [1]
    with pytest.raises(SecretsError):
        codec.loads(b'[1] ', limit=3)


def test_the_caller_chooses_the_failure_code():
    with pytest.raises(SecretsError) as caught:
        codec.loads(b'{', code='upstream_response')
    assert caught.value.code == 'upstream_response'


def test_canonical_encoding_is_sorted_compact_and_ascii():
    value = {'b': [1, 'é', '😀'], 'a': {'z': None, 'y': True}, 'A': '/"\\\n'}
    encoded = codec.dumps(value)
    assert encoded == (
        b'{"A":"/\\"\\\\\\n","a":{"y":true,"z":null},'
        b'"b":[1,"\\u00e9","\\ud83d\\ude00"]}'
    )
    assert codec.loads(encoded) == value
    assert codec.dumps(codec.loads(encoded)) == encoded


def test_digest_depends_on_meaning_not_spelling():
    one = codec.loads(b'{"b": 1,\n "a": "\\u00e9"}')
    two = codec.loads('{"a":"é","b":1}')
    assert codec.digest(one) == codec.digest(two)
    assert (
        codec.digest(one)
        == hashlib.sha256(b'{"a":"\\u00e9","b":1}').hexdigest()
    )
    assert codec.digest({'a': 'e', 'b': 1}) != codec.digest(one)


@pytest.mark.parametrize(
    'value',
    [float('nan'), float('inf'), {1, 2}, object(), b'bytes', {'a': {1}}],
)
def test_unencodable_values_fail_closed(value):
    with pytest.raises(SecretsError):
        codec.dumps(value)


def test_finite_floats_pass_through_provider_data():
    """Requests never carry floats, but a provider's JSON legitimately may."""
    value = codec.loads(b'{"ratio":1.5,"big":-2e3,"zero":0.0}')
    assert value == {'ratio': 1.5, 'big': -2000.0, 'zero': 0.0}
    assert codec.loads(codec.dumps(value)) == value
