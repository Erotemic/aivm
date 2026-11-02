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


@pytest.mark.parametrize(
    'data',
    [
        pytest.param(b'["\\ud800"]', id='lone-high'),
        pytest.param(b'["\\udc00"]', id='lone-low'),
        pytest.param(b'["\\uDBFF"]', id='uppercase-lone'),
        pytest.param(b'["\\ude00\\ud83d"]', id='reversed-pair'),
        pytest.param(b'["\\ud83d\\u0041"]', id='high-then-other-escape'),
        pytest.param(b'["\\ud83dx"]', id='high-then-literal'),
        pytest.param(b'["a\\ud83d"]', id='high-at-end'),
        pytest.param(b'{"\\ud800":1}', id='in-a-key'),
        pytest.param(b'{"a":[{"b":"\\udfff"}]}', id='nested'),
        pytest.param(b'"\\udfff"', id='bare-string'),
        pytest.param(b'["\xed\xa0\x80"]', id='utf8-encoded-surrogate'),
    ],
)
def test_lone_surrogates_are_refused(data: bytes) -> None:
    """Every accepted string has a UTF-8 encoding, as a Rust ``str`` does.

    Refusing one can turn a rare provider response into ``upstream_response``:
    the caller's code is kept, and the failure is closed.
    """
    with pytest.raises(SecretsError) as caught:
        codec.loads(data)
    assert caught.value.code == 'invalid_request'
    with pytest.raises(SecretsError) as caught:
        codec.loads(data, code='upstream_response')
    assert caught.value.code == 'upstream_response'


def test_a_surrogate_pair_is_one_code_point() -> None:
    pair = codec.loads(b'["\\ud83d\\ude00","\\uD83D\\uDE00"]')
    assert pair == ['\U0001f600', '\U0001f600']
    # A str argument holding a lone surrogate cannot be encoded at all.
    with pytest.raises(SecretsError):
        codec.loads('["\ud800"]')


def test_negative_zero_is_the_integer_zero() -> None:
    """``-0`` is a spelling of ``0``; ``-0.0`` stays a float."""
    value = codec.loads(b'{"a":-0,"b":[-0]}')
    assert value == {'a': 0, 'b': [0]}
    assert type(value['a']) is int
    assert codec.dumps(value) == b'{"a":0,"b":[0]}'
    assert codec.digest(value) == codec.digest({'a': 0, 'b': [0]})
    negative = codec.loads(b'[-0.0]')
    assert type(negative[0]) is float
    with pytest.raises(SecretsError):
        codec.digest(negative)


def test_loads_keeps_large_integers_that_digest_refuses() -> None:
    """Typed parsers bound integers; only a digest needs a 64-bit word."""
    assert codec.loads(b'[18446744073709551616]') == [2**64]
    assert codec.loads(b'[9223372036854775808]') == [2**63]


@pytest.mark.parametrize(
    'value',
    [
        pytest.param([1.5], id='float'),
        pytest.param([1.0], id='integral-float'),
        pytest.param({'a': [{'b': -0.0}]}, id='nested-float'),
        pytest.param(0.5, id='bare-float'),
        pytest.param([2**63], id='one-past-i64-max'),
        pytest.param([-(2**63) - 1], id='one-below-i64-min'),
        pytest.param({'n': 2**64}, id='beyond-u64'),
        pytest.param({1: 'a'}, id='integer-key'),
        pytest.param({None: 'a'}, id='null-key'),
        pytest.param(['\ud800'], id='lone-surrogate-value'),
        pytest.param({'\udc00': 1}, id='lone-surrogate-key'),
    ],
)
def test_digest_refuses_values_outside_its_domain(value: object) -> None:
    """Another implementation could not compute the same digest of these."""
    with pytest.raises(SecretsError) as caught:
        codec.digest(value)
    assert caught.value.code == 'invalid_request'


def test_digest_accepts_the_signed_64_bit_edges() -> None:
    edges = [-(2**63), 2**63 - 1, True, False, None, '\U0001f600']
    assert codec.digest(edges) == hashlib.sha256(
        b'[-9223372036854775808,9223372036854775807,true,false,null,'
        b'"\\ud83d\\ude00"]'
    ).hexdigest()
    # A tuple is encoded, and so digested, exactly as the array it stands for.
    assert codec.digest(tuple(edges)) == codec.digest(edges)


def test_digest_of_a_cyclic_value_fails_closed() -> None:
    loop: list[object] = []
    loop.append(loop)
    with pytest.raises(SecretsError):
        codec.digest(loop)
