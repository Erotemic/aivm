"""The closed alphabets every other secrets module builds on (CODEC-01)."""

from __future__ import annotations

import re

import pytest

from aivm_secrets.errors import MESSAGES, SecretsError
from aivm_secrets.kernel import grammar

# The regular expressions the validators replaced. They are kept here, and
# only here, as an independent oracle: the loops must accept exactly the
# language these describe.
ORACLES = {
    grammar.operation_name: re.compile(r'[a-z][a-z0-9_.-]{0,63}'),
    grammar.argument_name: re.compile(r'[a-z][a-z0-9_]{0,31}'),
    grammar.segment: re.compile(r'(?!\.{1,2}\Z)[A-Za-z0-9._~-]{1,128}'),
    grammar.media_type: re.compile(
        r'(?=.{3,96}\Z)[a-z][a-z0-9.+-]{0,63}/[a-z][a-z0-9.+-]{0,63}'
    ),
    grammar.header_name: re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,63}'),
    grammar.credential: re.compile(r'[!-~]{16,4096}'),
    grammar.hostname: re.compile(
        r'(?=.{4,253}\Z)(?!.*\.(?:local|localhost|[0-9]+)\Z)'
        r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+'
    ),
}

PROBES = [
    '', 'a', 'A', '0', '-', '.', '..', '...', '_', '~', 'a.b', 'a/b', 'a b',
    'a\n', '\na', 'a\x00', 'a\r\nb', 'é', 'а', 'pr.view', 'pr.review-comments',
    'Issue.View', '9lives', 'x' * 32, 'x' * 33, 'x' * 64, 'x' * 65, 'x' * 128,
    'x' * 129, 'a_b', 'a-b', 'a+b', 'a%2fb', 'a?b', 'a#b', 'a:b', 'a\\b', 'a{b}',
    'application/json', 'application/vnd.github+json', 'text/plain',
    'text/plain; charset=utf-8', 'a/b/c', '/json', 'json/', 'A/b', '*/*',
    'api.example.org', 'gitlab.com', 'localhost', 'a.local', 'a.localhost',
    '127.0.0.1', '1.2.3.4', 'a.1', 'a.b1', '-a.com', 'a-.com', 'a..com',
    'a.com.', '.a.com', 'A.com', 'a_b.com', 'xn--bcher-kva.example',
    'a.' + 'b' * 63 + '.com', 'a.' + 'b' * 64 + '.com', 'a.b:443', 'a.b/c',
    'x' * 16, 'x' * 15, 'x' * 4096, 'x' * 4097, 'tok en' + 'x' * 16,
    'token-0123456789abcdef', 'tok\ten0123456789abcdef', 'X-Api-Version',
    'X_Api', 'x:y',
]  # fmt: skip


@pytest.mark.parametrize(
    'validator', list(ORACLES), ids=lambda validator: validator.__name__
)
def test_validators_accept_exactly_their_documented_language(validator):
    oracle = ORACLES[validator]
    for probe in PROBES:
        expected = oracle.fullmatch(probe) is not None
        try:
            validator(probe)
            accepted = True
        except SecretsError:
            accepted = False
        assert accepted == expected, (validator.__name__, probe)


@pytest.mark.parametrize(
    'validator', list(ORACLES), ids=lambda validator: validator.__name__
)
@pytest.mark.parametrize(
    'value', [None, 1, True, 1.5, [], {}, b'bytes', ('a',)]
)
def test_validators_reject_every_non_string(validator, value):
    with pytest.raises(SecretsError):
        validator(value)


@pytest.mark.parametrize(
    'value,accepted',
    [(0, True), (5, True), (-1, False), (6, False), (True, False),
     (False, False), (1.0, False), ('1', False), (None, False)],
)  # fmt: skip
def test_integer_is_a_true_bounded_integer(value, accepted):
    if accepted:
        assert grammar.integer(value, 0, 5) == value
    else:
        with pytest.raises(SecretsError):
            grammar.integer(value, 0, 5)


@pytest.mark.parametrize(
    'value', ['', 'x' * 9, '\x00', 'a\x00b', '\ud800', 'ééééé', 7, None, b'x']
)
def test_text_is_bounded_utf8_without_nul_or_surrogates(value):
    with pytest.raises(SecretsError):
        grammar.text(value, 8)
    assert grammar.text('éééé', 8) == 'éééé'  # measured in bytes, not chars


def test_exact_keys_is_exact():
    need, may = frozenset({'a'}), frozenset({'b'})
    assert grammar.exact_keys({'a': 1}, need, may) == {'a': 1}
    assert grammar.exact_keys({'a': 1, 'b': 2}, need, may)
    for bad in [{}, {'b': 1}, {'a': 1, 'c': 2}, [], 'a', None, [('a', 1)]]:
        with pytest.raises(SecretsError):
            grammar.exact_keys(bad, need, may)


def test_lowering_is_ascii_only():
    assert grammar.lowered('TauCeti/ÀB') == 'tauceti/Àb'


def test_hex_string_is_lowercase_and_exact_length():
    assert grammar.hex_string('0a' * 16, 32)
    for bad in ['0A' * 16, '0a' * 15, '0a' * 17, 'zz' * 16, 32, None]:
        with pytest.raises(SecretsError):
            grammar.hex_string(bad, 32)


def test_header_values_cannot_fold_or_inject():
    assert grammar.header_value('2026-03-10') == '2026-03-10'
    for bad in ['', ' x', 'x ', 'a\r\nb: c', 'a\nb', 'é', 'x' * 257, '\t']:
        with pytest.raises(SecretsError):
            grammar.header_value(bad)


def test_validators_report_the_callers_fixed_code():
    with pytest.raises(SecretsError) as caught:
        grammar.segment('..', code='invalid_policy')
    assert caught.value.code == 'invalid_policy'


def test_error_codes_are_a_closed_set():
    assert SecretsError('not-a-real-code').code == 'internal_error'
    assert SecretsError('denied', status=99999).status == 0
    assert SecretsError('denied', status=True).status == 0
    assert SecretsError('upstream_rejected', status=404).status == 404
    for code in MESSAGES:
        error = SecretsError(code, detail='host-only context')
        # The public text is the fixed table entry and nothing else.
        assert str(error) == MESSAGES[code]
        assert 'host-only context' not in str(error)
        assert 'host-only context' in error.for_operator()
