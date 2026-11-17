"""Closed value types: requests, effects and destinations (ROUTE-01)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel.model import (
    RESERVED_HEADERS,
    Binding,
    Claims,
    Effect,
    Egress,
    Request,
    check_effect,
    parse_headers,
)

BINDING = Binding(1000, 'principal', 'vm', 'c' * 32)
CLAIMS = Claims(BINDING, 'a' * 64, 'b' * 32, 100, 200)


def test_claims_round_trip_and_are_strict():
    assert Claims.parse(CLAIMS.to_dict()) == CLAIMS
    assert Binding.parse(BINDING.to_dict()) == BINDING
    good = CLAIMS.to_dict()
    for key, value in [
        ('policy_digest', 'A' * 64),
        ('policy_digest', 'a' * 63),
        ('grant_id', 'b' * 31),
        ('issued_at', -1),
        ('issued_at', True),
        ('expires_at', 100),  # must be strictly after issue
        ('expires_at', 100 + 3601),  # never longer than one hour
        ('binding', {**BINDING.to_dict(), 'owner_uid': 2**32}),
        ('binding', {**BINDING.to_dict(), 'admin': True}),
        ('binding', {**BINDING.to_dict(), 'vm': ''}),
        ('extra', 1),
    ]:
        with pytest.raises(SecretsError):
            Claims.parse({**good, key: value})


def test_requests_are_canonical_and_cannot_carry_routing():
    one = Request.parse(
        {'operation': 'issue.view', 'arguments': {'b': 2, 'a': 'x'}}
    )
    two = Request.parse(
        {'arguments': {'a': 'x', 'b': 2}, 'operation': 'issue.view'}
    )
    assert one == two and one.digest == two.digest
    assert one.arguments == (('a', 'x'), ('b', 2))
    assert one.get('b') == 2 and one.get('missing') is None
    assert Request.parse({'operation': 'x'}).arguments == ()
    # Argument values stay out of reprs, tracebacks and log lines.
    assert 'x' not in repr(one).replace('issue.view', '')


@pytest.mark.parametrize(
    'bad',
    [
        {'operation': 'issue.view', 'url': 'https://evil.invalid'},
        {'operation': 'issue.view', 'method': 'DELETE'},
        {'operation': 'issue.view', 'headers': {}},
        {'operation': 'Issue.View'},
        {'operation': ['issue.view']},
        {'operation': 'x', 'arguments': []},
        {'operation': 'x', 'arguments': {'A': 1}},
        {'operation': 'x', 'arguments': {'a-b': 1}},
        {'operation': 'x', 'arguments': {'a': True}},
        {'operation': 'x', 'arguments': {'a': None}},
        {'operation': 'x', 'arguments': {'a': 1.5}},
        {'operation': 'x', 'arguments': {'a': -1}},
        {'operation': 'x', 'arguments': {'a': 2**31}},
        {'operation': 'x', 'arguments': {'a': ''}},
        {'operation': 'x', 'arguments': {'a': 'x' * 16385}},
        {'operation': 'x', 'arguments': {'a': '\ud800'}},
        {'operation': 'x', 'arguments': {'a': ['nested']}},
        {'operation': 'x', 'arguments': {'a': {'nested': 1}}},
        {'operation': 'x', 'arguments': {f'a{i}': 1 for i in range(17)}},
        {'arguments': {}},
        [],
        None,
    ],
)
def test_request_fields_are_closed(bad):
    with pytest.raises(SecretsError) as caught:
        Request.parse(bad)
    assert caught.value.code == 'invalid_request'


GOOD = Effect('GET', '/v1/issues/23', (('page', '2'),))


def test_effect_target_needs_no_escaping():
    assert GOOD.target == '/v1/issues/23?page=2'
    assert Effect('GET', '/v1').target == '/v1'
    many = Effect('GET', '/v1', (('per_page', '100'), ('page', '3')))
    assert many.target == '/v1?per_page=100&page=3'
    assert check_effect(GOOD) is GOOD
    body = (('body', 'héllo\n"quoted"'),)
    assert check_effect(Effect('POST', '/v1/c', body=body)).is_write
    assert 'héllo' not in repr(Effect('POST', '/v1/c', body=body))


@pytest.mark.parametrize(
    'change',
    [
        {'method': 'DELETE'},
        {'method': 'PUT'},
        {'method': 'get'},
        {'method': 'CONNECT'},
        {'path': 'v1/issues'},
        {'path': '/'},
        {'path': ''},
        {'path': '//evil.invalid/x'},
        {'path': '/v1//issues'},
        {'path': '/v1/../admin'},
        {'path': '/v1/./x'},
        {'path': '/v1/issues/'},
        {'path': '/v1/a b'},
        {'path': '/v1/a%2fb'},
        {'path': '/v1/a?x=y'},
        {'path': '/v1/a#frag'},
        {'path': '/v1/a\r\nHost: evil.invalid'},
        {'path': '/v1/a\\b'},
        {'path': '/https://evil.invalid'},
        {'path': '/v1/a:b'},
        {'path': '/v1/a@b'},
        {'path': '/' + 'a' * 2000},
        {'query': (('page', '1'), ('page', '2'))},
        {'query': (('page', '1&admin=1'),)},
        {'query': (('page', ''),)},
        {'query': (('Page', '1'),)},
        {'query': (('p', '1 2'),)},
        {'query': (('p', 'a=b'),)},
        {'accept': 'application/json\r\nX-Evil: 1'},
        {'accept': '*/*'},
        {'accept': 'application/json; q=1'},
        {'response': 'binary'},
        {'body': (('body', 'x'),)},  # a GET never has a body
        {'method': 'POST'},  # a write always has one
        {'method': 'POST', 'body': ()},
        {'method': 'POST', 'body': (('body', ''),)},
        {'method': 'POST', 'body': (('body', 'a\x00b'),)},
        {'method': 'POST', 'body': (('body', 'x'), ('body', 'y'))},
        {'method': 'POST', 'body': (('Body', 'x'),)},
        {'method': 'PATCH', 'body': (('body', 7),)},
    ],
)
def test_effect_grammar_refuses_rather_than_repairs(change):
    with pytest.raises(SecretsError) as caught:
        check_effect(replace(GOOD, **change))
    assert caught.value.code == 'denied'


@pytest.mark.parametrize(
    'value',
    [
        None,
        {},
        ('GET', '/v1'),
        'GET /v1',
        type('Fake', (), {'method': 'GET'})(),
    ],
)
def test_only_a_real_effect_is_an_effect(value):
    with pytest.raises(SecretsError):
        check_effect(value)


def test_egress_pins_are_canonical():
    plain = Egress.parse('api.example.org', 'bearer', {}, {})
    assert plain == Egress('api.example.org')
    assert plain.pins() == {'port': 443}
    pinned = Egress.parse(
        'git.corp.example',
        'x-api-key',
        {'port': 8443, 'address': '10.1.2.3', 'ca_file': '/etc/ssl/corp.pem'},
        {'X-Api-Version': '2026-03-10'},
    )
    assert pinned.pins() == {
        'port': 8443,
        'address': '10.1.2.3',
        'ca_file': '/etc/ssl/corp.pem',
    }
    assert pinned.headers == (('X-Api-Version', '2026-03-10'),)
    assert (
        Egress.parse('a.example', 'bearer', {'address': '::1'}, {}).address
        == '::1'
    )


@pytest.mark.parametrize(
    'host,auth,pins',
    [
        ('localhost', 'bearer', {}),
        ('127.0.0.1', 'bearer', {}),
        ('api.example.org:443', 'bearer', {}),
        ('API.example.org', 'bearer', {}),
        ('api.example.org', 'none', {}),
        ('api.example.org', 'basic', {}),
        ('api.example.org', ['bearer'], {}),
        ('api.example.org', 'bearer', {'port': 0}),
        ('api.example.org', 'bearer', {'port': 65536}),
        ('api.example.org', 'bearer', {'port': '443'}),
        ('api.example.org', 'bearer', {'address': 'evil.invalid'}),
        ('api.example.org', 'bearer', {'address': '127.1'}),
        ('api.example.org', 'bearer', {'address': '010.1.2.3'}),
        ('api.example.org', 'bearer', {'address': '0:0:0:0:0:0:0:1'}),
        ('api.example.org', 'bearer', {'address': '10.0.0.1:443'}),
        ('api.example.org', 'bearer', {'ca_file': 'relative.pem'}),
        ('api.example.org', 'bearer', {'ca_file': '/a/../b.pem'}),
        ('api.example.org', 'bearer', {'proxy': 'http://evil.invalid'}),
        ('api.example.org', 'bearer', {'verify': False}),
        ('api.example.org', 'bearer', []),
    ],
)
def test_untrusted_egress_is_rejected(host, auth, pins):
    with pytest.raises(SecretsError) as caught:
        Egress.parse(host, auth, pins, {})
    assert caught.value.code == 'invalid_policy'


@pytest.mark.parametrize('name', sorted(RESERVED_HEADERS))
def test_a_manifest_cannot_restate_an_executor_header(name):
    for spelling in (name, name.title(), name.upper()):
        with pytest.raises(SecretsError):
            parse_headers({spelling: 'value'})


@pytest.mark.parametrize(
    'headers',
    [
        {'X-Ok': 'a\r\nAuthorization: Bearer stolen'},
        {'X-Ok': ''},
        {'X Bad': 'v'},
        {'X-Ok:': 'v'},
        {'Proxy-Anything': 'v'},
        {'Sec-Fetch-Site': 'v'},
        {'X-Forwarded-For': '1.2.3.4'},
        {'X-Dup': 'a', 'x-dup': 'b'},
        {f'X-H{i}': 'v' for i in range(9)},
        {'X-Ok': 7},
        ['X-Ok'],
    ],
)
def test_static_headers_cannot_inject_or_impersonate(headers):
    with pytest.raises(SecretsError):
        parse_headers(headers)
