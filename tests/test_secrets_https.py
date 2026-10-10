"""Declarative HTTPS services, policy schema 2 (PLUGIN-01, ROUTE-01)."""

from __future__ import annotations

import copy

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel.https import HTTPSpec
from aivm_secrets.kernel.model import Effect, Request, check_effect
from aivm_secrets.kernel.scope import IntRange, IntSet, check_arguments
from aivm_secrets.kernel.scope import find as lookup
from tests.secrets_helpers import https_policy, must


def find(scope, name):
    """An operation the test expects the scope to contain."""
    return must(lookup(scope, name))


def spec(**changes):
    return HTTPSpec.parse(https_policy(**changes))


def one(**operation):
    base = {'name': 'op', 'method': 'GET', 'path': '/v1/x'}
    base.update(operation)
    return spec(operations=[base]).operations[0]


def request(operation, **arguments):
    return Request(operation, tuple(sorted(arguments.items())))


def test_http_policy_is_canonical_and_uses_non_github_credential_source():
    policy = spec()
    reordered = https_policy(
        operations=list(reversed(https_policy()['operations']))
    )
    assert HTTPSpec.parse(reordered).digest == policy.digest
    assert HTTPSpec.parse(policy.to_dict()) == policy
    assert policy.service == 'demo-service'
    assert policy.credential_source['argv'] == ['mytool', 'auth', 'print-token']
    assert policy.egress.host == 'api.example.org'
    assert policy.egress.authentication == 'x-api-key'
    assert [op.name for op in policy.operations] == [
        'issue.comment', 'issue.list', 'issue.view', 'profile.read',
    ]  # fmt: skip
    assert policy.client_aliases == ()


def test_every_policy_field_changes_the_digest():
    base = spec().digest
    changes = [
        {'service': 'other'},
        {'host': 'api.example.com'},
        {'authentication': 'bearer'},
        {'egress': {'port': 8443}},
        {'egress': {'address': '10.0.0.1'}},
        {'egress': {'ca_file': '/etc/ssl/x.pem'}},
        {'headers': {'X-Api-Version': '1'}},
        {'credential_source': {'kind': 'file', 'path': '/x/token'}},
        {'lifetime_seconds': 1799},
        {'max_requests': 4},
        {'max_body_bytes': 99},
    ]
    digests = {spec(**change).digest for change in changes}
    assert base not in digests and len(digests) == len(changes)
    operations = https_policy()['operations']
    for index, key, value in [
        (1, 'parameters', {'issue': [23]}),
        (1, 'path', '/v2/issues/{issue}'),
        (2, 'query', {'state': 'closed', 'page': '{page}'}),
        (3, 'body_fields', {'body': 99}),
        (3, 'method', 'PATCH'),
        (0, 'response', 'text'),
        (0, 'accept', 'application/vnd.api+json'),
    ]:
        edited = copy.deepcopy(operations)
        edited[index][key] = value
        assert spec(operations=edited).digest != base


def test_scope_is_the_authorization_view_of_the_manifest():
    scope = spec().scope()
    view = find(scope, 'issue.view')
    assert view.write is False and dict(view.parameters) == {
        'issue': IntSet((23, 24))
    }
    listing = find(scope, 'issue.list')
    assert dict(listing.parameters) == {'page': IntRange(1, 50)}
    comment = find(scope, 'issue.comment')
    assert comment.write is True
    assert [(f.name, f.max_bytes, f.required) for f in comment.fields] == [
        ('body', 100, True)
    ]
    assert lookup(scope, 'issue.delete') is None


def test_effects_are_built_only_from_the_template_and_allowlists():
    policy = spec()
    view = policy.final(request('issue.view', issue=23), None)
    assert view == Effect('GET', '/v1/issues/23')
    listing = policy.final(request('issue.list', page=7), None)
    assert listing.target == '/v1/issues?page=7&state=open'
    comment = policy.final(
        request('issue.comment', issue=24, body='héllo'), None
    )
    assert (comment.method, comment.path) == ('POST', '/v1/issues/24/comments')
    assert comment.body == (('body', 'héllo'),)
    for effect in (view, listing, comment):
        assert check_effect(effect) is effect
    # Schema 2 has no fact-conditioned operations.
    assert policy.preflight(request('issue.view', issue=23)) is None
    assert policy.reply_meta(request('issue.view', issue=23), {}) is None
    with pytest.raises(SecretsError):
        policy.final(request('issue.delete', issue=23), None)


def test_every_scope_admitted_request_compiles_to_a_wellformed_effect():
    """ROUTE-01, exhaustively for one manifest: admission implies routability."""
    policy = spec()
    scope = policy.scope()
    seen = set()
    for issue in (23, 24):
        for body in ('x', 'é' * 50):
            for candidate in (
                request('issue.view', issue=issue),
                request('issue.comment', issue=issue, body=body),
            ):
                check_arguments(find(scope, candidate.operation), candidate)
                effect = check_effect(policy.final(candidate, None))
                assert effect.is_write == find(scope, candidate.operation).write
                seen.add(effect.target)
    for page in range(1, 51):
        candidate = request('issue.list', page=page)
        check_arguments(find(scope, 'issue.list'), candidate)
        seen.add(check_effect(policy.final(candidate, None)).target)
    assert len(seen) == 2 + 2 + 50
    assert all(target.startswith('/v1/') for target in seen)


def test_string_parameters_and_response_modes():
    op = one(
        path='/v1/{org}/repos/{repo}/raw',
        parameters={'org': ['acme'], 'repo': ['a.b', 'c_d', 'e-f~g']},
        response='text',
    )
    assert op.accept == 'text/plain'
    effect = op.effect(request('op', org='acme', repo='e-f~g'))
    assert (
        effect.path == '/v1/acme/repos/e-f~g/raw' and effect.response == 'text'
    )
    assert one().accept == 'application/json'
    assert (
        one(accept='application/vnd.api+json').accept
        == 'application/vnd.api+json'
    )


@pytest.mark.parametrize(
    'change',
    [
        {'adapter': 'exec'},
        {'adapter': 'http'},
        {'schema': 3},
        {'schema': True},
        {'host': 'localhost'},
        {'host': 'localhost.local'},
        {'host': '127.0.0.1'},
        {'host': 'api.example.org:443'},
        {'host': 'https://api.example.org'},
        {'host': 'api.example.org/path'},
        {'authentication': 'none'},
        {'authentication': 'basic'},
        {'service': 'Bad Name'},
        {'egress': {'address': 'attacker.invalid'}},
        {'egress': {'proxy': 'http://attacker.invalid'}},
        {'headers': {'Authorization': 'Bearer x'}},
        {'headers': {'Host': 'attacker.invalid'}},
        {'credential_source': {'kind': 'shell', 'script': 'x'}},
        {'operations': []},
        {'operations': 'all'},
        {
            'operations': [
                {'name': f'o{i}', 'method': 'GET', 'path': '/x'}
                for i in range(65)
            ]
        },
        {'lifetime_seconds': 3601},
        {'lifetime_seconds': 0},
        {'max_requests': 1001},
        {'max_body_bytes': 16385},
        {'unexpected': 1},
        {'allow_writes': True},
    ],
)
def test_untrusted_egress_templates_rejected(change):
    with pytest.raises(SecretsError) as caught:
        spec(**change)
    assert caught.value.code == 'invalid_policy'


@pytest.mark.parametrize(
    'operation',
    [
        {'method': 'DELETE'},
        {'method': 'PUT'},
        {'method': 'get'},
        {'path': '/v1/../admin'},
        {'path': '/v1//x'},
        {'path': 'v1/x'},
        {'path': '/'},
        {'path': '/https://attacker.invalid'},
        {'path': '/v1/x?admin=1'},
        {'path': '/v1/x#frag'},
        {'path': '/v1/%2e%2e/x'},
        {'path': '/v1/{a}{b}', 'parameters': {'a': [1], 'b': [2]}},
        {'path': '/v1/x{a}', 'parameters': {'a': [1]}},
        {'path': '/v1/{A}', 'parameters': {'A': [1]}},
        {'path': '/v1/{a}'},  # placeholder with no allowlist
        {'parameters': {'a': [1]}},  # allowlist that is never used
        {'path': '/{target}', 'parameters': {'target': ['ok', '../unsafe']}},
        {'path': '/{target}', 'parameters': {'target': ['a/b']}},
        {'path': '/{target}', 'parameters': {'target': ['a?b']}},
        {'path': '/{target}', 'parameters': {'target': ['..']}},
        {'path': '/{target}', 'parameters': {'target': []}},
        {'path': '/{target}', 'parameters': {'target': '*'}},
        {'path': '/{target}', 'parameters': {'target': list(range(257))}},
        {'query': {'q': 'a b'}},
        {'query': {'q': 'a&b=c'}},
        {'query': {'q': '{missing}'}},
        {'query': {'Q': 'x'}},
        {'query': {'q': 7}},
        {'query': ['q']},
        {'body_fields': {'body': 10}},  # a GET never has a body
        {'method': 'POST'},  # a write always declares one
        {'method': 'POST', 'body_fields': {'body': 0}},
        {'method': 'POST', 'body_fields': {'body': 16385}},
        {'method': 'POST', 'body_fields': {'Body': 10}},
        {'method': 'POST', 'path': '/v1/{a}', 'parameters': {'a': [1]},
         'body_fields': {'a': 10}},
        {'response': 'binary'},
        {'accept': 'application/json, */*'},
        {'name': 'Bad Name'},
        {'headers': {'X': 'y'}},
        {'url': 'https://attacker.invalid'},
    ],
)  # fmt: skip
def test_untrusted_operation_templates_rejected(operation):
    with pytest.raises(SecretsError) as caught:
        one(**operation)
    assert caught.value.code == 'invalid_policy'


def test_operation_names_are_unique():
    duplicate = [
        {'name': 'same', 'method': 'GET', 'path': '/a'},
        {'name': 'same', 'method': 'GET', 'path': '/b'},
    ]
    with pytest.raises(SecretsError):
        spec(operations=duplicate)


def test_request_parsing_is_the_generic_shape_only():
    policy = spec()
    parsed = policy.parse_request(
        {'operation': 'issue.view', 'arguments': {'issue': 23}}
    )
    assert parsed == request('issue.view', issue=23)
    for bad in [
        {'operation': 'issue.view', 'issue': 23},
        {
            'operation': 'issue.view',
            'arguments': {'issue': 23},
            'method': 'DELETE',
        },
    ]:
        with pytest.raises(SecretsError):
            policy.parse_request(bad)
