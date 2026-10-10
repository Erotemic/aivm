from dataclasses import replace
from itertools import product

import pytest

from aivm_secrets.core import (Binding, Claims, Policy, PRFacts, Request, State,
                               authorize, effect_route, is_attenuation, metadata_route)
from aivm_secrets.errors import SecretsError
from aivm_secrets.wire import loads
from tests.secrets_helpers import metadata, policy_data


def test_policy_canonicalization_and_digest():
    p = Policy.parse(policy_data())
    q = Policy.parse(policy_data(repository='taucetiproject/TAUCETI',
                                 operations=list(reversed(p.operations)),
                                 pr_numbers=[13862, 13861]))
    assert p == q
    assert p.digest == q.digest
    assert p == Policy.parse(p.to_dict())


@pytest.mark.parametrize('field,value', [
    ('schema', True), ('schema', 2), ('pr_numbers', []), ('pr_numbers', [True]),
    ('pr_numbers', [1, 1]), ('pr_numbers', [0]), ('pr_numbers', [2**31]),
    ('operations', ['pr.merge']), ('operations', []), ('operations', ['pr.view', 'pr.view']),
    ('operations', [['pr.view']]), ('lifetime_seconds', 3601), ('lifetime_seconds', 0),
    ('lifetime_seconds', 1.0), ('max_requests', False), ('max_requests', 1001),
    ('max_body_bytes', 16385), ('author', 'Erotemic/evil'),
    ('head_repository', 'https://evil.invalid/r'), ('unexpected', 1),
])
def test_policy_rejects_bad_shapes(field, value):
    with pytest.raises(SecretsError, match='Invalid policy'):
        Policy.parse(policy_data(**{field: value}))


@pytest.mark.parametrize('repo', ['../repo', 'x/..', 'x/.', 'x/repo/../else',
                                  'x/repo%2felse', 'x/repo?x=y', 'x/repo#fragment',
                                  'x/repo\\other', 'x/repo\r\nHeader: x',
                                  'https://api.github.com/x/repo', 'x//repo',
                                  'x/repo:443', 'x/r\x00', '\u0445/repo'])
def test_repository_parser_denies_path_and_host_confusion(repo):
    with pytest.raises(SecretsError):
        Request.parse({'operation': 'pr.view', 'repository': repo, 'pr': 1})


@pytest.mark.parametrize('extra', [
    {'url': 'https://evil.invalid'}, {'headers': {}}, {'principal': 'admin'},
    {'method': 'DELETE'}, {'state': 'closed'}, {'body': 'write on read'},
    {'title': 'write on read'}, {'page': 1}, {'pr': True}, {'pr': -1},
    {'operation': 'api'}, {'operation': ['pr.view']}, {'body': '\ud800'},
])
def test_request_fields_are_closed(extra):
    data = {'operation': 'pr.view', 'repository': 'a/b', 'pr': 1}
    data.update(extra)
    with pytest.raises(SecretsError):
        Request.parse(data)


@pytest.mark.parametrize('data', [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                                  b'{"x":-Infinity}', b'{"x":"\xff"}', b'[] trailing',
                                  b'[' * 2000 + b']' * 2000],
                         ids=['duplicate', 'nan', 'infinity', 'negative-infinity',
                              'invalid-utf8', 'trailing', 'deep-nesting'])
def test_wire_strict_json(data):
    with pytest.raises(SecretsError):
        loads(data)


def test_attenuation_contract():
    parent = Policy.parse(policy_data())
    child = replace(parent, pr_numbers=(13861,), operations=('pr.view',), max_requests=2)
    assert is_attenuation(child, parent)
    assert is_attenuation(child, child)
    assert not is_attenuation(parent, child)
    for field, value in [('repository', 'other/repo'), ('author', 'other'),
                         ('head_repository', 'other/fork'), ('pr_numbers', (9,)),
                         ('max_requests', parent.max_requests + 1),
                         ('lifetime_seconds', parent.lifetime_seconds + 1),
                         ('max_body_bytes', parent.max_body_bytes + 1)]:
        assert not is_attenuation(replace(child, **{field: value}), parent)


def test_authorization_matches_independent_bounded_oracle():
    policy = Policy.parse(policy_data(operations=['pr.view', 'pr.comment'], max_requests=2))
    binding = Binding(1000, 'principal-a', 'vm-a', 'channel-a')
    claims = Claims(binding, policy.digest, 'a' * 32, 100, 200)
    # 2^8 cases cover interactions, not only one-condition-at-a-time examples.
    for active, bound, live, time_ok, quota, repo_ok, pr_ok, write_ok in product([False, True], repeat=8):
        request = Request.parse({'operation': 'pr.comment',
                                 'repository': policy.repository if repo_ok else 'other/repo',
                                 'pr': 13861 if pr_ok else 9, 'body': 'proof repaired'})
        state = State(active, 1 if quota else 2)
        got = None
        try:
            got = authorize(policy, claims, binding if bound else replace(binding, channel='other'),
                            request, state, now=150 if time_ok else 200,
                            monotonic_live=live, allow_writes=write_ok)
        except SecretsError:
            pass
        expected = all([active, bound, live, time_ok, quota, repo_ok, pr_ok, write_ok])
        assert (got is not None) == expected
        if got is not None:
            assert got.used == state.used + 1 and got.active


@pytest.mark.parametrize('now,accepted', [(99, False), (100, True), (199, True), (200, False)])
def test_half_open_validity(now, accepted):
    policy = Policy.parse(policy_data())
    binding = Binding(1000, 'p', 'v', 'c')
    claims = Claims(binding, policy.digest, 'a' * 32, 100, 200)
    request = Request.parse({'operation': 'pr.view', 'repository': policy.repository, 'pr': 13861})
    if accepted:
        assert authorize(policy, claims, binding, request, State(), now=now,
                         monotonic_live=True, allow_writes=False).used == 1
    else:
        with pytest.raises(SecretsError):
            authorize(policy, claims, binding, request, State(), now=now,
                      monotonic_live=True, allow_writes=False)


@pytest.mark.parametrize('operation,method,suffix', [
    ('pr.diff', 'GET', '/pulls/13861'),
    ('pr.comments', 'GET', '/issues/13861/comments?per_page=100&page=1'),
    ('pr.reviews', 'GET', '/pulls/13861/reviews?per_page=100&page=1'),
    ('pr.review-comments', 'GET', '/pulls/13861/comments?per_page=100&page=1'),
    ('pr.checks', 'GET', '/commits/' + 'a' * 40 + '/check-runs?per_page=100&page=1'),
    ('pr.comment', 'POST', '/issues/13861/comments'),
    ('pr.edit', 'PATCH', '/pulls/13861'),
])
def test_effect_routes_are_constructed_not_taken_from_provider(operation, method, suffix):
    policy = Policy.parse(policy_data())
    args = {'operation': operation, 'repository': policy.repository, 'pr': 13861}
    if operation in {'pr.comment', 'pr.edit'}:
        args['body'] = 'A precise update.'
    request = Request.parse(args)
    data = metadata()
    data['url'] = 'https://attacker.invalid/token-dump'
    route = effect_route(policy, request, PRFacts.parse(data))
    assert route.method == method
    assert route.path == '/repos/' + policy.repository + suffix
    if route.body:
        assert route.body == {'body': args['body']}
    assert metadata_route(request).method == 'GET'
