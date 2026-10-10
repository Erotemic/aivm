"""The fact-conditioned GitHub PR service, policy schema 1."""

from __future__ import annotations

import copy

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel import github
from aivm_secrets.kernel.github import GitHubSpec, PRFacts
from aivm_secrets.kernel.model import check_effect
from aivm_secrets.kernel.scope import (
    IntRange,
    IntSet,
    StrSet,
    check_arguments,
)
from aivm_secrets.kernel.scope import find as lookup
from aivm_secrets.kernel.source import GH_SOURCE
from tests.secrets_helpers import REPO, github_policy, metadata, must

REPOSITORY = REPO.lower()


def find(scope, name):
    """An operation the test expects the scope to contain."""
    return must(lookup(scope, name))


def spec(**changes):
    return GitHubSpec.parse(github_policy(**changes))


def parse(policy, operation='pr.view', **changes):
    wire = {'operation': operation, 'repository': REPO, 'pr': 13861}
    wire.update(changes)
    return policy.parse_request(wire)


def admit(policy, request):
    """Scope check, as the kernel applies it after parsing."""
    return check_arguments(find(policy.scope(), request.operation), request)


def test_policy_canonicalization_and_digest():
    p = spec()
    q = spec(
        repository='taucetiproject/TAUCETI',
        operations=list(reversed(p.operations)),
        pr_numbers=[13862, 13861],
        author='EROTEMIC',
    )
    assert p == q and p.digest == q.digest
    assert p == GitHubSpec.parse(p.to_dict())
    assert p.service == REPOSITORY and p.client_aliases == ('gh',)
    assert p.credential_source == GH_SOURCE
    assert p.egress.host == 'api.github.com' and p.egress.port == 443
    assert p.egress.authentication == 'bearer'
    assert dict(p.egress.headers) == {
        'X-GitHub-Api-Version': github.API_VERSION
    }


@pytest.mark.parametrize(
    'field,value',
    [
        ('schema', True), ('schema', 2), ('pr_numbers', []), ('pr_numbers', [True]),
        ('pr_numbers', [1, 1]), ('pr_numbers', [0]), ('pr_numbers', [2**31]),
        ('pr_numbers', list(range(1, 514))), ('pr_numbers', '*'),
        ('operations', ['pr.merge']), ('operations', []),
        ('operations', ['pr.view', 'pr.view']), ('operations', [['pr.view']]),
        ('operations', ['pr.*']), ('lifetime_seconds', 3601),
        ('lifetime_seconds', 0), ('lifetime_seconds', 1.0), ('max_requests', False),
        ('max_requests', 1001), ('max_body_bytes', 16385),
        ('author', 'Erotemic/evil'), ('author', ''), ('author', '-leading'),
        ('head_repository', 'https://evil.invalid/r'), ('head_repository', 'x/..'),
        ('repository', 'no-slash'), ('unexpected', 1), ('host', 'evil.invalid'),
    ],
)  # fmt: skip
def test_policy_rejects_bad_shapes(field, value):
    with pytest.raises(SecretsError, match='Invalid policy'):
        spec(**{field: value})


@pytest.mark.parametrize(
    'repo',
    [
        '../repo', 'x/..', 'x/.', 'x/repo/../else', 'x/repo%2felse', 'x/repo?x=y',
        'x/repo#fragment', 'x/repo\\other', 'x/repo\r\nHeader: x',
        'https://api.github.com/x/repo', 'x//repo', 'x/repo:443', 'x/r\x00',
        'х/repo', '-x/repo', 'x' * 40 + '/repo', 'x/' + 'r' * 101, 'x/re po',
    ],
)  # fmt: skip
def test_repository_parser_denies_path_and_host_confusion(repo):
    with pytest.raises(SecretsError):
        parse(spec(), repository=repo)


@pytest.mark.parametrize(
    'extra',
    [
        {'url': 'https://evil.invalid'}, {'headers': {}}, {'principal': 'admin'},
        {'method': 'DELETE'}, {'state': 'closed'}, {'body': 'write on read'},
        {'title': 'write on read'}, {'page': 1}, {'pr': True}, {'pr': -1},
        {'operation': 'api'}, {'operation': ['pr.view']}, {'body': '\ud800'},
        {'operation': 'pr.merge'}, {'owner_uid': 0},
    ],
)  # fmt: skip
def test_request_fields_are_closed(extra):
    """Every one of these is refused by parsing or by the scope check."""
    policy = spec()
    with pytest.raises(SecretsError) as caught:
        admit(policy, parse(policy, **extra))
    assert caught.value.code == 'invalid_request'


@pytest.mark.parametrize(
    'operation,arguments,code',
    [
        ('pr.view', {'repository': 'other/repo'}, 'denied'),
        ('pr.view', {'pr': 9}, 'denied'),
        ('pr.comments', {'page': 0}, 'denied'),
        ('pr.comments', {'page': 10001}, 'denied'),
        ('pr.comment', {}, 'invalid_request'),
        ('pr.comment', {'body': 'b', 'title': 't'}, 'invalid_request'),
        ('pr.edit', {}, 'invalid_request'),
        ('pr.edit', {'title': 't' * 257}, 'denied'),
        ('pr.comment', {'body': 'x' * 16385}, 'invalid_request'),
    ],
)
def test_scope_refuses_out_of_grant_requests(operation, arguments, code):
    policy = spec()
    with pytest.raises(SecretsError) as caught:
        admit(policy, parse(policy, operation, **arguments))
    assert caught.value.code == code


def test_flat_and_generic_request_shapes_are_one_request():
    policy = spec()
    flat = parse(policy, 'pr.comments')
    generic = policy.parse_request(
        {
            'operation': 'pr.comments',
            'arguments': {'repository': REPO, 'pr': 13861},
        }
    )
    explicit = parse(policy, 'pr.comments', page=1, repository=REPOSITORY)
    assert flat == generic == explicit and flat.digest == generic.digest
    assert dict(flat.arguments) == {
        'page': 1,
        'pr': 13861,
        'repository': REPOSITORY,
    }
    assert 'page' not in dict(parse(policy, 'pr.view').arguments)
    assert admit(policy, flat) == 0
    assert admit(policy, parse(policy, 'pr.comment', body='héllo')) == 6


def test_scope_is_exactly_the_policy():
    policy = spec(
        operations=['pr.view', 'pr.comments', 'pr.edit'], pr_numbers=[7, 9]
    )
    scope = policy.scope()
    assert [op.name for op in scope] == ['pr.comments', 'pr.edit', 'pr.view']
    assert [op.write for op in scope] == [False, True, False]
    for operation in scope:
        parameters = dict(operation.parameters)
        assert parameters['pr'] == IntSet((7, 9))
        assert parameters['repository'] == StrSet((REPOSITORY,))
        assert ('page' in parameters) == (operation.name == 'pr.comments')
    assert dict(find(scope, 'pr.comments').parameters)['page'] == IntRange(
        1, 10000
    )
    edit = {
        f.name: (f.max_bytes, f.required) for f in find(scope, 'pr.edit').fields
    }
    assert edit == {'body': (16384, False), 'title': (256, False)}


@pytest.mark.parametrize(
    'operation,method,suffix',
    [
        ('pr.diff', 'GET', '/pulls/13861'),
        ('pr.comments', 'GET', '/issues/13861/comments?per_page=100&page=1'),
        ('pr.reviews', 'GET', '/pulls/13861/reviews?per_page=100&page=1'),
        (
            'pr.review-comments',
            'GET',
            '/pulls/13861/comments?per_page=100&page=1',
        ),
        (
            'pr.checks',
            'GET',
            '/commits/' + 'a' * 40 + '/check-runs?per_page=100&page=1',
        ),
        ('pr.comment', 'POST', '/issues/13861/comments'),
        ('pr.edit', 'PATCH', '/pulls/13861'),
    ],
)
def test_effect_routes_are_constructed_not_taken_from_provider(
    operation, method, suffix
):
    policy = spec()
    arguments = {'body': 'A precise update.'} if method != 'GET' else {}
    request = parse(policy, operation, **arguments)
    facts = metadata()
    # Provider-supplied URLs are data. None of them can become a route.
    facts['url'] = 'https://attacker.invalid/token-dump'
    facts['_links'] = {'self': {'href': 'https://attacker.invalid/x'}}
    facts['head']['repo']['url'] = 'https://attacker.invalid/y'
    effect = check_effect(policy.final(request, facts))
    assert effect.method == method
    assert effect.target == '/repos/' + REPOSITORY + suffix
    assert 'attacker' not in repr(effect)
    if method != 'GET':
        assert effect.body == (('body', 'A precise update.'),)
    assert effect.accept == (
        github.DIFF_MEDIA if operation == 'pr.diff' else github.JSON_MEDIA
    )
    assert effect.response == ('text' if operation == 'pr.diff' else 'json')
    preflight = check_effect(policy.preflight(request))
    assert (preflight.method, preflight.target) == (
        'GET',
        f'/repos/{REPOSITORY}/pulls/13861',
    )


def test_view_has_no_second_effect_and_edit_sends_only_what_was_given():
    policy = spec()
    assert policy.final(parse(policy), metadata()) is None
    both = policy.final(
        parse(policy, 'pr.edit', body='B', title='T'), metadata()
    )
    assert both.body == (('body', 'B'), ('title', 'T'))
    title = policy.final(parse(policy, 'pr.edit', title='T'), metadata())
    assert title.body == (('title', 'T'),)


def test_paging_reaches_the_route_and_checks_use_the_validated_sha():
    policy = spec()
    page = policy.final(parse(policy, 'pr.reviews', page=7), metadata())
    assert page.target.endswith('/reviews?per_page=100&page=7')
    facts = metadata()
    facts['head']['sha'] = 'ABCDEF' + '0' * 34
    checks = policy.final(parse(policy, 'pr.checks'), facts)
    assert '/commits/abcdef' + '0' * 34 + '/check-runs' in checks.target


@pytest.mark.parametrize(
    'mutate',
    [
        lambda f: f.update(number=9),
        lambda f: f.update(number='13861'),
        lambda f: f['user'].update(login='other'),
        lambda f: f['head']['repo'].update(full_name='Other/TauCeti'),
        lambda f: f['head'].update(repo=None),  # deleted fork
        lambda f: f['base']['repo'].update(full_name='Other/TauCeti'),
        lambda f: f['head'].update(sha='not-a-sha'),
        lambda f: f['head'].update(sha='a' * 39),
        lambda f: f['head'].update(sha='../../orgs/x'),
        lambda f: f['head'].update(sha=None),
        lambda f: f.pop('user'),
        lambda f: f.pop('base'),
        lambda f: f['head']['repo'].update(full_name='a/b/c'),
    ],
)
def test_fresh_metadata_must_match_the_grant(mutate):
    """The second denial class of AUTH-01: facts gate every later effect."""
    policy = spec()
    facts = copy.deepcopy(metadata())
    mutate(facts)
    for operation in ('pr.view', 'pr.diff', 'pr.checks'):
        with pytest.raises(SecretsError) as caught:
            policy.final(parse(policy, operation), facts)
        assert caught.value.code == 'resource_mismatch'


@pytest.mark.parametrize('facts', [None, [], 'pr', 7, {}, {'number': 13861}])
def test_malformed_provider_metadata_is_a_mismatch_not_a_crash(facts):
    with pytest.raises(SecretsError) as caught:
        PRFacts.parse(facts)
    assert caught.value.code == 'resource_mismatch'


def test_facts_fold_case_like_the_policy():
    facts = metadata()
    facts['user']['login'] = 'EROTEMIC'
    facts['base']['repo']['full_name'] = 'TAUCETIPROJECT/tauceti'
    policy = spec()
    assert policy.final(parse(policy, 'pr.diff'), facts) is not None


@pytest.mark.parametrize(
    'operation', ['pr.comments', 'pr.reviews', 'pr.review-comments']
)
def test_pagination_is_explicit_not_silently_complete(operation):
    policy = spec()
    request = parse(policy, operation, page=2)
    full = policy.reply_meta(request, [{'id': i} for i in range(100)])
    assert full == {
        'pagination': {'page': 2, 'per_page': 100, 'possibly_more': True}
    }
    partial = policy.reply_meta(request, [{'id': 1}])
    assert partial['pagination']['possibly_more'] is False
    for bad in ([{}] * 101, {'not': 'a list'}, None):
        with pytest.raises(SecretsError) as caught:
            policy.reply_meta(request, bad)
        assert caught.value.code == 'upstream_response'


def test_check_run_pagination_and_unpaged_operations():
    policy = spec()
    checks = parse(policy, 'pr.checks')
    meta = policy.reply_meta(checks, {'check_runs': [{}] * 100})
    assert meta['pagination']['possibly_more'] is True
    for bad in ([], {'check_runs': 'x'}, {'check_runs': [{}] * 101}):
        with pytest.raises(SecretsError):
            policy.reply_meta(checks, bad)
    assert policy.reply_meta(parse(policy), metadata()) is None


def test_a_generic_request_without_a_repository_is_incomplete_not_defaulted():
    policy = spec()
    request = policy.parse_request(
        {'operation': 'pr.view', 'arguments': {'pr': 13861}}
    )
    assert dict(request.arguments) == {'pr': 13861}
    with pytest.raises(SecretsError) as caught:
        admit(policy, request)
    assert caught.value.code == 'invalid_request'
