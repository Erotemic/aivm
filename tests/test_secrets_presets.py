"""Built-in manifests: GitHub pull requests as data, not as code.

Policy ``schema: 1`` is shorthand. These tests hold the preset to that: its
expansion is an ordinary schema-2 manifest, byte-for-byte reproducible from
a file an operator could have written, and everything GitHub-specific about
it -- fact checks, case folding, the commit a check run belongs to, the
``gh`` command table -- is expressed in that manifest.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel import presets
from aivm_secrets.kernel.https import HTTPSpec
from aivm_secrets.kernel.model import check_effect
from aivm_secrets.kernel.scope import (
    IntRange,
    IntSet,
    StrSet,
    check_arguments,
)
from aivm_secrets.kernel.scope import find as lookup
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import REPO, github_policy, metadata, must

REPOSITORY = REPO.lower()
EXAMPLES = Path(__file__).resolve().parents[1] / 'docs' / 'examples'


def spec(**changes):
    return parse_policy(github_policy(**changes))


def parse(policy, operation='pr.view', **changes):
    arguments = {'repository': REPO, 'pr': 13861}
    arguments.update(changes)
    return policy.parse_request(
        {'operation': operation, 'arguments': arguments}
    )


def admit(policy, request):
    """Scope check, as the kernel applies it after parsing."""
    operation = lookup(policy.scope(), request.operation)
    if operation is None:
        raise SecretsError('denied')
    return check_arguments(operation, request)


def find(scope, name):
    return must(lookup(scope, name))


# -- the preset is data ------------------------------------------------------


def test_schema_1_is_exactly_its_schema_2_expansion():
    policy = github_policy()
    manifest = presets.github_pr(policy)
    assert manifest['schema'] == 2 and manifest['adapter'] == 'https'
    direct = HTTPSpec.parse(manifest)
    assert parse_policy(policy) == direct
    # The expansion survives a trip through text, like a file would.
    assert parse_policy(json.loads(json.dumps(manifest))) == direct
    assert type(direct) is HTTPSpec


def test_the_shipped_manifest_file_is_the_preset():
    """An operator-readable file gives the same session as the shorthand."""
    written = json.loads((EXAMPLES / 'aivm-secrets-github-pr.json').read_text())
    shorthand = {
        'schema': 1,
        'repository': 'example-org/example-repo',
        'pr_numbers': [7, 8],
        'operations': list(presets.PR_OPERATIONS),
        'author': 'octocat',
        'head_repository': 'octocat/example-repo',
    }
    assert parse_policy(written).digest == parse_policy(shorthand).digest


def test_policy_canonicalization_and_digest():
    p = spec()
    q = spec(
        repository='taucetiproject/TAUCETI',
        operations=list(reversed(github_policy()['operations'])),
        pr_numbers=[13862, 13861],
        author='EROTEMIC',
    )
    assert p == q and p.digest == q.digest
    assert p == HTTPSpec.parse(p.to_dict())
    assert p.service == 'github-pr' and p.client_aliases == ('gh',)
    assert p.credential_source == presets.GH_SOURCE
    assert p.egress.host == 'api.github.com' and p.egress.port == 443
    assert p.egress.authentication == 'bearer'
    assert dict(p.egress.headers) == {
        'X-GitHub-Api-Version': presets.GITHUB_API_VERSION
    }


@pytest.mark.parametrize(
    'change',
    [
        {'repository': 'other/TauCeti'},
        {'pr_numbers': [13861]},
        {'operations': ['pr.view']},
        {'author': 'someone-else'},
        {'head_repository': 'other/TauCeti'},
        {'lifetime_seconds': 60},
        {'max_requests': 19},
        {'max_body_bytes': 100},
    ],
)
def test_every_shorthand_field_changes_the_digest(change):
    assert spec(**change).digest != spec().digest


@pytest.mark.parametrize(
    'field,value',
    [
        ('schema', True), ('schema', 2), ('pr_numbers', []), ('pr_numbers', [True]),
        ('pr_numbers', [1, 1]), ('pr_numbers', [0]), ('pr_numbers', [2**31]),
        ('pr_numbers', list(range(1, 258))), ('pr_numbers', '*'),
        ('operations', ['pr.merge']), ('operations', []),
        ('operations', ['pr.view', 'pr.view']), ('operations', [['pr.view']]),
        ('operations', ['pr.*']), ('lifetime_seconds', 3601),
        ('lifetime_seconds', 0), ('lifetime_seconds', 1.0), ('max_requests', False),
        ('max_requests', 1001), ('max_body_bytes', 16385),
        ('author', 'Erotemic/evil'), ('author', ''), ('author', '-leading'),
        ('head_repository', 'https://evil.invalid/r'), ('head_repository', 'x/..'),
        ('repository', 'no-slash'), ('unexpected', 1), ('host', 'evil.invalid'),
        ('checks', {}), ('cli', {}), ('credential_source', {'kind': 'file'}),
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
def test_repository_grammar_denies_path_and_host_confusion(repo):
    """Neither a policy nor a request can carry one of these into a path."""
    with pytest.raises(SecretsError, match='Invalid policy'):
        spec(repository=repo)
    with pytest.raises(SecretsError, match='Invalid policy'):
        spec(head_repository=repo)
    policy = spec()
    with pytest.raises(SecretsError):
        admit(policy, parse(policy, repository=repo))


# -- requests ----------------------------------------------------------------


@pytest.mark.parametrize(
    'extra',
    [
        {'url': 'https://evil.invalid'}, {'headers': 'x'}, {'principal': 'admin'},
        {'method': 'DELETE'}, {'state': 'closed'}, {'body': 'write on read'},
        {'title': 'write on read'}, {'page': 1}, {'pr': True}, {'pr': -1},
        {'body': '\ud800'}, {'owner_uid': 0}, {'pr': 13861.0},
        {'repository': ['a/b']}, {'head_sha': 'a' * 40},
    ],
)  # fmt: skip
def test_request_arguments_are_closed(extra):
    """Every one of these is refused by parsing or by the scope check."""
    policy = spec()
    with pytest.raises(SecretsError) as caught:
        admit(policy, parse(policy, **extra))
    assert caught.value.code == 'invalid_request'


@pytest.mark.parametrize(
    'wire',
    [
        # The flat shape an early draft of schema 1 used is not a request.
        {'operation': 'pr.view', 'repository': REPO, 'pr': 13861},
        {
            'operation': 'pr.view',
            'arguments': {'pr': 13861},
            'repository': REPO,
        },
        {'operation': ['pr.view'], 'arguments': {}},
        {'operation': 'pr.view', 'arguments': []},
    ],
)
def test_there_is_one_request_shape(wire):
    with pytest.raises(SecretsError) as caught:
        spec().parse_request(wire)
    assert caught.value.code == 'invalid_request'


@pytest.mark.parametrize(
    'operation,arguments,code',
    [
        ('pr.view', {'repository': 'other/repo'}, 'denied'),
        ('pr.view', {'pr': 9}, 'denied'),
        ('pr.view', {'pr': '13861'}, 'denied'),  # type-exact membership
        ('pr.merge', {}, 'denied'),
        ('api', {}, 'denied'),
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


def test_folding_and_defaults_make_equal_requests_identical():
    policy = spec()
    mixed = parse(policy, 'pr.comments')
    explicit = parse(policy, 'pr.comments', page=1, repository=REPOSITORY)
    shouted = parse(policy, 'pr.comments', repository=REPO.upper())
    assert mixed == explicit == shouted and mixed.digest == explicit.digest
    assert dict(mixed.arguments) == {
        'page': 1,
        'pr': 13861,
        'repository': REPOSITORY,
    }
    assert 'page' not in dict(parse(policy, 'pr.view').arguments)
    assert admit(policy, mixed) == 0
    assert admit(policy, parse(policy, 'pr.comment', body='héllo')) == 6


def test_a_request_without_a_repository_is_incomplete_not_defaulted():
    policy = spec()
    request = policy.parse_request(
        {'operation': 'pr.view', 'arguments': {'pr': 13861}}
    )
    assert dict(request.arguments) == {'pr': 13861}
    with pytest.raises(SecretsError) as caught:
        admit(policy, request)
    assert caught.value.code == 'invalid_request'


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


# -- effects -----------------------------------------------------------------


@pytest.mark.parametrize(
    'operation,method,suffix',
    [
        ('pr.diff', 'GET', '/pulls/13861'),
        ('pr.comments', 'GET', '/issues/13861/comments?page=1&per_page=100'),
        ('pr.reviews', 'GET', '/pulls/13861/reviews?page=1&per_page=100'),
        (
            'pr.review-comments',
            'GET',
            '/pulls/13861/comments?page=1&per_page=100',
        ),
        (
            'pr.checks',
            'GET',
            '/commits/' + 'a' * 40 + '/check-runs?page=1&per_page=100',
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
    effect = check_effect(must(policy.final(request, facts)))
    assert effect.method == method
    assert effect.target == '/repos/' + REPOSITORY + suffix
    assert 'attacker' not in repr(effect)
    if method != 'GET':
        assert effect.body == (('body', 'A precise update.'),)
    assert effect.accept == (
        presets.GITHUB_DIFF if operation == 'pr.diff' else presets.GITHUB_JSON
    )
    assert effect.response == ('text' if operation == 'pr.diff' else 'json')
    preflight = check_effect(must(policy.preflight(request)))
    assert (preflight.method, preflight.target, preflight.accept) == (
        'GET',
        f'/repos/{REPOSITORY}/pulls/13861',
        presets.GITHUB_JSON,
    )


def test_view_has_no_second_effect_and_edit_sends_only_what_was_given():
    policy = spec()
    assert policy.final(parse(policy), metadata()) is None
    both = must(
        policy.final(parse(policy, 'pr.edit', body='B', title='T'), metadata())
    )
    assert both.body == (('body', 'B'), ('title', 'T'))
    title = must(policy.final(parse(policy, 'pr.edit', title='T'), metadata()))
    assert title.body == (('title', 'T'),)


def test_paging_reaches_the_route_and_checks_use_the_validated_sha():
    policy = spec()
    page = must(policy.final(parse(policy, 'pr.reviews', page=7), metadata()))
    assert page.target.endswith('/reviews?page=7&per_page=100')
    facts = metadata()
    facts['head']['sha'] = 'ABCDEF' + '0' * 34
    checks = must(policy.final(parse(policy, 'pr.checks'), facts))
    assert '/commits/abcdef' + '0' * 34 + '/check-runs' in checks.target
    facts['head']['sha'] = 'b' * 64  # a SHA-256 repository
    assert (
        '/commits/' + 'b' * 64
        in must(policy.final(parse(policy, 'pr.checks'), facts)).target
    )


@pytest.mark.parametrize(
    'mutate',
    [
        lambda f: f.update(number=9),
        lambda f: f.update(number=13862),  # the grant's other PR
        lambda f: f.update(number='13861'),
        lambda f: f.update(number=True),
        lambda f: f['user'].update(login='other'),
        lambda f: f['user'].update(login=None),
        lambda f: f['head']['repo'].update(full_name='Other/TauCeti'),
        lambda f: f['head'].update(repo=None),  # deleted fork
        lambda f: f['base']['repo'].update(full_name='Other/TauCeti'),
        lambda f: f['head'].update(sha='not-a-sha'),
        lambda f: f['head'].update(sha='a' * 39),
        lambda f: f['head'].update(sha='a' * 41),
        lambda f: f['head'].update(sha='../../orgs/x'),
        lambda f: f['head'].update(sha=None),
        lambda f: f['head'].pop('sha'),
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
    for operation in ('pr.view', 'pr.diff', 'pr.checks', 'pr.comment'):
        extra = {'body': 'b'} if operation == 'pr.comment' else {}
        with pytest.raises(SecretsError) as caught:
            policy.final(parse(policy, operation, **extra), facts)
        assert caught.value.code == 'resource_mismatch'


@pytest.mark.parametrize('facts', [None, [], 'pr', 7, {}, {'number': 13861}])
def test_malformed_provider_metadata_is_a_mismatch_not_a_crash(facts):
    policy = spec()
    with pytest.raises(SecretsError) as caught:
        policy.final(parse(policy), facts)
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
    partial = must(policy.reply_meta(request, [{'id': 1}]))
    assert partial['pagination']['possibly_more'] is False
    for bad in ([{}] * 101, {'not': 'a list'}, None):
        with pytest.raises(SecretsError) as caught:
            policy.reply_meta(request, bad)
        assert caught.value.code == 'upstream_response'


def test_check_run_pagination_and_unpaged_operations():
    policy = spec()
    checks = parse(policy, 'pr.checks')
    meta = must(policy.reply_meta(checks, {'check_runs': [{}] * 100}))
    assert meta['pagination']['possibly_more'] is True
    for bad in ([], {'check_runs': 'x'}, {'check_runs': [{}] * 101}):
        with pytest.raises(SecretsError):
            policy.reply_meta(checks, bad)
    assert policy.reply_meta(parse(policy), metadata()) is None


# -- the gh command table ----------------------------------------------------


def test_the_gh_table_lists_exactly_the_granted_operations():
    policy = spec(operations=['pr.view', 'pr.diff', 'pr.comment'])
    table = policy.cli_tables()
    assert list(table) == ['gh']
    rows = {' '.join(row['command']): row for row in table['gh']}
    assert sorted(rows) == ['pr comment', 'pr diff', 'pr view']
    assert rows['pr view'] == {
        'command': ['pr', 'view'],
        'operation': 'pr.view',
        'positional': ['pr'],
        'options': {'--repo': 'repository', '-R': 'repository'},
        'output': 'reply',
    }
    assert rows['pr diff']['output'] == 'result'
    assert rows['pr comment']['options'] == {
        '--body': 'body',
        '--body-file': '@body',
        '--repo': 'repository',
        '-R': 'repository',
    }


def test_the_table_grants_nothing_a_request_could_not_already_ask_for():
    """A table row only names an operation and arguments the scope has."""
    policy = spec()
    scope = policy.scope()
    for row in policy.cli_tables()['gh']:
        operation = find(scope, row['operation'])
        known = {name for name, _ in operation.parameters} | {
            item.name for item in operation.fields
        }
        targets = [t.lstrip('@') for t in row['options'].values()]
        assert set(row['positional']) | set(targets) <= known


def test_gh_compat_v2_opt_in_preserves_legacy_policy_digest():
    """The frozen schema-1 shorthand is unchanged without an explicit opt-in."""
    legacy = spec()
    modern = spec(gh_compat=2)
    assert legacy.digest != modern.digest
    legacy_rows = legacy.to_dict()['cli']['gh']
    modern_rows = modern.to_dict()['cli']['gh']
    old = next(row for row in legacy_rows if row['command'] == ['pr', 'view'])
    new = next(row for row in modern_rows if row['command'] == ['pr', 'view'])
    assert 'repository_default' not in old and 'json_fields' not in old
    assert new['json_fields'] == presets.GH_VIEW_JSON
    assert new['repository_default']['environment'] == 'GH_REPO'
    assert parse_policy(modern.to_dict()) == modern
    with pytest.raises(SecretsError):
        spec(gh_compat=3)


def test_tauceti_opt_in_example_is_read_only():
    example = json.loads(
        (EXAMPLES / 'aivm-secrets-tauceti-gh2.json').read_text()
    )
    assert example['gh_compat'] == 2
    result = parse_policy(example)
    assert not any(item.write for item in result.scope())
    assert 'pr.summary' in [item.name for item in result.scope()]
    assert 'pr.review-threads' in [item.name for item in result.scope()]
