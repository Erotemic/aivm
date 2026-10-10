"""Declarative HTTPS manifests: the one service mechanism (PLUGIN-01, ROUTE-01).

``https_policy`` is the plain case; ``tracker_policy`` uses every general
feature -- fact checks, bound facts, folding, defaults, pagination, a
declared-write ``GET`` and a command table -- for an invented provider.
"""

from __future__ import annotations

import copy

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel.https import (
    Capture,
    Check,
    HTTPSpec,
    Requirement,
    lookup,
)
from aivm_secrets.kernel.model import Effect, Request, check_effect
from aivm_secrets.kernel.scope import IntRange, IntSet, StrSet, check_arguments
from aivm_secrets.kernel.scope import find as find_operation
from tests.secrets_helpers import (
    PROJECT,
    REVISION,
    https_policy,
    must,
    tracker_facts,
    tracker_policy,
)


def find(scope, name):
    """An operation the test expects the scope to contain."""
    return must(find_operation(scope, name))


def spec(**changes):
    return HTTPSpec.parse(https_policy(**changes))


def tracker(**changes):
    return HTTPSpec.parse(tracker_policy(**changes))


def one(**operation):
    base = {'name': 'op', 'effect': 'read', 'method': 'GET', 'path': '/v1/x'}
    base.update(operation)
    return spec(operations=[base]).operations[0]


def request(operation, **arguments):
    return Request(operation, tuple(sorted(arguments.items())))


def ticket(policy, operation='ticket.view', **arguments):
    given = {'project': PROJECT, 'ticket': 7}
    given.update(arguments)
    return policy.parse_request({'operation': operation, 'arguments': given})


def edited(index=None, **changes):
    """``tracker_policy`` with one operation (or the check) altered."""
    policy = tracker_policy()
    target = (
        policy['checks']['ticket']
        if index is None
        else policy['operations'][index]
    )
    for key, value in changes.items():
        if value is None:
            target.pop(key, None)
        else:
            target[key] = value
    return policy


VIEW, BUILDS, NOTE, CLOSE, LOG = range(5)


def refused(policy):
    with pytest.raises(SecretsError) as caught:
        HTTPSpec.parse(policy)
    assert caught.value.code == 'invalid_policy'


# -- the plain manifest ------------------------------------------------------


def test_http_policy_is_canonical_and_names_its_own_credential_source():
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
    assert policy.client_aliases == () and policy.cli_tables() == {}
    assert policy.checks == ()


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
        (1, 'effect', 'write'),
        (2, 'query', {'state': 'closed', 'page': '{page}'}),
        (3, 'body_fields', {'body': 99}),
        (3, 'body_fields', {'body': {'max_bytes': 100, 'optional': True}}),
        (3, 'method', 'PATCH'),
        (0, 'response', 'text'),
        (0, 'accept', 'application/vnd.api+json'),
    ]:
        changed = copy.deepcopy(operations)
        changed[index][key] = value
        assert spec(operations=changed).digest != base


def test_every_tracker_feature_changes_the_digest():
    base = tracker().digest
    seen = {base}
    variants = [
        edited(accept='application/vnd.tracker+json'),
        edited(path='/v2/projects/{project}/tickets/{ticket}'),
        edited(
            bind={'revision': {'at': ['head', 'rev'], 'format': 'hex'},
                  'serial': {'at': ['serial'], 'format': 'integer'},
                  'branch': {'at': ['ref'], 'format': 'segment'}}
        ),
        edited(BUILDS, defaults=None),
        edited(BUILDS, page={'size': 50, 'at': ['builds']}),
        edited(BUILDS, page={'size': 49, 'at': ['builds'], 'parameter': 'page'}),
        edited(BUILDS, page={'size': 50, 'parameter': 'page'}),
        edited(CLOSE, fold=None),
        edited(CLOSE, effect='read'),
        tracker_policy(cli={}),
    ]  # fmt: skip
    for index in range(5):
        variant = tracker_policy()
        variant['checks']['ticket']['require'].pop(index)
        variants.append(variant)
    folded = tracker_policy()
    folded['checks']['ticket']['require'][2]['fold'] = True
    variants.append(folded)
    renamed = tracker_policy()
    renamed['cli']['tk'][0]['options'] = {'--project': 'project'}
    variants.append(renamed)
    for variant in variants:
        digest = HTTPSpec.parse(variant).digest
        assert digest not in seen
        seen.add(digest)


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
    assert find_operation(scope, 'issue.delete') is None


def test_effects_are_built_only_from_the_template_and_allowlists():
    policy = spec()
    view = must(policy.final(request('issue.view', issue=23), None))
    assert view == Effect('GET', '/v1/issues/23')
    listing = must(policy.final(request('issue.list', page=7), None))
    assert listing.target == '/v1/issues?page=7&state=open'
    comment = must(
        policy.final(request('issue.comment', issue=24, body='héllo'), None)
    )
    assert (comment.method, comment.path) == ('POST', '/v1/issues/24/comments')
    assert comment.body == (('body', 'héllo'),)
    for effect in (view, listing, comment):
        assert check_effect(effect) is effect
    # Nothing here is conditioned on a fact or paged.
    assert policy.preflight(request('issue.view', issue=23)) is None
    assert policy.reply_meta(request('issue.view', issue=23), {}) is None
    absent = request('issue.delete', issue=23)
    for refuse in (
        lambda: policy.final(absent, None),
        lambda: policy.preflight(absent),
        lambda: policy.reply_meta(absent, None),
    ):
        with pytest.raises(SecretsError) as caught:
            refuse()
        assert caught.value.code == 'denied'


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
                effect = check_effect(must(policy.final(candidate, None)))
                assert effect.is_write == find(scope, candidate.operation).write
                seen.add(effect.target)
    for page in range(1, 51):
        candidate = request('issue.list', page=page)
        check_arguments(find(scope, 'issue.list'), candidate)
        seen.add(check_effect(must(policy.final(candidate, None))).target)
    assert len(seen) == 2 + 2 + 50
    assert all(target.startswith('/v1/') for target in seen)


def test_string_parameters_and_response_modes():
    op = one(
        path='/v1/{org}/repos/{repo}/raw',
        parameters={'org': ['acme'], 'repo': ['a.b', 'c_d', 'e-f~g']},
        response='text',
    )
    assert op.accept == 'text/plain'
    effect = op.effect(request('op', org='acme', repo='e-f~g'), {})
    assert (
        effect.path == '/v1/acme/repos/e-f~g/raw' and effect.response == 'text'
    )
    assert one().accept == 'application/json'
    assert (
        one(accept='application/vnd.api+json').accept
        == 'application/vnd.api+json'
    )


def test_a_string_used_only_in_a_path_may_span_segments():
    """``owner/name`` is one allowlisted value, each segment still safe."""
    op = one(path='/v1/{repo}/raw', parameters={'repo': ['acme/widgets']})
    effect = op.effect(request('op', repo='acme/widgets'), {})
    assert check_effect(effect).path == '/v1/acme/widgets/raw'
    for unsafe in (
        'acme/../etc',
        'acme//x',
        '/acme',
        'acme/',
        'a/b?c',
        'a/%2e',
    ):
        with pytest.raises(SecretsError):
            one(path='/v1/{repo}', parameters={'repo': [unsafe]})
    # The same value in a query string would change the query's meaning.
    with pytest.raises(SecretsError):
        one(query={'repo': '{repo}'}, parameters={'repo': ['acme/widgets']})


# -- effect classification ---------------------------------------------------


def test_effect_is_declared_and_never_inferred_from_the_method():
    """A GET may be a write; a method with a body may never be a read."""
    with pytest.raises(SecretsError):
        one(effect=None)
    operations = https_policy()['operations']
    for index in range(4):
        missing = copy.deepcopy(operations)
        del missing[index]['effect']
        refused(https_policy(operations=missing))
    for bad in ('READ', 'none', 'idempotent', True, 1, ['read']):
        with pytest.raises(SecretsError):
            one(effect=bad)
    for method in ('POST', 'PATCH'):
        with pytest.raises(SecretsError):
            one(method=method, effect='read', body_fields={'body': 10})
    close = one(effect='write')
    assert close.write is True and close.scope().write is True
    assert close.to_dict()['effect'] == 'write'
    # The constructed request is still a GET with no body.
    effect = close.effect(request('op'), {})
    assert (effect.method, effect.body, effect.is_write) == ('GET', None, False)


def test_the_tracker_scope_classifies_by_declaration():
    scope = tracker().scope()
    assert {op.name: op.write for op in scope} == {
        'ticket.builds': False,
        'ticket.close': True,
        'ticket.log': False,
        'ticket.note': True,
        'ticket.view': False,
    }


# -- fact checks -------------------------------------------------------------


def test_a_check_conditions_every_operation_that_requires_it():
    policy = tracker()
    assert HTTPSpec.parse(policy.to_dict()) == policy
    for operation, extra in (
        ('ticket.view', {}),
        ('ticket.builds', {}),
        ('ticket.note', {'text': 'hi'}),
    ):
        fetch = must(policy.preflight(ticket(policy, operation, **extra)))
        assert (fetch.method, fetch.target, fetch.body) == (
            'GET',
            '/v1/projects/acme/widgets/tickets/7',
            None,
        )
        assert check_effect(fetch) is fetch
    assert policy.preflight(ticket(policy, 'ticket.close')) is None
    assert policy.preflight(request('ticket.log', ticket=7)) is None


def test_the_verified_facts_can_be_the_whole_answer():
    policy = tracker()
    assert policy.final(ticket(policy), tracker_facts()) is None


def test_bound_facts_enter_the_route_only_after_validation():
    policy = tracker()
    builds = must(
        policy.final(ticket(policy, 'ticket.builds'), tracker_facts())
    )
    assert check_effect(builds).target == (
        f'/v1/projects/acme/widgets/revisions/{REVISION}/builds/31/main'
        '?page=1&per_page=50'
    )
    note = must(
        policy.final(
            ticket(policy, 'ticket.note', text='hi', title='T'), tracker_facts()
        )
    )
    assert (note.method, note.body) == (
        'POST',
        (('text', 'hi'), ('title', 'T')),
    )
    only = must(
        policy.final(ticket(policy, 'ticket.note', text='hi'), tracker_facts())
    )
    assert only.body == (('text', 'hi'),)


@pytest.mark.parametrize(
    'mutate',
    [
        lambda f: f.update(id=8),  # the grant's other ticket
        lambda f: f.update(id='7'),
        lambda f: f.update(id=True),
        lambda f: f.update(id=7.0),
        lambda f: f.pop('id'),
        lambda f: f['project'].update(slug='acme/gadgets'),
        lambda f: f.update(project='acme/widgets'),
        lambda f: f.update(project=None),
        lambda f: f.update(state='OPEN'),  # this requirement does not fold
        lambda f: f.update(state='closed'),
        lambda f: f.update(state=None),
        lambda f: f['owner'].update(name='mallory'),
        lambda f: f['owner'].update(name=['alice']),
        lambda f: f.update(version='2'),
        lambda f: f.update(version=3),
        lambda f: f.update(version=True),
    ],
)
def test_a_fact_that_does_not_hold_stops_everything(mutate):
    """The second denial class of AUTH-01, for a generic manifest."""
    policy = tracker()
    facts = tracker_facts()
    mutate(facts)
    for operation, extra in (
        ('ticket.view', {}),
        ('ticket.builds', {}),
        ('ticket.note', {'text': 'hi'}),
    ):
        with pytest.raises(SecretsError) as caught:
            policy.final(ticket(policy, operation, **extra), facts)
        assert caught.value.code == 'resource_mismatch'


@pytest.mark.parametrize(
    'mutate',
    [
        lambda f: f['head'].update(rev='../../admin'),
        lambda f: f['head'].update(rev='c0ffee'),
        lambda f: f['head'].update(rev='g' * 40),
        lambda f: f['head'].update(rev='a' * 41),
        lambda f: f['head'].update(rev=None),
        lambda f: f['head'].update(rev=7),
        lambda f: f.pop('head'),
        lambda f: f.update(serial='31'),
        lambda f: f.update(serial=-1),
        lambda f: f.update(serial=True),
        lambda f: f.update(serial=2**31),
        lambda f: f.update(branch='feature/x'),
        lambda f: f.update(branch='..'),
        lambda f: f.update(branch='a?b=c'),
        lambda f: f.update(branch=''),
        lambda f: f.update(branch=3),
        lambda f: f.pop('branch'),
    ],
)
def test_a_provider_cannot_steer_a_route_through_a_bound_fact(mutate):
    """Facts are data from the network; only a validated one enters a path."""
    policy = tracker()
    facts = tracker_facts()
    mutate(facts)
    with pytest.raises(SecretsError) as caught:
        policy.final(ticket(policy, 'ticket.builds'), facts)
    assert caught.value.code == 'resource_mismatch'


@pytest.mark.parametrize('facts', [None, [], 'ticket', 7, {}, {'id': 7}])
def test_malformed_facts_are_a_mismatch_not_a_crash(facts):
    policy = tracker()
    with pytest.raises(SecretsError) as caught:
        policy.final(ticket(policy), facts)
    assert caught.value.code == 'resource_mismatch'


def test_requirements_compare_by_exact_type_and_optional_folding():
    plain = Requirement.parse({'at': ['a', 'b'], 'equals': 'Open'})
    folded = Requirement.parse(
        {'at': ['a', 'b'], 'equals': 'Open', 'fold': True}
    )
    number = Requirement.parse({'at': [], 'equals': 2})
    echo = Requirement.parse({'at': ['id'], 'equals_parameter': 'ticket'})
    none = request('op')
    assert plain.holds({'a': {'b': 'Open'}}, none)
    assert not plain.holds({'a': {'b': 'open'}}, none)
    assert folded.holds({'a': {'b': 'OPEN'}}, none)
    assert not folded.holds({'a': {'b': 'opened'}}, none)
    assert number.holds(2, none) and not number.holds(True, none)
    one = Requirement.parse({'at': [], 'equals': 1})
    # In Python ``True == 1``; a provider's boolean is still not the number.
    assert one.holds(1, none) and not one.holds(True, none)
    assert not number.holds('2', none) and not number.holds(2.0, none)
    assert echo.holds({'id': 7}, request('op', ticket=7))
    assert not echo.holds({'id': 7}, request('op', ticket=8))
    assert not echo.holds({'id': '7'}, request('op', ticket=7))
    assert plain.to_dict() == {
        'at': ['a', 'b'],
        'equals': 'Open',
        'fold': False,
    }
    assert echo.to_dict() == {
        'at': ['id'],
        'equals_parameter': 'ticket',
        'fold': False,
    }
    with pytest.raises(SecretsError) as caught:
        plain.holds({'a': 'not an object'}, none)
    assert caught.value.code == 'resource_mismatch'


def test_captures_yield_a_safe_segment_or_nothing():
    hexed = Capture.parse('rev', {'at': ['sha'], 'format': 'hex'})
    assert hexed.extract({'sha': 'AB' * 20}) == 'ab' * 20
    assert hexed.extract({'sha': 'c' * 64}) == 'c' * 64
    number = Capture.parse('n', {'at': [], 'format': 'integer'})
    assert number.extract(0) == '0' and number.extract(41) == '41'
    segment = Capture.parse('ref', {'at': ['x'], 'format': 'segment'})
    assert segment.extract({'x': 'release-1.2_3~rc'}) == 'release-1.2_3~rc'
    for capture, facts in (
        (hexed, {'sha': 'ab' * 16}),
        (hexed, {'sha': 'zz' * 20}),
        (hexed, {'sha': 40}),
        (hexed, {}),
        (number, '7'),
        (number, -1),
        (number, False),
        (segment, {'x': 'a/b'}),
        (segment, {'x': '.'}),
        (segment, {'x': 'a b'}),
        (segment, {'x': None}),
    ):
        with pytest.raises(SecretsError) as caught:
            capture.extract(facts)
        assert caught.value.code == 'resource_mismatch'


def test_lookup_never_indexes_arrays_or_guesses():
    document = {'a': {'b': [{'c': 1}]}, 'n': None}
    assert lookup(document, (), code='denied') is document
    assert lookup(document, ('a', 'b'), code='denied') == [{'c': 1}]
    assert lookup(document, ('n',), code='denied') is None
    for pointer in (('a', 'b', '0'), ('a', 'b', 'c'), ('missing',), ('n', 'x')):
        with pytest.raises(SecretsError) as caught:
            lookup(document, pointer, code='resource_mismatch')
        assert caught.value.code == 'resource_mismatch'


def test_check_reports_the_parameters_it_reads():
    check = tracker().checks[0]
    assert isinstance(check, Check) and check.name == 'ticket'
    assert check.parameters() == {'project', 'ticket'}
    assert [item.name for item in check.bind] == [
        'branch',
        'revision',
        'serial',
    ]
    assert check.accept == 'application/json'


@pytest.mark.parametrize(
    'change',
    [
        {'path': None},
        {'require': None},
        {'require': []},
        {'require': {}},
        {'require': [{'at': ['id']}]},
        {'require': [{'at': ['id'], 'equals': 1, 'equals_parameter': 'ticket'}]},
        {'require': [{'at': 'id', 'equals': 1}]},
        {'require': [{'at': ['id'], 'equals': None}]},
        {'require': [{'at': ['id'], 'equals': 1.5}]},
        {'require': [{'at': ['id'], 'equals': True}]},
        {'require': [{'at': ['id'], 'equals': -1}]},
        {'require': [{'at': ['id'], 'equals': ['x']}]},
        {'require': [{'at': ['id'], 'equals': 'x' * 257}]},
        {'require': [{'at': ['id'], 'equals': 1, 'fold': True}]},
        {'require': [{'at': ['id'], 'equals': 'x', 'fold': 'yes'}]},
        {'require': [{'at': ['id'], 'equals': 'x', 'regex': '.*'}]},
        {'require': [{'at': [1], 'equals': 'x'}]},
        {'require': [{'at': ['k'] * 9, 'equals': 'x'}]},
        {'require': [{'at': ['id'], 'equals_parameter': 'Ticket'}]},
        {'require': [{'at': ['id'], 'equals_parameter': 'absent'}]},
        {'require': ['id == ticket']},
        {'require': [{'at': ['id'], 'equals': 1}] * 17},
        {'path': '/v1/{project}/{other}'},
        {'path': 'v1/x'},
        {'path': '/v1/../x'},
        {'accept': 'text/html, */*'},
        {'bind': []},
        {'bind': {'Revision': {'at': ['x'], 'format': 'hex'}}},
        {'bind': {'revision': {'at': ['x'], 'format': 'regex'}}},
        {'bind': {'revision': {'at': ['x'], 'format': ['hex']}}},
        {'bind': {'revision': {'at': ['x']}}},
        {'bind': {'revision': 'head.rev'}},
        {'bind': {'revision': {'at': 'x', 'format': 'hex'}}},
        # A bound name may not shadow a request parameter or a body field.
        {'bind': {'ticket': {'at': ['id'], 'format': 'integer'}}},
        {'bind': {'text': {'at': ['id'], 'format': 'segment'}}},
        # Operations reference facts this check no longer binds.
        {'bind': {}},
        {'method': 'GET'},
        {'body_fields': {}},
    ],
)  # fmt: skip
def test_untrusted_check_definitions_rejected(change):
    refused(edited(**change))


def test_a_check_need_not_bind_anything():
    gate = {'path': '/v1/account', 'require': [{'at': ['active'], 'equals': 1}]}
    operations = https_policy()['operations']
    operations[0]['requires'] = 'account'
    policy = spec(checks={'account': gate}, operations=operations)
    assert HTTPSpec.parse(policy.to_dict()) == policy
    assert 'bind' not in policy.to_dict()['checks']['account']
    read = request('profile.read')
    assert must(policy.preflight(read)).target == '/v1/account'
    assert must(policy.final(read, {'active': 1})).target == '/v1/account'
    with pytest.raises(SecretsError):
        policy.final(read, {'active': 0})


def test_checks_are_closed_and_must_be_used():
    refused(tracker_policy(checks=[]))
    refused(
        tracker_policy(checks={'Ticket': tracker_policy()['checks']['ticket']})
    )
    spare = tracker_policy()
    spare['checks']['unused'] = {
        'path': '/v1/x',
        'require': [{'at': ['a'], 'equals': 1}],
    }
    refused(spare)
    refused(edited(VIEW, requires='absent'))
    refused(edited(VIEW, requires=['ticket']))
    refused(https_policy(checks={'k': {'path': '/x', 'require': []}}))
    many = {
        f'c{i}': {'path': '/x', 'require': [{'at': ['a'], 'equals': 1}]}
        for i in range(17)
    }
    refused(https_policy(checks=many))


@pytest.mark.parametrize(
    'change',
    [
        # The checked facts are the answer: nothing about a second request
        # may be stated, and nothing can be changed.
        {'method': 'GET'},
        {'path': '/v1/x'},
        {'query': {'a': 'b'}},
        {'body_fields': {'text': 10}},
        {'response': 'json'},
        {'accept': 'application/json'},
        {'page': {'size': 10}},
        {'effect': 'write'},
        {'requires': None},
        {'returns': 'facts'},
        {'returns': True},
        # The check reads a parameter this operation does not declare.
        {'parameters': {'ticket': [7]}, 'fold': None},
        # ... or the operation declares one nothing reads.
        {'parameters': {'project': [PROJECT], 'ticket': [7], 'extra': [1]}},
    ],
)
def test_untrusted_check_only_operations_rejected(change):
    refused(edited(VIEW, **change))


def test_an_ordinary_operation_states_its_request():
    refused(edited(LOG, method=None))
    refused(edited(LOG, path=None))
    refused(edited(LOG, method=['GET']))
    refused(edited(LOG, returns='check'))
    assert tracker(**edited(LOG, returns='response')).digest == tracker().digest


# -- normalization -----------------------------------------------------------


def test_folding_and_defaults_are_applied_once_at_the_boundary():
    policy = tracker()
    plain = ticket(policy, 'ticket.builds')
    shouted = ticket(policy, 'ticket.builds', project='ACME/Widgets', page=1)
    assert plain == shouted and plain.digest == shouted.digest
    assert dict(plain.arguments) == {
        'page': 1,
        'project': PROJECT,
        'ticket': 7,
    }
    assert dict(ticket(policy, 'ticket.builds', page=4).arguments)['page'] == 4
    # A value of the wrong type is left for the scope check to refuse.
    odd = policy.parse_request(
        {'operation': 'ticket.view', 'arguments': {'project': 5, 'ticket': 7}}
    )
    assert dict(odd.arguments)['project'] == 5
    with pytest.raises(SecretsError):
        check_arguments(find(policy.scope(), 'ticket.view'), odd)
    # An operation the manifest lacks passes through for the scope to deny.
    unknown = policy.parse_request(
        {'operation': 'ticket.delete', 'arguments': {'project': 'ACME/x'}}
    )
    assert dict(unknown.arguments) == {'project': 'ACME/x'}


@pytest.mark.parametrize(
    'change',
    [
        {'defaults': {'page': 0}},
        {'defaults': {'page': 10}},
        {'defaults': {'page': '1'}},
        {'defaults': {'page': True}},
        {'defaults': {'page': [1]}},
        {'defaults': {'absent': 1}},
        {'defaults': {'project': 'other/project'}},
        {'defaults': [['page', 1]]},
        {'fold': ['ticket']},
        {'fold': ['page']},
        {'fold': ['absent']},
        {'fold': ['project', 'project']},
        {'fold': [7]},
        {'fold': 'project'},
        {'fold': ['project'] * 17},
        # Folding normalizes the request; the allowlist must already be folded.
        {'parameters': {'project': ['Acme/Widgets'], 'ticket': [7],
                        'page': {'min': 1, 'max': 9}}},
    ],
)  # fmt: skip
def test_untrusted_normalization_rejected(change):
    refused(edited(BUILDS, **change))


def test_a_default_may_be_any_permitted_value():
    policy = tracker(**edited(BUILDS, defaults={'page': 9, 'project': PROJECT}))
    filled = policy.parse_request(
        {'operation': 'ticket.builds', 'arguments': {'ticket': 7}}
    )
    assert dict(filled.arguments) == {
        'page': 9,
        'project': PROJECT,
        'ticket': 7,
    }


# -- pagination --------------------------------------------------------------


def test_pagination_is_explicit_not_silently_complete():
    policy = tracker()
    builds = ticket(policy, 'ticket.builds', page=3)
    full = policy.reply_meta(builds, {'builds': [{}] * 50})
    assert full == {
        'pagination': {'page': 3, 'per_page': 50, 'possibly_more': True}
    }
    part = must(policy.reply_meta(builds, {'builds': []}))
    assert part['pagination']['possibly_more'] is False
    for bad in ([], {'builds': 'x'}, {'builds': [{}] * 51}, {}, None):
        with pytest.raises(SecretsError) as caught:
            policy.reply_meta(builds, bad)
        assert caught.value.code == 'upstream_response'
    assert policy.reply_meta(ticket(policy), tracker_facts()) is None
    # Without a page parameter the reply still says whether there may be more.
    fixed = tracker(**edited(BUILDS, page={'size': 2}))
    assert fixed.reply_meta(ticket(fixed, 'ticket.builds'), [1, 2]) == {
        'pagination': {'per_page': 2, 'possibly_more': True}
    }


@pytest.mark.parametrize(
    'page',
    [
        {}, {'size': 0}, {'size': 1001}, {'size': '50'}, {'size': True},
        {'size': 50, 'at': 'builds'}, {'size': 50, 'at': [0]},
        {'size': 50, 'parameter': 'absent'}, {'size': 50, 'parameter': 'project'},
        {'size': 50, 'parameter': 'Page'}, {'size': 50, 'next': 'cursor'}, [50],
    ],
)  # fmt: skip
def test_untrusted_pagination_rejected(page):
    refused(edited(BUILDS, page=page))


def test_only_a_json_answer_can_be_paged():
    refused(edited(LOG, page={'size': 10}))


# -- command tables ----------------------------------------------------------


def test_command_tables_are_canonical_data_for_the_guest_client():
    policy = tracker()
    assert policy.client_aliases == ('tk',)
    rows = policy.cli_tables()['tk']
    assert [row['command'] for row in rows] == [
        ['view'], ['builds', 'list'], ['note'], ['log'],
    ]  # fmt: skip
    assert rows[0] == {
        'command': ['view'],
        'operation': 'ticket.view',
        'positional': ['ticket'],
        'options': {'--project': 'project', '-p': 'project'},
        'output': 'reply',
    }
    assert rows[2]['options']['--text-file'] == '@text'
    assert rows[3]['output'] == 'result' and rows[3]['options'] == {}
    two = tracker_policy()
    two['cli']['zz'] = [{'command': ['x'], 'operation': 'ticket.log'}]
    assert HTTPSpec.parse(two).client_aliases == ('tk', 'zz')


def row(**changes):
    policy = tracker_policy()
    policy['cli']['tk'][2].update(changes)
    return policy


@pytest.mark.parametrize(
    'change',
    [
        {'command': []}, {'command': 'note'}, {'command': ['a'] * 5},
        {'command': ['Note']}, {'command': ['--note']}, {'command': ['a b']},
        {'command': [7]}, {'command': ['view']},  # duplicates another row
        {'operation': 'ticket.delete'}, {'operation': ['ticket.note']},
        {'positional': 'ticket'}, {'positional': ['absent']},
        {'positional': ['text']}, {'positional': ['ticket', 'ticket']},
        {'positional': [7]}, {'positional': ['ticket'] * 17},
        {'options': []}, {'options': {'--text': 'absent'}},
        {'options': {'--text': 7}}, {'options': {7: 'text'}},
        {'options': {'text': 'text'}}, {'options': {'-text': 'text'}},
        {'options': {'--Text': 'text'}}, {'options': {'---': 'text'}},
        {'options': {'--': 'text'}}, {'options': {'-': 'text'}},
        {'options': {'--x=y': 'text'}}, {'options': {'-=': 'text'}},
        # ``@`` reads a file: only into a body field, never a parameter.
        {'options': {'--from': '@ticket'}}, {'options': {'--from': '@absent'}},
        {'options': {f'--o{i}': 'text' for i in range(33)}},
        {'output': 'raw'}, {'output': True}, {'run': 'sh -c id'},
    ],
)  # fmt: skip
def test_untrusted_command_rows_rejected(change):
    refused(row(**change))


@pytest.mark.parametrize(
    'cli',
    [
        [], 'tk', {'TK': []}, {'t k': []}, {'-tk': []}, {'t' * 17: []},
        {'tk': []}, {'tk': 'view'}, {'tk': [{}]}, {'tk': ['view']},
        # The client's own verbs cannot be taken over by a table.
        {'aivm': None}, {'as': None}, {'invoke': None}, {'operations': None},
        {'delegate': None}, {'renounce': None},
        # ... nor can the programs the client is started through.
        {'env': None}, {'python3': None}, {'python': None}, {'sh': None},
        {f'a{i}': None for i in range(5)},
    ],
)  # fmt: skip
def test_untrusted_command_tables_rejected(cli):
    good = [{'command': ['x'], 'operation': 'ticket.log'}]
    if isinstance(cli, dict):
        cli = {key: good if rows is None else rows for key, rows in cli.items()}
    refused(tracker_policy(cli=cli))


def test_a_table_cannot_be_longer_than_the_client_would_read():
    rows = [
        {'command': [f'c{i}'], 'operation': 'ticket.log'} for i in range(129)
    ]
    refused(tracker_policy(cli={'tk': rows}))
    assert tracker(cli={'tk': rows[:128]}).client_aliases == ('tk',)


# -- rejected manifests ------------------------------------------------------


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
                {'name': f'o{i}', 'effect': 'read', 'method': 'GET', 'path': '/x'}
                for i in range(65)
            ]
        },
        {'lifetime_seconds': 3601},
        {'lifetime_seconds': 0},
        {'max_requests': 1001},
        {'max_body_bytes': 16385},
        {'unexpected': 1},
        {'allow_writes': True},
        {'plugins': ['os.system']},
    ],
)  # fmt: skip
def test_untrusted_egress_templates_rejected(change):
    with pytest.raises(SecretsError) as caught:
        spec(**change)
    assert caught.value.code == 'invalid_policy'


@pytest.mark.parametrize(
    'operation',
    [
        {'method': 'DELETE', 'effect': 'write'},
        {'method': 'PUT', 'effect': 'write'},
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
        {'method': 'POST', 'effect': 'write'},  # a body method declares one
        {'method': 'POST', 'effect': 'write', 'body_fields': {'body': 0}},
        {'method': 'POST', 'effect': 'write', 'body_fields': {'body': 16385}},
        {'method': 'POST', 'effect': 'write', 'body_fields': {'Body': 10}},
        {'method': 'POST', 'effect': 'write', 'body_fields': {'body': '10'}},
        {'method': 'POST', 'effect': 'write',
         'body_fields': {'body': {'max_bytes': 10, 'optional': 'no'}}},
        {'method': 'POST', 'effect': 'write',
         'body_fields': {'body': {'optional': True}}},
        {'method': 'POST', 'effect': 'write',
         'body_fields': {'body': {'max_bytes': 10, 'pattern': '.*'}}},
        {'method': 'POST', 'effect': 'write', 'path': '/v1/{a}',
         'parameters': {'a': [1]}, 'body_fields': {'a': 10}},
        {'response': 'binary'},
        {'response': ['json']},
        {'accept': 'application/json, */*'},
        {'name': 'Bad Name'},
        {'headers': {'X': 'y'}},
        {'url': 'https://attacker.invalid'},
        {'parameters': {f'p{i}': [1] for i in range(17)}},
    ],
)  # fmt: skip
def test_untrusted_operation_templates_rejected(operation):
    with pytest.raises(SecretsError) as caught:
        one(**operation)
    assert caught.value.code == 'invalid_policy'


def test_operation_names_are_unique():
    duplicate = [
        {'name': 'same', 'effect': 'read', 'method': 'GET', 'path': '/a'},
        {'name': 'same', 'effect': 'read', 'method': 'GET', 'path': '/b'},
    ]
    with pytest.raises(SecretsError):
        spec(operations=duplicate)


def test_a_body_made_only_of_optional_fields_may_not_be_sent_empty():
    policy = tracker(
        **edited(
            NOTE,
            body_fields={
                'text': {'max_bytes': 100, 'optional': True},
                'title': {'max_bytes': 20, 'optional': True},
            },
        )
    )
    scope = find(policy.scope(), 'ticket.note')
    assert [item.required for item in scope.fields] == [False, False]
    assert check_arguments(scope, ticket(policy, 'ticket.note', title='T')) == 1
    with pytest.raises(SecretsError) as caught:
        check_arguments(scope, ticket(policy, 'ticket.note'))
    assert caught.value.code == 'invalid_request'
    assert isinstance(dict(scope.parameters)['project'], StrSet)


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
