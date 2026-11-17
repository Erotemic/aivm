"""The trusted interpreter: ordering, audit, failure handling and secrecy.

Kernel decisions are tested in ``test_secrets_machine``. These tests are
about what the broker does *around* them: that the executor only ever sees
what the kernel authorized, that audit intent precedes dispatch, that every
failure stops authority rather than widening it, and that nothing the guest
receives or the audit records contains the credential.
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from typing import Any

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.audit import verify
from aivm_secrets.kernel import codec
from aivm_secrets.kernel.model import Claims
from aivm_secrets.kernel.service import reparse
from tests.secrets_helpers import (
    PROJECT,
    REPO,
    REVISION,
    SERVICE_TOKEN,
    TOKEN,
    Harness,
    https_policy,
    tracker_facts,
    tracker_policy,
)


@pytest.fixture
def h(tmp_path):
    instance = Harness(tmp_path)
    yield instance
    instance.broker.close()


@pytest.fixture
def make(tmp_path):
    """Build further harnesses that are closed with the test."""
    made = []

    def build(name='extra', **kwargs):
        instance = Harness(tmp_path / name, **kwargs)
        made.append(instance)
        return instance

    yield build
    for instance in made:
        instance.broker.close()


@pytest.fixture
def g(make):
    """A declarative (schema 2) service."""
    return make('generic', policy=https_policy(), token=SERVICE_TOKEN)


def code(reply):
    assert reply['ok'] is False
    return reply['error']['code']


# -- reads, secrecy and audit ordering --------------------------------------


def test_view_and_audit_do_not_expose_credential(h):
    reply = h.call()
    assert reply['ok'] and reply['result']['number'] == 13861
    assert len(h.executor.calls) == 1
    assert h.executor.calls[0][1] == TOKEN
    assert TOKEN not in json.dumps(reply)
    audit = h.audit.read_text()
    assert TOKEN not in audit and h.capability not in audit
    assert h.events() == ['session_open', 'authorized', 'completed']
    row = h.rows()[1]
    assert row['operation'] == 'pr.view'
    assert row['resource'] == {'pr': 13861, 'repository': REPO.lower()}


def test_service_reads_are_fixed_origin_and_allowlisted(g):
    reply = g.invoke('issue.view', issue=23)
    assert reply['ok'] and reply['result']['path'] == '/v1/issues/23'
    assert g.executor.calls[0][1] == SERVICE_TOKEN
    assert SERVICE_TOKEN not in json.dumps(reply) + g.audit.read_text()
    # Intent to dispatch is durable before the dispatch (AUDIT-01).
    assert g.events() == ['session_open', 'authorized', 'dispatch', 'completed']
    listing = g.invoke('issue.list', page=3)
    assert listing['result']['path'] == '/v1/issues?page=3&state=open'


def test_audit_intent_is_written_before_each_provider_call(make):
    """AUDIT-01: every dispatch is preceded by its own durable record."""
    order = []
    h = make(writes='allow')
    real_record = h.broker._audit.record
    real_execute = h.executor.execute

    def record(event, *args, **kwargs):
        order.append(event)
        return real_record(event, *args, **kwargs)

    def execute(authorized, credential):
        order.append('EXECUTE:' + authorized.effect.method)
        return real_execute(authorized, credential)

    h.broker._audit.record = record
    h.executor.execute = execute
    assert h.call('pr.comment', body='Update')['ok']
    assert order == [
        'authorized', 'EXECUTE:GET', 'dispatch', 'EXECUTE:POST', 'completed',
    ]  # fmt: skip


@pytest.mark.parametrize(
    'change,expected',
    [
        ({'repository': 'other/repo'}, 'denied'),
        ({'pr': 9}, 'denied'),
        ({'operation': 'pr.merge'}, 'denied'),
        ({'url': 'https://evil.invalid'}, 'invalid_request'),
        ({'owner_uid': 0}, 'invalid_request'),
        ({'pr': True}, 'invalid_request'),
    ],
)
def test_scope_denials_make_no_network_calls(h, change, expected):
    assert code(h.call(**change)) == expected
    assert not h.executor.calls


@pytest.mark.parametrize(
    'bad,expected',
    [
        ({'issue': 25}, 'denied'),
        ({'issue': '23'}, 'denied'),
        ({'issue': True}, 'invalid_request'),
        ({'issue': 23, 'url': 'https://elsewhere.example'}, 'invalid_request'),
        ({}, 'invalid_request'),
    ],
)
def test_arguments_fail_closed_without_egress(g, bad, expected):
    assert code(g.invoke('issue.view', **bad)) == expected
    assert not g.executor.calls


def test_unsupported_operation_does_not_reach_provider(g):
    assert code(g.invoke('tool.exec', args='sudo rm -rf /')) == 'denied'
    assert not g.executor.calls
    assert 'sudo' not in g.audit.read_text()


@pytest.mark.parametrize(
    'frame',
    [
        b'not json',
        b'',
        b'[]',
        b'{"version":1}',
        b'{"version":2,"capability":"x","request":{}}',
        b'{"version":1,"capability":"x","request":{},"describe":true}',
        b'{"version":1,"capability":"x","exec":["id"]}',
        b'{"version":1,"capability":"x","approve":"' + b'a' * 64 + b'"}',
        b'{"version":1,"capability":"x","command":"revoke"}',
        b'{"version":1,"capability":"x","describe":false}',
        b'{"version":1,"capability":7,"describe":true}',
        b'{"version":1,"capability":"x","request":{},"extra":1}',
    ],
)
def test_guest_frames_are_a_closed_grammar(h, frame):
    """No frame reaches the host control plane or names a host program."""
    assert code(h.broker.handle(frame)) == 'invalid_request'
    assert not h.executor.calls


# -- writes ------------------------------------------------------------------


def test_writes_require_both_host_opt_in_and_policy(h, make):
    assert code(h.call('pr.comment', body='Update')) == 'denied'
    assert not h.executor.calls
    allowed = make('allowed', writes='allow')
    assert allowed.call('pr.comment', body='Update')['ok']
    assert allowed.executor.methods == ['GET', 'POST']
    assert allowed.executor.calls[-1][0].body == (('body', 'Update'),)
    assert 'Update' not in allowed.audit.read_text()
    denied = make('denied', writes='allow', operations=['pr.view'])
    assert code(denied.call('pr.comment', body='Update')) == 'denied'
    assert not denied.executor.calls


def test_writes_require_policy_and_host_enablement(g, make):
    assert code(g.invoke('issue.comment', issue=23, body='hello')) == 'denied'
    assert not g.executor.calls
    w = make('w', policy=https_policy(), writes='allow')
    assert w.invoke('issue.comment', issue=24, body='hello')['ok']
    effect = w.executor.calls[-1][0]
    assert (effect.method, effect.path) == ('POST', '/v1/issues/24/comments')
    assert effect.body == (('body', 'hello'),)
    assert 'hello' not in w.audit.read_text()


@pytest.mark.parametrize('bad', ['false', 'true', '', 1, None, True, 'ALLOW'])
def test_write_opt_in_is_a_closed_choice_not_truthiness(tmp_path, bad):
    with pytest.raises(SecretsError, match='policy'):
        Harness(tmp_path, writes=bad)


@pytest.mark.parametrize(
    'key,value',
    [
        ('number', 9),
        ('user', {'login': 'other'}),
        ('head', {'repo': {'full_name': 'Other/TauCeti'}, 'sha': 'a' * 40}),
        ('head', {'repo': None, 'sha': 'a' * 40}),
        ('base', {'repo': {'full_name': 'Other/TauCeti'}}),
    ],
)
def test_live_metadata_blocks_write_on_wrong_resource(make, key, value):
    h = make(writes='allow')
    h.executor.metadata[key] = value
    assert code(h.call('pr.comment', body='Update')) == 'resource_mismatch'
    assert h.executor.methods == ['GET']
    # No dispatch intent was recorded for a write that was never attempted.
    assert h.events() == ['session_open', 'authorized', 'rejected_or_failed']


# -- time, budget and revocation ---------------------------------------------


def test_expiry_and_clock_rollback(h):
    h.clock.wall = 2800
    assert code(h.call()) == 'expired'
    h.clock.wall = 1000
    h.clock.monotonic = 1900
    assert code(h.call()) == 'expired'
    assert not h.executor.calls


def test_expiry_after_metadata_prevents_write(make):
    h = make(writes='allow')
    h.executor.after_metadata = lambda: setattr(h.clock, 'monotonic', 9999)
    assert code(h.call('pr.comment', body='Update')) == 'expired'
    assert h.executor.methods == ['GET']


@pytest.mark.parametrize(
    'event,expected_calls', [('authorized', 0), ('dispatch', 1)]
)
def test_expiry_during_audit_prevents_next_network_dispatch(
    make, event, expected_calls
):
    h = make(writes='allow')
    original = h.broker._audit.record

    def advance_clock(current, *args, **kwargs):
        original(current, *args, **kwargs)
        if current == event:
            h.clock.monotonic = 9999

    h.broker._audit.record = advance_clock
    assert code(h.call('pr.comment', body='Update')) == 'expired'
    assert len(h.executor.calls) == expected_calls


def test_revocation_and_close(h):
    h.broker.revoke()
    assert code(h.call()) == 'revoked'
    assert not h.executor.calls
    raw = h.raw()
    h.broker.close()
    assert code(h.broker.handle(raw)) == 'revoked'
    assert h.broker.capability == ''
    h.broker.close()  # idempotent
    assert h.events()[-1] == 'session_close'
    assert h.events().count('session_close') == 1


def test_revocation_lands_between_the_metadata_read_and_the_write(make):
    """REVOKE-01: revoke does not wait for the request in flight.

    The provider is mid-preflight when a host revoke arrives from another
    thread. It must not block behind the request, and the write must not go.
    """
    h = make(writes='allow')
    h.executor.after_metadata = h.broker.revoke
    assert code(h.call('pr.comment', body='Update')) == 'revoked'
    assert h.executor.methods == ['GET']
    assert 'dispatch' in h.events()  # intent was logged, then refused
    assert code(h.call()) == 'revoked'


def test_host_revoke_is_not_blocked_by_a_slow_provider(make):
    h = make()
    entered, release = threading.Event(), threading.Event()

    def slow(authorized, credential):
        entered.set()
        assert release.wait(10)
        return h.executor.metadata

    h.executor.execute = slow
    worker = threading.Thread(target=h.call)
    worker.start()
    assert entered.wait(10)
    done = threading.Event()
    threading.Thread(target=lambda: (h.broker.revoke(), done.set())).start()
    assert done.wait(2), 'revoke waited for the provider'
    assert h.broker.status()['active'] is False
    release.set()
    worker.join(10)


def test_budget_reserved_on_failed_preflight(make):
    h = make(max_requests=1)
    h.executor.metadata['user']['login'] = 'other'
    assert code(h.call()) == 'resource_mismatch'
    assert code(h.call()) == 'exhausted'
    assert len(h.executor.calls) == 1


def test_second_dispatch_does_not_double_charge_budget(make):
    h = make(max_requests=1)
    assert h.call('pr.reviews')['ok']
    assert len(h.executor.calls) == 2
    assert code(h.call()) == 'exhausted'


def test_one_budget_unit_per_action_and_revoke(make):
    h = make(policy=https_policy(max_requests=1))
    assert h.invoke('profile.read')['ok']
    assert code(h.invoke('profile.read')) == 'exhausted'
    h.broker.revoke()
    assert code(h.invoke('profile.read')) == 'revoked'


def test_concurrent_requests_cannot_exceed_session_budget(make):
    h = make(policy=https_policy(max_requests=7))
    replies = []

    def hammer():
        for _ in range(5):
            replies.append(h.invoke('profile.read'))

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(reply['ok'] for reply in replies) == 7 == len(h.executor.calls)
    assert {code(r) for r in replies if not r['ok']} <= {'exhausted'}
    assert h.broker.status()['used'] == 7


def test_attempt_budget_bounds_invalid_request_audit(h):
    cap = h.broker.status()
    limit = 4 * cap['max_requests'] + 16
    for _ in range(limit + 50):
        h.broker.handle(b'not json')
    assert len(h.rows()) == limit + 1
    assert code(h.call()) == 'exhausted'
    assert not h.executor.calls
    assert h.broker.status()['attempts'] == limit


# -- binding -----------------------------------------------------------------


def test_capability_cannot_be_used_in_another_session(h, make):
    other = make('other')
    assert code(other.broker.handle(h.raw())) == 'invalid_capability'
    assert not other.executor.calls


def test_even_authenticated_claims_must_match_channel_and_policy(h):
    opened = h.broker._codec.open(h.capability)
    for claims in [
        replace(opened.claims, binding=replace(h.binding, channel='elsewhere')),
        replace(opened.claims, policy_digest='0' * 64),
        replace(opened.claims, grant_id='0' * 32),
    ]:
        forged = h.broker._codec.seal(claims, TOKEN)
        reply = h.broker.handle(h.frame('describe', True, forged))
        assert code(reply) == 'wrong_binding'
        view = {
            'operation': 'pr.view',
            'arguments': {'repository': REPO, 'pr': 13861},
        }
        reply = h.broker.handle(h.frame('request', view, forged))
        assert code(reply) == 'wrong_binding'
    assert not h.executor.calls


# -- failure handling --------------------------------------------------------


def test_raw_errors_and_provider_reflection_do_not_leak(h):
    def explode(authorized, credential):
        raise RuntimeError('sensitive: ' + credential)

    h.executor.execute = explode
    reply = h.call()
    assert code(reply) == 'internal_error'
    assert TOKEN not in json.dumps(reply) + h.audit.read_text()
    assert 'sensitive' not in json.dumps(reply) + h.audit.read_text()


def test_provider_cannot_reflect_literal_credential(h):
    h.executor.metadata['body'] = 'leak: ' + TOKEN
    assert code(h.call()) == 'upstream_response'
    assert TOKEN not in h.audit.read_text()


def test_response_must_not_reflect_provider_secret(g):
    g.executor.execute = lambda authorized, secret: {
        'nested': [{'secret': secret}]
    }
    reply = g.invoke('profile.read')
    assert code(reply) == 'upstream_response'
    assert SERVICE_TOKEN not in json.dumps(reply) + g.audit.read_text()


def test_unencodable_provider_data_is_an_upstream_fault(g):
    g.executor.execute = lambda authorized, secret: {'value': float('nan')}
    assert code(g.invoke('profile.read')) == 'upstream_response'


def test_audit_failure_before_dispatch_is_fail_closed(h):
    def fail(*args, **kwargs):
        raise SecretsError('audit_failed')

    h.broker._audit.record = fail
    assert code(h.call()) == 'audit_failed'
    assert not h.executor.calls
    # Permit fixture teardown without hiding the tested failure.
    h.broker._audit.record = lambda *args, **kwargs: None


def test_transient_audit_failure_revokes_session(h):
    original = h.broker._audit.record

    def fail_once(event, *args, **kwargs):
        if event == 'authorized':
            raise SecretsError('audit_failed')
        return original(event, *args, **kwargs)

    h.broker._audit.record = fail_once
    assert code(h.call()) == 'audit_failed'
    h.broker._audit.record = original
    assert code(h.call()) == 'revoked'
    assert not h.executor.calls


def test_post_write_audit_failure_reports_unknown_outcome(make):
    h = make(writes='allow')
    original = h.broker._audit.record

    def fail_completion(event, *args, **kwargs):
        if event == 'completed':
            raise SecretsError('audit_failed')
        return original(event, *args, **kwargs)

    h.broker._audit.record = fail_completion
    assert code(h.call('pr.comment', body='Update')) == 'outcome_unknown'
    assert len(h.executor.calls) == 2
    h.broker._audit.record = original
    assert code(h.call()) == 'revoked'  # an audit failure ends the session


@pytest.mark.parametrize(
    'raised,reported',
    [
        (SecretsError('upstream_error'), 'outcome_unknown'),
        (SecretsError('upstream_error', status=503), 'outcome_unknown'),
        (SecretsError('upstream_response'), 'outcome_unknown'),
        (SecretsError('outcome_unknown'), 'outcome_unknown'),
        (SecretsError('internal_error'), 'outcome_unknown'),
        (RuntimeError('boom'), 'outcome_unknown'),
        # A 4xx is not proof either: a service may apply a write and then
        # answer 409 or 422. Only its own contract could say otherwise.
        (SecretsError('upstream_rejected', status=409), 'outcome_unknown'),
        (SecretsError('upstream_rejected', status=422), 'outcome_unknown'),
        (SecretsError('outcome_unknown', status=404), 'outcome_unknown'),
        # The one definite answer about a dispatched write: nothing was sent.
        (SecretsError('unreachable'), 'unreachable'),
    ],
)
def test_any_failure_after_write_dispatch_requires_reconciliation(
    make, raised, reported
):
    h = make(writes='allow')
    original = h.executor.execute

    def execute(authorized, credential):
        if authorized.write:
            raise raised
        return original(authorized, credential)

    h.executor.execute = execute
    reply = h.call('pr.comment', body='Update')
    assert code(reply) == reported
    status = getattr(raised, 'status', 0)
    # The status the service gave is kept as a datum beside the verdict.
    assert reply['error'].get('status') == (status or None)
    assert h.rows()[-1].get('status') == (status or None)
    assert h.rows()[-1]['code'] == reported


def test_a_failed_fact_fetch_before_a_write_is_not_an_unknown_outcome(make):
    """Nothing was dispatched yet: the read's own failure is the answer."""
    h = make(writes='allow')

    def execute(authorized, credential):
        assert not authorized.final and not authorized.write
        raise SecretsError('upstream_rejected', status=404)

    h.executor.execute = execute
    reply = h.call('pr.comment', body='Update')
    assert reply['error']['code'] == 'upstream_rejected'
    assert reply['error']['status'] == 404
    assert 'dispatch' not in h.events()


def test_read_failures_keep_their_own_code_and_status(g):
    def execute(authorized, credential):
        raise SecretsError('upstream_rejected', status=404)

    g.executor.execute = execute
    reply = g.invoke('issue.view', issue=23)
    assert reply['error'] == {
        'code': 'upstream_rejected',
        'message': 'Service refused the read request.',
        'status': 404,
    }


# -- a generic manifest: declared effects, fact checks, command tables ------


@pytest.fixture
def tracker(make):
    def build(writes='deny', **changes):
        instance = make(
            f'tracker-{writes}',
            policy=tracker_policy(**changes),
            token=SERVICE_TOKEN,
            writes=writes,
        )
        instance.executor.metadata = tracker_facts()
        return instance

    return build


TICKET = {'project': PROJECT, 'ticket': 7}


def test_a_declared_write_get_is_refused_until_the_host_allows_writes(tracker):
    """``ticket.close`` is a GET. It is gated by ``effect``, not by method."""
    denied = tracker('deny')
    assert code(denied.invoke('ticket.close', **TICKET)) == 'denied'
    assert not denied.executor.calls
    # An ordinary read on the same session still works.
    assert denied.invoke('ticket.log', ticket=7)['ok']

    waiting = tracker('approve')
    reply = waiting.invoke('ticket.close', **TICKET)
    assert code(reply) == 'approval_required' and not waiting.executor.calls
    digest = reply['approval']['digest']
    (pending,) = waiting.broker.control({'command': 'pending'})['pending']
    assert pending['operation'] == 'ticket.close'
    assert waiting.broker.control({'command': 'approve', 'digest': digest})[
        'ok'
    ]
    assert waiting.invoke('ticket.close', **TICKET)['ok']
    assert code(waiting.invoke('ticket.close', **TICKET)) == 'approval_required'

    allowed = tracker('allow')
    assert allowed.invoke('ticket.close', **TICKET)['ok']
    ((effect, _),) = allowed.executor.calls
    assert (effect.method, effect.body) == ('GET', None)
    assert effect.target == '/v1/projects/acme/widgets/tickets/7/close'
    events = allowed.events()
    assert events.index('dispatch') < events.index('completed')


@pytest.mark.parametrize('status', [404, 409, 500])
def test_a_failed_declared_write_get_is_an_unknown_outcome(tracker, status):
    h = tracker('allow')
    seen = []

    def execute(authorized, credential):
        seen.append(authorized)
        code_ = 'upstream_rejected' if status < 500 else 'upstream_error'
        raise SecretsError(code_, status=status)

    h.executor.execute = execute
    reply = h.invoke('ticket.close', **TICKET)
    assert reply['error']['code'] == 'outcome_unknown'
    assert reply['error']['status'] == status
    (authorized,) = seen
    assert authorized.write and authorized.effect.method == 'GET'
    assert h.rows()[-1]['code'] == 'outcome_unknown'


def test_a_fact_check_gates_and_can_answer_a_generic_operation(tracker):
    h = tracker('allow')
    view = h.invoke('ticket.view', project='ACME/Widgets', ticket=7)
    assert view['ok'] and view['result'] == tracker_facts()
    assert [e.target for e, _ in h.executor.calls] == [
        '/v1/projects/acme/widgets/tickets/7'
    ]
    builds = h.invoke('ticket.builds', **TICKET)
    assert builds['ok']
    assert h.executor.calls[-1][0].target == (
        f'/v1/projects/acme/widgets/revisions/{REVISION}/builds/31/main'
        '?page=1&per_page=50'
    )
    note = h.invoke('ticket.note', text='NOTE-TEXT', **TICKET)
    assert note['ok'] and note['result']['body'] == {'text': 'NOTE-TEXT'}
    assert h.executor.methods == ['GET', 'GET', 'GET', 'GET', 'POST']
    # The recorded resource is the normalized request, never a body.
    row = [r for r in h.rows() if r['event'] == 'completed'][-1]
    assert row['resource'] == {'project': PROJECT, 'ticket': 7}
    assert 'NOTE-TEXT' not in json.dumps(h.rows())


@pytest.mark.parametrize(
    'path,value',
    [
        (('id',), 8),
        (('owner', 'name'), 'mallory'),
        (('state',), 'closed'),
        (('project', 'slug'), 'acme/gadgets'),
        (('head', 'rev'), '../../admin'),
        (('branch',), 'a/b'),
    ],
)
def test_a_failed_fact_check_prevents_every_later_effect(tracker, path, value):
    h = tracker('allow')
    target = h.executor.metadata
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    for operation, extra in (
        ('ticket.note', {'text': 'hi'}),
        ('ticket.builds', {}),
    ):
        reply = h.invoke(operation, **TICKET, **extra)
        assert code(reply) == 'resource_mismatch'
    # One fact fetch each, and never a second request.
    assert h.executor.methods == ['GET', 'GET']
    assert 'dispatch' not in h.events()
    assert h.broker.status()['used'] == 2  # the budget is spent regardless


def test_generic_pagination_reaches_the_reply(tracker):
    h = tracker()
    h.executor.result = [{}] * 50
    reply = h.invoke('ticket.builds', page=3, **TICKET)
    assert reply['pagination'] == {
        'page': 3,
        'per_page': 50,
        'possibly_more': True,
    }
    h.executor.result = [{}] * 51
    assert code(h.invoke('ticket.builds', **TICKET)) == 'upstream_response'


def test_describe_carries_the_command_tables_as_plain_data(h, g, tracker):
    """The guest client learns how to phrase requests; it is granted nothing."""
    assert g.send('describe')['cli'] == {}
    gh = h.send('describe')['cli']
    assert list(gh) == ['gh']
    assert {' '.join(row['command']) for row in gh['gh']} == {
        'pr view', 'pr diff', 'pr comments', 'pr reviews',
        'pr review-comments', 'pr checks', 'pr comment', 'pr edit',
    }  # fmt: skip
    t = tracker()
    described = t.send('describe')
    assert described['cli'] == t.spec.cli_tables()
    assert not (h.executor.calls or g.executor.calls or t.executor.calls)
    text = json.dumps(described)
    for hidden in ('api.example.org', 'mytool', SERVICE_TOKEN, 'owner'):
        assert hidden not in text


def test_pagination_reaches_the_reply(h):
    h.executor.result = [{'id': i} for i in range(100)]
    reply = h.call('pr.comments', page=2)
    assert reply['ok'] and reply['pagination'] == {
        'page': 2, 'per_page': 100, 'possibly_more': True,
    }  # fmt: skip
    assert h.executor.calls[-1][0].target.endswith('?page=2&per_page=100')
    h.executor.result = [{'id': i} for i in range(101)]
    assert code(h.call('pr.comments')) == 'upstream_response'


def test_checks_use_validated_sha_and_are_not_workflow_logs(h):
    assert h.call('pr.checks')['ok']
    assert (
        '/commits/' + 'a' * 40 + '/check-runs' in h.executor.calls[-1][0].target
    )


def test_the_executor_only_ever_receives_kernel_authorizations(make):
    """EFFECT-01 at the interpreter: FakeExecutor asserts the type per call."""
    h = make(writes='allow')
    for operation, extra in [
        ('pr.view', {}), ('pr.diff', {}), ('pr.reviews', {'page': 3}),
        ('pr.checks', {}), ('pr.comment', {'body': 'x'}), ('pr.edit', {'title': 't'}),
    ]:  # fmt: skip
        assert h.call(operation, **extra)['ok']
    assert h.executor.methods == [
        'GET', 'GET', 'GET', 'GET', 'GET', 'GET', 'GET', 'GET', 'POST', 'GET', 'PATCH',
    ]  # fmt: skip
    assert all(credential == TOKEN for _, credential in h.executor.calls)
    assert all(
        effect.path.startswith('/repos/') for effect, _ in h.executor.calls
    )


# -- describe, delegate, renounce -------------------------------------------


def test_describe_shows_the_grant_and_nothing_about_the_host(g):
    reply = g.send('describe')
    grant = reply['grant']
    assert grant['remaining_requests'] == 5 and grant['writes'] == 'deny'
    assert [op['name'] for op in grant['operations']] == [
        'issue.comment', 'issue.list', 'issue.view', 'profile.read',
    ]  # fmt: skip
    text = json.dumps(reply)
    for hidden in ('api.example.org', 'mytool', 'x-api-key', SERVICE_TOKEN):
        assert hidden not in text
    assert not g.executor.calls
    assert g.broker.status()['used'] == 0  # an attempt, not a request


def test_a_delegated_capability_is_smaller_and_spends_the_parents_budget(g):
    narrowing = {
        'operations': {'issue.view': {'issue': [23]}},
        'max_requests': 2,
        'lifetime_seconds': 60,
    }
    reply = g.send('delegate', narrowing)
    child = reply['capability']
    assert child.startswith('aivs1.') and child != g.capability
    assert reply['grant']['remaining_requests'] == 2
    assert reply['grant']['operations'][0]['parameters'] == {'issue': [23]}
    assert g.invoke('issue.view', child, issue=23)['ok']
    assert code(g.invoke('issue.view', child, issue=24)) == 'denied'
    assert code(g.invoke('profile.read', child)) == 'denied'
    assert g.invoke('issue.view', child, issue=23)['ok']
    assert code(g.invoke('issue.view', child, issue=23)) == 'exhausted'
    # The parent paid for the child's two requests.
    assert g.send('describe')['grant']['remaining_requests'] == 3
    # The child carries the same sealed credential and nothing readable.
    assert SERVICE_TOKEN not in child
    assert g.executor.calls[0][1] == SERVICE_TOKEN
    assert 'delegated' in g.events()
    # Expiry follows the child's own, shorter clock.
    g.clock.wall, g.clock.monotonic = 1060, 160
    assert code(g.send('describe', True, child)) == 'expired'
    assert g.send('describe')['ok']


@pytest.mark.parametrize(
    'narrowing,expected',
    [
        ({'operations': {'issue.view': {'issue': [25]}}}, 'denied'),
        ({'operations': {'issue.delete': {}}}, 'denied'),
        ({'operations': {'issue.view': {}}, 'max_requests': 6}, 'denied'),
        (
            {'operations': {'issue.view': {}}, 'writes': 'allow'},
            'invalid_request',
        ),
        ({'operations': {}}, 'invalid_request'),
        ('everything', 'invalid_request'),
    ],
)
def test_delegation_cannot_widen(g, narrowing, expected):
    assert code(g.send('delegate', narrowing)) == expected
    assert g.broker.status()['grants'] == 1


def test_a_child_cannot_delegate_past_itself_or_approve_itself(make):
    g = make(policy=https_policy(), writes='approve')
    child = g.send('delegate', {'operations': {'issue.view': {'issue': [23]}}})[
        'capability'
    ]
    wider = {'operations': {'issue.view': {'issue': [23, 24]}}}
    assert code(g.send('delegate', wider, child)) == 'denied'
    assert (
        code(g.send('delegate', {'operations': {'issue.comment': {}}}, child))
        == 'denied'
    )
    grandchild = g.send('delegate', {'operations': {'issue.view': {}}}, child)
    assert grandchild['grant']['operations'][0]['parameters'] == {'issue': [23]}


def test_renounce_and_host_revocation_of_one_grant(g):
    child = g.send('delegate', {'operations': {'issue.view': {}}})
    assert g.send('renounce', True, child['capability'])['ok']
    assert (
        code(g.invoke('issue.view', child['capability'], issue=23)) == 'revoked'
    )
    assert g.invoke('issue.view', issue=23)['ok']
    assert 'renounced' in g.events()
    other = g.send('delegate', {'operations': {'issue.view': {}}})
    grant_id = other['grant']['grant']
    assert g.broker.control({'command': 'revoke', 'grant': grant_id})['ok']
    assert (
        code(g.invoke('issue.view', other['capability'], issue=23)) == 'revoked'
    )
    assert g.invoke('issue.view', issue=23)['ok']
    assert (
        code(g.broker.control({'command': 'revoke', 'grant': '0' * 32}))
        == 'invalid_request'
    )


# -- approvals and the host control plane ------------------------------------


def test_a_write_waits_for_exactly_one_host_approval(make):
    """APPROVAL-01 end to end through both planes of the broker."""
    g = make(policy=https_policy(), writes='approve')
    reply = g.invoke('issue.comment', issue=23, body='ship it')
    assert code(reply) == 'approval_required'
    digest = reply['approval']['digest']
    assert not g.executor.calls and g.broker.status()['used'] == 0
    # The operator sees the exact content, not a summary of it.
    pending = g.broker.control({'command': 'pending'})['pending']
    assert [(p['digest'], p['operation'], p['arguments']) for p in pending] == [
        (digest, 'issue.comment', {'issue': 23, 'body': 'ship it'})
    ]
    # ...which the audit does not.
    assert 'ship it' not in g.audit.read_text()
    assert g.broker.control({'command': 'approve', 'digest': digest[:12]})['ok']
    assert g.broker.control({'command': 'pending'})['pending'] == []
    # Different bytes are a different request.
    assert (
        code(g.invoke('issue.comment', issue=23, body='ship it!'))
        == 'approval_required'
    )
    assert g.invoke('issue.comment', issue=23, body='ship it')['ok']
    assert g.executor.calls[-1][0].body == (('body', 'ship it'),)
    assert len(g.executor.calls) == 1
    # One approval, one write.
    assert (
        code(g.invoke('issue.comment', issue=23, body='ship it'))
        == 'approval_required'
    )
    events = g.events()
    assert (
        events.count('approval_requested') == 3
        and events.count('approved') == 1
    )
    assert g.invoke('issue.view', issue=23)['ok']  # reads never wait


def test_approval_needs_a_pending_request_the_operator_could_see(make):
    g = make(policy=https_policy(), writes='approve')
    unseen = 'f' * 64
    assert (
        code(g.broker.control({'command': 'approve', 'digest': unseen}))
        == 'invalid_request'
    )
    one = g.invoke('issue.comment', issue=23, body='one')['approval']['digest']
    two = g.invoke('issue.comment', issue=23, body='two')['approval']['digest']
    assert one != two
    for ambiguous in ('', 'abc', one[:7], 7, None):
        reply = g.broker.control({'command': 'approve', 'digest': ambiguous})
        assert code(reply) == 'invalid_request'
    assert (
        code(g.broker.control({'command': 'approve', 'digest': one, 'ttl': 0}))
        == 'invalid_request'
    )
    assert g.broker.control({'command': 'deny', 'digest': one})['ok']
    assert (
        code(g.invoke('issue.comment', issue=23, body='one'))
        == 'approval_required'
    )
    assert not g.executor.calls


def test_pending_queue_is_bounded(make):
    g = make(policy=https_policy(max_requests=40), writes='approve')
    for index in range(20):
        g.invoke('issue.comment', issue=23, body=f'message {index}')
    pending = g.broker.control({'command': 'pending'})['pending']
    assert len(pending) == 16
    assert pending[-1]['arguments']['body'] == 'message 19'
    assert pending[0]['arguments']['body'] == 'message 4'  # oldest were dropped


def test_approvals_do_not_exist_outside_approve_mode(g):
    assert code(g.invoke('issue.comment', issue=23, body='x')) == 'denied'
    assert g.broker.control({'command': 'pending'})['pending'] == []
    assert (
        code(g.broker.control({'command': 'approve', 'digest': 'a' * 64}))
        == 'invalid_request'
    )


@pytest.mark.parametrize(
    'command', [None, [], 'status', {}, {'command': 'exec'}, {'command': ['status']},
                {'command': 'revoke', 'grant': 7}]
)  # fmt: skip
def test_control_commands_are_a_closed_set(h, command):
    assert code(h.broker.control(command)) == 'invalid_request'


def test_status_is_descriptive_and_secret_free(g):
    g.invoke('issue.view', issue=23)
    status = g.broker.control({'command': 'status'})['session']
    assert status['service'] == 'demo-service' and status['vm'] == 'vm-test'
    assert status['access_identity'] == 'principal-test'
    assert (status['used'], status['max_requests'], status['active']) == (
        1,
        5,
        True,
    )
    assert status['operations'] == [
        'issue.comment',
        'issue.list',
        'issue.view',
        'profile.read',
    ]
    assert status['audit'] == str(g.audit)
    text = json.dumps(status)
    assert SERVICE_TOKEN not in text and g.capability not in text
    g.broker.revoke()
    assert g.broker.status()['active'] is False


# -- the audit file as a whole ----------------------------------------------


def test_a_whole_session_leaves_a_verifiable_secret_free_audit(make):
    g = make(policy=https_policy(max_requests=20), writes='approve')
    secret_body = 'confidential review text 9f8e7d'
    g.invoke('issue.view', issue=23)
    g.invoke('issue.view', issue=99)
    g.invoke('issue.view', issue='<script>' + 'A' * 500)
    digest = g.invoke('issue.comment', issue=23, body=secret_body)['approval'][
        'digest'
    ]
    g.broker.control({'command': 'approve', 'digest': digest})
    assert g.invoke('issue.comment', issue=23, body=secret_body)['ok']
    child = g.send('delegate', {'operations': {'issue.view': {}}})['capability']
    g.invoke('issue.view', child, issue=24)
    g.broker.handle(b'garbage \xff')
    g.broker.close()
    count, head = verify(g.audit)
    assert count == len(g.rows()) and head == g.broker.status()['audit_head']
    text = g.audit.read_text()
    for forbidden in (
        SERVICE_TOKEN,
        g.capability,
        child,
        secret_body,
        '<script>',
        'AAAA',
    ):
        assert forbidden not in text
    events = g.events()
    assert events[0] == 'session_open' and events[-1] == 'session_close'
    # Arguments are recorded only once the kernel has validated them.
    for row in g.rows():
        if row['event'] == 'rejected_or_failed':
            assert 'resource' not in row
        for value in row.get('resource', {}).values():
            assert value in (23, 24)


def test_a_broker_reparses_its_spec_and_binding(h, tmp_path):
    """A spec edited in memory cannot define a session the parser would refuse."""
    from aivm_secrets.host.broker import Broker

    comment = next(op for op in h.spec.operations if op.name == 'pr.comment')
    others = tuple(op for op in h.spec.operations if op is not comment)
    edits: list[Any] = [
        replace(h.spec, max_requests=10**6),
        replace(h.spec, lifetime_seconds=10**6),
        replace(h.spec, operations=()),
        replace(h.spec, service='../../orgs/x'),
        # A write quietly reclassified as a read ...
        replace(h.spec, operations=others + (replace(comment, write=False),)),
        replace(
            h.spec,
            operations=others
            + (replace(comment, template=('repos', '..', 'admin')),),
        ),
        object(),
    ]
    for tampered in edits:
        with pytest.raises(SecretsError) as caught:
            Broker(tampered, h.binding, TOKEN, tmp_path / 'never.jsonl')
        assert caught.value.code == 'invalid_policy'
    # An edit that happens to be a valid policy is honestly a different one:
    # the session it would define carries a different digest.
    released = replace(
        h.spec, operations=others + (replace(comment, requires=''),)
    )
    assert reparse(released).digest != h.spec.digest
    with pytest.raises(SecretsError):
        Broker(
            h.spec,
            replace(h.binding, owner_uid=-1),
            TOKEN,
            tmp_path / 'never.jsonl',
        )
    assert not (tmp_path / 'never.jsonl').exists()


def test_capability_claims_are_what_the_kernel_issued(h):
    opened = h.broker._codec.open(h.capability)
    assert isinstance(opened.claims, Claims)
    assert opened.claims.binding == h.binding
    assert opened.claims.policy_digest == h.spec.digest
    assert (opened.claims.issued_at, opened.claims.expires_at) == (1000, 2800)
    assert h.broker.expires_at == 2800
    assert codec.dumps(opened.credential) == codec.dumps(TOKEN)
