import json
from dataclasses import replace

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.wire import dumps, loads
from tests.secrets_helpers import Harness, TOKEN


@pytest.fixture
def h(tmp_path):
    instance = Harness(tmp_path)
    yield instance
    instance.broker.close()


def test_view_and_audit_do_not_expose_credential(h):
    reply = h.call()
    assert reply['ok'] and reply['result']['number'] == 13861
    assert len(h.provider.calls) == 1
    assert h.provider.calls[0][1] == TOKEN
    assert TOKEN not in json.dumps(reply)
    audit = h.audit.read_text()
    assert TOKEN not in audit and h.broker.capability not in audit
    assert [json.loads(line)['event'] for line in audit.splitlines()] == [
        'session_open', 'authorized', 'completed']


@pytest.mark.parametrize('change,code', [
    ({'repository': 'other/repo'}, 'denied'), ({'pr': 9}, 'denied'),
    ({'operation': 'pr.merge'}, 'invalid_request'), ({'url': 'https://evil.invalid'}, 'invalid_request'),
    ({'owner_uid': 0}, 'invalid_request'), ({'pr': True}, 'invalid_request'),
])
def test_scope_denials_make_no_network_calls(h, change, code):
    reply = h.call(**change)
    assert reply['error']['code'] == code
    assert not h.provider.calls


def test_writes_require_both_host_opt_in_and_policy(tmp_path, h):
    assert h.call('pr.comment', body='Update')['error']['code'] == 'denied'
    assert not h.provider.calls
    allowed = Harness(tmp_path / 'allowed', allow_writes=True)
    try:
        assert allowed.call('pr.comment', body='Update')['ok']
        assert [route.method for route, _ in allowed.provider.calls] == ['GET', 'POST']
        assert allowed.provider.calls[-1][0].body == {'body': 'Update'}
        assert 'Update' not in allowed.audit.read_text()
    finally:
        allowed.broker.close()
    denied = Harness(tmp_path / 'denied', allow_writes=True, operations=['pr.view'])
    try:
        assert denied.call('pr.comment', body='Update')['error']['code'] == 'denied'
        assert not denied.provider.calls
    finally:
        denied.broker.close()


@pytest.mark.parametrize('key,value', [('number', 9), ('user', {'login': 'other'}),
                                      ('head', {'repo': {'full_name': 'Other/TauCeti'}, 'sha': 'a'*40}),
                                      ('head', {'repo': None, 'sha': 'a'*40}),
                                      ('base', {'repo': {'full_name': 'Other/TauCeti'}})])
def test_live_metadata_blocks_write_on_wrong_resource(tmp_path, key, value):
    h = Harness(tmp_path, allow_writes=True)
    h.provider.metadata[key] = value
    try:
        assert h.call('pr.comment', body='Update')['error']['code'] == 'resource_mismatch'
        assert len(h.provider.calls) == 1
        assert h.provider.calls[0][0].method == 'GET'
    finally:
        h.broker.close()


def test_expiry_and_clock_rollback(h):
    h.clock.wall = 2800
    assert h.call()['error']['code'] == 'expired'
    h.clock.wall = 1000
    h.clock.monotonic = 1900
    assert h.call()['error']['code'] == 'expired'
    assert not h.provider.calls


def test_expiry_after_metadata_prevents_write(tmp_path):
    h = Harness(tmp_path, allow_writes=True)
    h.provider.after_metadata = lambda: setattr(h.clock, 'monotonic', 9999)
    try:
        assert h.call('pr.comment', body='Update')['error']['code'] == 'expired'
        assert len(h.provider.calls) == 1
    finally:
        h.broker.close()


def test_revocation_and_close(h):
    h.broker.revoke()
    assert h.call()['error']['code'] == 'revoked'
    assert not h.provider.calls
    raw = h.raw()
    h.broker.close()
    assert h.broker.handle(raw)['error']['code'] == 'revoked'


def test_budget_reserved_on_failed_preflight(tmp_path):
    h = Harness(tmp_path, max_requests=1)
    h.provider.metadata['user']['login'] = 'other'
    try:
        assert h.call()['error']['code'] == 'resource_mismatch'
        assert h.call()['error']['code'] == 'exhausted'
        assert len(h.provider.calls) == 1
    finally:
        h.broker.close()


def test_second_dispatch_does_not_double_charge_budget(tmp_path):
    h = Harness(tmp_path, max_requests=1)
    try:
        assert h.call('pr.reviews')['ok']
        assert len(h.provider.calls) == 2
        assert h.call()['error']['code'] == 'exhausted'
    finally:
        h.broker.close()


def test_capability_cannot_be_used_in_another_session(tmp_path, h):
    other = Harness(tmp_path / 'other')
    try:
        assert other.broker.handle(h.raw())['error']['code'] == 'invalid_capability'
        assert not other.provider.calls
    finally:
        other.broker.close()


def test_even_authenticated_claims_must_match_channel_and_policy(h):
    wire = loads(h.raw())
    for claims in [replace(h.broker._claims, binding=replace(h.binding, channel='elsewhere')),
                   replace(h.broker._claims, policy_digest='0' * 64),
                   replace(h.broker._claims, grant_id='0' * 32)]:
        wire['capability'] = h.broker._codec.seal(claims, TOKEN)
        assert h.broker.handle(dumps(wire))['error']['code'] == 'wrong_binding'
    assert not h.provider.calls


def test_raw_errors_and_provider_reflection_do_not_leak(h):
    def explode(route, credential):
        raise RuntimeError('sensitive: ' + credential)
    h.provider.execute = explode
    reply = h.call()
    assert reply['error']['code'] == 'internal_error'
    assert TOKEN not in json.dumps(reply) + h.audit.read_text()


def test_provider_cannot_reflect_literal_credential(h):
    h.provider.metadata['body'] = 'leak: ' + TOKEN
    assert h.call()['error']['code'] == 'upstream_response'
    assert TOKEN not in h.audit.read_text()


def test_audit_failure_before_dispatch_is_fail_closed(h):
    def fail(*args, **kwargs):
        raise SecretsError('audit_failed')
    h.broker._audit.record = fail
    assert h.call()['error']['code'] == 'audit_failed'
    assert not h.provider.calls
    # Permit fixture teardown without hiding the tested failure.
    h.broker._audit.record = lambda *args, **kwargs: None


def test_post_write_audit_failure_reports_unknown_outcome(tmp_path):
    h = Harness(tmp_path, allow_writes=True)
    original = h.broker._audit.record
    def fail_completion(event, *args, **kwargs):
        if event == 'completed':
            raise SecretsError('audit_failed')
        return original(event, *args, **kwargs)
    h.broker._audit.record = fail_completion
    try:
        assert h.call('pr.comment', body='Update')['error']['code'] == 'outcome_unknown'
        assert len(h.provider.calls) == 2
    finally:
        h.broker.close()


def test_attempt_budget_bounds_invalid_request_audit(h):
    for _ in range(h.broker._max_attempts + 50):
        h.broker.handle(b'not json')
    assert len(h.audit.read_text().splitlines()) == h.broker._max_attempts + 1
    assert h.call()['error']['code'] == 'exhausted'
    assert not h.provider.calls


@pytest.mark.parametrize('operation', ['pr.comments', 'pr.reviews', 'pr.review-comments'])
def test_pagination_is_explicit_not_silently_complete(h, operation):
    h.provider.result = [{'id': i} for i in range(100)]
    reply = h.call(operation, page=2)
    assert reply['ok'] and reply['pagination'] == {'page': 2, 'per_page': 100, 'possibly_more': True}
    assert h.provider.calls[-1][0].path.endswith('?per_page=100&page=2')


def test_checks_use_validated_sha_and_are_not_workflow_logs(h):
    reply = h.call('pr.checks')
    assert reply['ok']
    assert '/commits/' + 'a' * 40 + '/check-runs' in h.provider.calls[-1][0].path


@pytest.mark.parametrize('bad', ['false', 1, None])
def test_write_opt_in_is_a_boolean_not_truthiness(tmp_path, bad):
    with pytest.raises(SecretsError, match='policy'):
        Harness(tmp_path, allow_writes=bad)


def test_transient_audit_failure_revokes_session(h):
    original = h.broker._audit.record
    def fail_once(event, *args, **kwargs):
        if event == 'authorized':
            raise SecretsError('audit_failed')
        return original(event, *args, **kwargs)
    h.broker._audit.record = fail_once
    assert h.call()['error']['code'] == 'audit_failed'
    h.broker._audit.record = original
    assert h.call()['error']['code'] == 'revoked'
    assert not h.provider.calls


@pytest.mark.parametrize('event,expected_calls', [('authorized', 0), ('dispatch', 1)])
def test_expiry_during_audit_prevents_next_network_dispatch(tmp_path, event, expected_calls):
    h = Harness(tmp_path, allow_writes=True)
    original = h.broker._audit.record
    def advance_clock(current, *args, **kwargs):
        original(current, *args, **kwargs)
        if current == event:
            h.clock.monotonic = 9999
    h.broker._audit.record = advance_clock
    try:
        assert h.call('pr.comment', body='Update')['error']['code'] == 'expired'
        assert len(h.provider.calls) == expected_calls
    finally:
        h.broker.close()


def test_any_failure_after_write_dispatch_requires_reconciliation(tmp_path):
    h = Harness(tmp_path, allow_writes=True)
    original = h.provider.execute
    def execute(route, credential):
        if route.method != 'GET':
            raise SecretsError('upstream_error')
        return original(route, credential)
    h.provider.execute = execute
    try:
        assert h.call('pr.comment', body='Update')['error']['code'] == 'outcome_unknown'
    finally:
        h.broker.close()
