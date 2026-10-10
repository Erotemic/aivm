"""The secret-use state machine, one transition at a time.

Each test names the assurance-plan theorem it is evidence for. These are
regressions and bounded enumerations, not proofs: they state, executably,
what the Rust/Lean port must establish for all inputs.
"""

from __future__ import annotations

from dataclasses import replace
from itertools import product

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel import machine
from aivm_secrets.kernel.model import Binding, Clock, Effect, Request
from aivm_secrets.kernel.scope import Narrowing, is_subset
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import (
    REPO,
    github_policy,
    https_policy,
    metadata,
    must,
)

BINDING = Binding(1000, 'principal-a', 'vm-a', 'c' * 32)
NOW = Clock(1000, 100)
ROOT = 'a' * 32


def session(
    policy=None, *, write_mode='deny', binding=BINDING, clock=NOW, **changes
):
    spec = parse_policy(dict(policy or https_policy(), **changes))
    state, claims = machine.open_session(
        spec, binding, ROOT, clock, write_mode=write_mode
    )
    return spec, state, claims


def request(operation, **arguments):
    return Request(operation, tuple(sorted(arguments.items())))


VIEW = request('issue.view', issue=23)
COMMENT = request('issue.comment', issue=23, body='hello')


def code_of(call, *args):
    with pytest.raises(SecretsError) as caught:
        call(*args)
    return caught.value.code


def run(state, spec, claims, req, clock=NOW, *, binding=BINDING, facts=None):
    """Admit, emit and settle one request; return (state, final effect)."""
    state = machine.admit(state, claims, binding, req, clock)
    state, preflight = machine.emit_preflight(state, spec, req, clock)
    state, final = machine.emit_final(state, spec, req, facts, clock)
    return machine.settle(state), final


def invariants(state):
    """Properties every reachable state must satisfy (BUDGET-01, ATTEN-01)."""
    by_id = {grant.grant_id: grant for grant in state.grants}
    assert len(by_id) == len(state.grants) <= machine.MAX_GRANTS
    root = state.grants[0]
    assert root.parent == '' and root.depth == 0
    assert state.serial == root.used  # one ticket per admission, ever
    assert 0 <= state.attempts <= state.max_attempts
    assert len(state.approvals) <= machine.MAX_APPROVALS
    for grant in state.grants:
        assert 0 <= grant.used <= grant.max_requests
        assert grant.issued_at < grant.expires_at
        if grant.parent:
            parent = by_id[grant.parent]
            assert grant.depth == parent.depth + 1 <= machine.MAX_DEPTH
            assert is_subset(grant.scope, parent.scope)
            assert grant.expires_at <= parent.expires_at
            assert grant.deadline <= parent.deadline
            assert grant.max_requests <= parent.max_requests
            assert grant.max_body_bytes <= parent.max_body_bytes
        children = [g for g in state.grants if g.parent == grant.grant_id]
        # Children spend their ancestors' budget, never their own copy of it.
        assert sum(child.used for child in children) <= grant.used


# -- sessions ---------------------------------------------------------------


def test_open_session_derives_the_root_grant_from_the_policy():
    spec, state, claims = session()
    root = state.grants[0]
    assert state.policy_digest == spec.digest == claims.policy_digest
    assert (root.issued_at, root.expires_at, root.deadline) == (
        1000,
        2800,
        1900,
    )
    assert (claims.issued_at, claims.expires_at) == (1000, 2800)
    assert root.scope == spec.scope() and root.max_requests == 5
    assert state.max_attempts == 4 * 5 + 16
    assert claims.binding == BINDING and claims.grant_id == ROOT
    invariants(state)


@pytest.mark.parametrize('mode', ['', 'ALLOW', 'yes', True, 1, None])
def test_write_opt_in_is_a_closed_choice_not_truthiness(mode):
    spec = parse_policy(https_policy())
    assert (
        code_of(
            lambda: machine.open_session(
                spec, BINDING, ROOT, NOW, write_mode=mode
            )
        )
        == 'invalid_policy'
    )


# -- AUTH-01 / BIND-01 / TIME-01 / BUDGET-01: admission ----------------------


def test_admission_reserves_exactly_one_request():
    spec, state, claims = session()
    admitted = machine.admit(state, claims, BINDING, VIEW, NOW)
    ticket = admitted.ticket
    assert ticket == machine.Ticket(
        0, ROOT, 'issue.view', (('issue', 23),), VIEW.digest, False
    )
    assert admitted.grants[0].used == 1 and admitted.serial == 1
    # The input state is untouched: transitions are functions of values.
    assert state.grants[0].used == 0 and state.ticket is None


def test_authorization_matches_independent_bounded_oracle():
    """AUTH-01: 2^9 interacting conditions, against a one-line oracle."""
    spec, base, claims = session(write_mode='allow', max_requests=2)
    for (
        active, bound, digest_ok, live, time_ok, quota, operation_ok, resource_ok, size_ok,
    ) in product([False, True], repeat=9):  # fmt: skip
        state = replace(
            base,
            active=active,
            grants=(replace(base.grants[0], used=1 if quota else 2),),
        )
        presented = (
            claims if digest_ok else replace(claims, policy_digest='0' * 64)
        )
        binding = BINDING if bound else replace(BINDING, channel='d' * 32)
        clock = Clock(1500 if time_ok else 2800, 100 if live else 1900)
        req = request(
            'issue.comment' if operation_ok else 'issue.delete',
            issue=23 if resource_ok else 99,
            body='x' * (100 if size_ok else 101),
        )
        expected = all(
            [active, bound, digest_ok, live, time_ok, quota,
             operation_ok, resource_ok, size_ok]
        )  # fmt: skip
        try:
            after = machine.admit(state, presented, binding, req, clock)
        except SecretsError:
            assert not expected
            continue
        assert expected
        assert after.grants[0].used == state.grants[0].used + 1
        ticket = must(after.ticket)
        assert ticket.write and ticket.request_digest == req.digest


def test_denial_precedence_is_fixed():
    """A caller learns the first failed check in a fixed order, nothing more."""
    spec, state, claims = session(max_requests=1)
    spent = replace(state, grants=(replace(state.grants[0], used=1),))
    late = Clock(2800, 100)
    other = replace(BINDING, channel='d' * 32)
    bad = request('issue.delete')
    revoked = machine.revoke(spent)
    assert (
        code_of(machine.admit, revoked, claims, other, bad, late) == 'revoked'
    )
    assert (
        code_of(machine.admit, spent, claims, other, bad, late)
        == 'wrong_binding'
    )
    assert (
        code_of(machine.admit, spent, claims, BINDING, bad, late) == 'expired'
    )
    assert (
        code_of(machine.admit, spent, claims, BINDING, bad, NOW) == 'exhausted'
    )
    assert code_of(machine.admit, state, claims, BINDING, bad, NOW) == 'denied'


@pytest.mark.parametrize(
    'change',
    [
        {'channel': 'd' * 32},
        {'access_identity': 'principal-b'},
        {'vm': 'vm-b'},
        {'owner_uid': 1001},
    ],
)
def test_a_grant_is_honoured_only_on_its_own_channel(change):
    """BIND-01, for each component of the binding and from either side."""
    spec, state, claims = session()
    elsewhere = replace(BINDING, **change)
    # The transport says this connection belongs to a different session.
    assert (
        code_of(machine.admit, state, claims, elsewhere, VIEW, NOW)
        == 'wrong_binding'
    )
    # The capability says it was sealed for a different session.
    forged = replace(claims, binding=elsewhere)
    assert (
        code_of(machine.admit, state, forged, BINDING, VIEW, NOW)
        == 'wrong_binding'
    )
    assert (
        code_of(machine.admit, state, forged, elsewhere, VIEW, NOW)
        == 'wrong_binding'
    )


@pytest.mark.parametrize(
    'change',
    [
        {'policy_digest': '0' * 64},
        {'grant_id': '0' * 32},
        {'issued_at': 999},
        {'expires_at': 2801},
        {'expires_at': 2799},
    ],
)
def test_even_authenticated_claims_must_match_kernel_state(change):
    spec, state, claims = session()
    forged = replace(claims, **change)
    assert (
        code_of(machine.admit, state, forged, BINDING, VIEW, NOW)
        == 'wrong_binding'
    )


@pytest.mark.parametrize(
    'wall,accepted', [(999, False), (1000, True), (2799, True), (2800, False)]
)
def test_half_open_validity(wall, accepted):
    """TIME-01: ``issued <= now < expires``."""
    spec, state, claims = session()
    clock = Clock(wall, 100)
    if accepted:
        assert machine.admit(state, claims, BINDING, VIEW, clock).serial == 1
    else:
        assert (
            code_of(machine.admit, state, claims, BINDING, VIEW, clock)
            == 'expired'
        )


@pytest.mark.parametrize(
    'mono,accepted', [(100, True), (1899, True), (1900, False)]
)
def test_wall_clock_rollback_cannot_extend_a_grant(mono, accepted):
    """TIME-01: the monotonic deadline holds even when the wall clock lies."""
    spec, state, claims = session()
    rolled_back = Clock(1000, mono)
    if accepted:
        assert machine.admit(state, claims, BINDING, VIEW, rolled_back)
    else:
        assert (
            code_of(machine.admit, state, claims, BINDING, VIEW, rolled_back)
            == 'expired'
        )


def test_budget_is_bounded_and_never_refunded():
    """BUDGET-01: admissions <= limit, whatever happens after admission."""
    spec, state, claims = session(github_policy(), max_requests=3)
    view = spec.parse_request(
        {'operation': 'pr.view', 'repository': REPO, 'pr': 13861}
    )
    wrong = metadata()
    wrong['user']['login'] = 'someone-else'
    for attempt in range(3):
        state = machine.admit(state, claims, BINDING, view, NOW)
        state, preflight = machine.emit_preflight(state, spec, view, NOW)
        assert preflight is not None
        # The fact check fails after the metadata read. Nothing is refunded.
        assert (
            code_of(machine.emit_final, state, spec, view, wrong, NOW)
            == 'resource_mismatch'
        )
        state = machine.settle(state)
        assert state.grants[0].used == attempt + 1
        invariants(state)
    assert (
        code_of(machine.admit, state, claims, BINDING, view, NOW) == 'exhausted'
    )
    assert state.grants[0].used == 3


def test_attempt_cap_is_finite_and_permanent():
    spec, state, claims = session(max_requests=1)
    for _ in range(state.max_attempts):
        state = machine.note_attempt(state)
    assert state.attempts == state.max_attempts == 20
    assert code_of(machine.note_attempt, state) == 'exhausted'
    assert code_of(machine.note_attempt, state) == 'exhausted'


# -- EFFECT-01: tickets and emissions ---------------------------------------


def test_final_effect_is_computed_by_the_kernel_from_the_admitted_request():
    spec, state, claims = session()
    state = machine.admit(state, claims, BINDING, VIEW, NOW)
    state, preflight = machine.emit_preflight(state, spec, VIEW, NOW)
    assert preflight is None  # schema 2 has no fact fetch
    state, final = machine.emit_final(state, spec, VIEW, None, NOW)
    assert final == machine.AuthorizedEffect(
        0, ROOT, VIEW.digest, True, Effect('GET', '/v1/issues/23')
    )
    assert must(state.ticket).phase == 'final'


def test_a_ticket_cannot_be_spent_on_a_different_request():
    """EFFECT-01: tickets are not interchangeable across requests."""
    spec, state, claims = session()
    state = machine.admit(state, claims, BINDING, VIEW, NOW)
    other = request('issue.view', issue=24)
    assert (
        code_of(machine.emit_preflight, state, spec, other, NOW)
        == 'internal_error'
    )
    assert (
        code_of(machine.emit_final, state, spec, other, None, NOW)
        == 'internal_error'
    )
    foreign = parse_policy(https_policy(service='another'))
    assert (
        code_of(machine.emit_final, state, foreign, VIEW, None, NOW)
        == 'internal_error'
    )


def test_no_effect_without_an_admission_and_one_final_effect_per_ticket():
    spec, state, claims = session()
    assert (
        code_of(machine.emit_preflight, state, spec, VIEW, NOW)
        == 'internal_error'
    )
    assert (
        code_of(machine.emit_final, state, spec, VIEW, None, NOW)
        == 'internal_error'
    )
    state = machine.admit(state, claims, BINDING, VIEW, NOW)
    # One request at a time: a second admission cannot open beside the first.
    assert (
        code_of(machine.admit, state, claims, BINDING, VIEW, NOW)
        == 'internal_error'
    )
    state, _ = machine.emit_final(state, spec, VIEW, None, NOW)
    assert (
        code_of(machine.emit_final, state, spec, VIEW, None, NOW)
        == 'internal_error'
    )
    assert (
        code_of(machine.emit_preflight, state, spec, VIEW, NOW)
        == 'internal_error'
    )
    state = machine.settle(state)
    assert state.ticket is None
    assert (
        code_of(machine.emit_final, state, spec, VIEW, None, NOW)
        == 'internal_error'
    )


def test_fact_conditioned_requests_cannot_skip_or_repeat_the_preflight():
    spec, state, claims = session(github_policy(), write_mode='allow')
    comment = spec.parse_request(
        {
            'operation': 'pr.comment',
            'repository': REPO,
            'pr': 13861,
            'body': 'Update',
        }
    )
    state = machine.admit(state, claims, BINDING, comment, NOW)
    # The write cannot be emitted before the facts were fetched.
    assert (
        code_of(machine.emit_final, state, spec, comment, metadata(), NOW)
        == 'internal_error'
    )
    state, preflight = machine.emit_preflight(state, spec, comment, NOW)
    preflight = must(preflight)
    assert not preflight.final and preflight.effect.method == 'GET'
    assert (
        code_of(machine.emit_preflight, state, spec, comment, NOW)
        == 'internal_error'
    )
    state, final = machine.emit_final(state, spec, comment, metadata(), NOW)
    final = must(final)
    assert final.final and final.effect.method == 'POST'
    assert final.effect.body == (('body', 'Update'),)
    assert final.serial == preflight.serial == 0  # one reservation, two effects
    assert machine.settle(state).grants[0].used == 1


def test_liveness_is_resampled_at_every_emission():
    """TIME-01/REVOKE-01: the dispatch point observes what happened since."""
    spec, state, claims = session(github_policy(), write_mode='allow')
    comment = spec.parse_request(
        {
            'operation': 'pr.comment',
            'repository': REPO,
            'pr': 13861,
            'body': 'Update',
        }
    )
    admitted = machine.admit(state, claims, BINDING, comment, NOW)
    expired = Clock(1000, 1900)
    assert (
        code_of(machine.emit_preflight, admitted, spec, comment, expired)
        == 'expired'
    )
    after, _ = machine.emit_preflight(admitted, spec, comment, NOW)
    assert (
        code_of(machine.emit_final, after, spec, comment, metadata(), expired)
        == 'expired'
    )
    # Revocation that lands between the preflight and the write wins.
    revoked = machine.revoke(after)
    assert (
        code_of(machine.emit_final, revoked, spec, comment, metadata(), NOW)
        == 'revoked'
    )
    by_grant = machine.revoke(after, ROOT)
    assert (
        code_of(machine.emit_final, by_grant, spec, comment, metadata(), NOW)
        == 'revoked'
    )


class _Hostile:
    """A defective service compiler, to show the kernel does not trust one."""

    lifetime_seconds, max_requests, max_body_bytes = 60, 5, 100

    def __init__(self, real, *, preflight=None, final=None):
        self._real, self._preflight, self._final = real, preflight, final
        self.digest = real.digest

    def scope(self):
        return self._real.scope()

    def preflight(self, req):
        return self._preflight

    def final(self, req, facts):
        return self._final


@pytest.mark.parametrize(
    'preflight,final,stage',
    [
        (Effect('POST', '/v1/x', body=(('b', 'x'),)), None, 'preflight'),
        (Effect('GET', '/v1/../admin'), None, 'preflight'),
        (None, Effect('POST', '/v1/issues/23/comments', body=(('b', 'x'),)), 'final'),
        (None, Effect('GET', '//attacker.invalid/x'), 'final'),
        (None, Effect('GET', '/v1/x', (('q', 'a&b=c'),)), 'final'),
    ],
    ids=[
        'preflight-write', 'preflight-escape', 'read-became-write',
        'final-host-confusion', 'final-query-injection',
    ],
)  # fmt: skip
def test_kernel_refuses_effects_a_defective_compiler_would_emit(
    preflight, final, stage
):
    """COMP-01: every emitted effect passes the grammar and matches its class."""
    real, state, claims = session()
    hostile = _Hostile(real, preflight=preflight, final=final)
    state = machine.admit(state, claims, BINDING, VIEW, NOW)
    if stage == 'preflight':
        assert (
            code_of(machine.emit_preflight, state, hostile, VIEW, NOW)
            == 'denied'
        )
    else:
        assert (
            code_of(machine.emit_final, state, hostile, VIEW, None, NOW)
            == 'denied'
        )


def test_a_write_ticket_must_end_in_a_write():
    real, state, claims = session(write_mode='allow')
    state = machine.admit(state, claims, BINDING, COMMENT, NOW)
    for final in (None, Effect('GET', '/v1/issues/23')):
        hostile = _Hostile(real, final=final)
        assert (
            code_of(machine.emit_final, state, hostile, COMMENT, None, NOW)
            == 'denied'
        )


# -- writes and APPROVAL-01 --------------------------------------------------


def test_writes_require_both_policy_and_host_mode():
    read_only = https_policy(
        operations=[
            op for op in https_policy()['operations'] if op['method'] == 'GET'
        ]
    )
    for mode, policy, expected in [
        ('deny', None, 'denied'),
        ('allow', read_only, 'denied'),
        ('approve', read_only, 'denied'),
        ('approve', None, 'approval_required'),
    ]:
        spec, state, claims = session(policy, write_mode=mode)
        assert (
            code_of(machine.admit, state, claims, BINDING, COMMENT, NOW)
            == expected
        )
        assert machine.admit(
            state, claims, BINDING, VIEW, NOW
        )  # reads unaffected
    spec, state, claims = session(write_mode='allow')
    assert must(
        machine.admit(state, claims, BINDING, COMMENT, NOW).ticket
    ).write


def test_an_approval_authorizes_exactly_one_exact_write():
    """APPROVAL-01: one-shot, exact bytes, consumed with admission."""
    spec, state, claims = session(write_mode='approve')
    digest = machine.approval_digest(state.policy_digest, ROOT, COMMENT)
    state = machine.approve(state, digest, NOW, 60)
    for different in [
        request('issue.comment', issue=23, body='hello!'),
        request('issue.comment', issue=24, body='hello'),
        request('issue.comment', issue=23, body='Hello'),
    ]:
        assert (
            code_of(machine.admit, state, claims, BINDING, different, NOW)
            == 'approval_required'
        )
    assert len(state.approvals) == 1  # a refused attempt consumes nothing
    state, final = run(state, spec, claims, COMMENT)
    assert final.effect.body == (('body', 'hello'),) and state.approvals == ()
    # The identical bytes again need a new human decision.
    assert (
        code_of(machine.admit, state, claims, BINDING, COMMENT, NOW)
        == 'approval_required'
    )
    invariants(state)


def test_an_approval_is_consumed_even_when_the_write_then_fails():
    spec, state, claims = session(write_mode='approve')
    digest = machine.approval_digest(state.policy_digest, ROOT, COMMENT)
    state = machine.approve(state, digest, NOW, 60)
    state = machine.admit(state, claims, BINDING, COMMENT, NOW)
    assert (
        code_of(
            machine.emit_final, state, spec, COMMENT, None, Clock(1000, 1900)
        )
        == 'expired'
    )
    state = machine.settle(state)
    assert state.approvals == () and state.grants[0].used == 1


def test_approvals_expire_and_are_bound_to_policy_and_grant():
    spec, state, claims = session(write_mode='approve')
    digest = machine.approval_digest(state.policy_digest, ROOT, COMMENT)
    state = machine.approve(state, digest, NOW, 60)
    assert (
        code_of(
            machine.admit, state, claims, BINDING, COMMENT, Clock(1060, 160)
        )
        == 'approval_required'
    )
    assert machine.admit(state, claims, BINDING, COMMENT, Clock(1059, 159))
    assert digest != machine.approval_digest('0' * 64, ROOT, COMMENT)
    assert digest != machine.approval_digest(
        state.policy_digest, 'b' * 32, COMMENT
    )
    # A child grant cannot spend an approval given to its parent.
    state, child = machine.delegate(
        state, claims, BINDING,
        Narrowing.parse({'operations': {'issue.comment': {}}}), 'b' * 32, NOW,
    )  # fmt: skip
    assert (
        code_of(machine.admit, state, child, BINDING, COMMENT, NOW)
        == 'approval_required'
    )


def test_approval_is_only_for_approve_mode_and_is_bounded():
    for mode in ('deny', 'allow'):
        spec, state, claims = session(write_mode=mode)
        assert code_of(machine.approve, state, 'a' * 64, NOW, 60) == 'denied'
    spec, state, claims = session(write_mode='approve')
    for bad_digest, ttl in [
        ('A' * 64, 60),
        ('a' * 63, 60),
        ('a' * 64, 0),
        ('a' * 64, 901),
    ]:
        assert (
            code_of(machine.approve, state, bad_digest, NOW, ttl)
            == 'invalid_request'
        )
    for index in range(machine.MAX_APPROVALS):
        state = machine.approve(state, format(index, '064x'), NOW, 60)
    assert code_of(machine.approve, state, 'f' * 64, NOW, 60) == 'exhausted'
    # Re-approving a held digest replaces it; expired ones make room.
    assert (
        len(machine.approve(state, format(0, '064x'), NOW, 90).approvals) == 16
    )
    later = Clock(1060, 160)
    assert len(machine.approve(state, 'f' * 64, later, 60).approvals) == 1


# -- ATTEN-01: delegation ----------------------------------------------------


def narrowing(**value):
    value.setdefault('operations', {'issue.view': {'issue': [23]}})
    return Narrowing.parse(value)


def test_a_child_grant_is_strictly_smaller_and_shares_its_parents_budget():
    spec, state, claims = session()
    state, child = machine.delegate(
        state,
        claims,
        BINDING,
        narrowing(max_requests=2, lifetime_seconds=60),
        'b' * 32,
        NOW,
    )
    assert (child.grant_id, child.issued_at, child.expires_at) == (
        'b' * 32,
        1000,
        1060,
    )
    assert (
        child.binding == BINDING and child.policy_digest == claims.policy_digest
    )
    invariants(state)
    # Outside the narrowed scope, though the parent could do it.
    assert (
        code_of(
            machine.admit,
            state,
            child,
            BINDING,
            request('issue.view', issue=24),
            NOW,
        )
        == 'denied'
    )
    assert (
        code_of(
            machine.admit, state, child, BINDING, request('profile.read'), NOW
        )
        == 'denied'
    )
    for _ in range(2):
        state, _ = run(state, spec, child, VIEW)
    assert [grant.used for grant in state.grants] == [
        2,
        2,
    ]  # parent debited too
    assert (
        code_of(machine.admit, state, child, BINDING, VIEW, NOW) == 'exhausted'
    )
    invariants(state)


def test_a_child_expires_on_its_own_shorter_clock():
    spec, state, claims = session()
    state, child = machine.delegate(
        state, claims, BINDING, narrowing(lifetime_seconds=60), 'b' * 32, NOW
    )
    assert machine.admit(state, child, BINDING, VIEW, Clock(1059, 159))
    assert (
        code_of(machine.admit, state, child, BINDING, VIEW, Clock(1060, 100))
        == 'expired'
    )
    # Rolling the wall clock back does not revive it either.
    assert (
        code_of(machine.admit, state, child, BINDING, VIEW, Clock(1000, 160))
        == 'expired'
    )
    assert machine.admit(state, claims, BINDING, VIEW, Clock(1060, 160))


def test_children_cannot_amplify_the_parents_budget():
    """ATTEN-01/BUDGET-01: many children still spend one shared budget."""
    spec, state, claims = session(max_requests=3)
    children = []
    for index in range(4):
        state, child = machine.delegate(
            state, claims, BINDING, narrowing(), format(index + 1, '032x'), NOW
        )
        children.append(child)
    admitted = 0
    for child in children * 3:
        try:
            state, _ = run(state, spec, child, VIEW)
            admitted += 1
        except SecretsError as ex:
            assert ex.code == 'exhausted'
    assert admitted == 3 == state.grants[0].used
    invariants(state)


@pytest.mark.parametrize(
    'value',
    [
        {'operations': {'issue.view': {'issue': [25]}}},
        {'operations': {'issue.merge': {}}},
        {'max_requests': 6},
        {'max_body_bytes': 101},
    ],
)
def test_delegation_cannot_widen_anything(value):
    spec, state, claims = session()
    assert (
        code_of(
            machine.delegate,
            state,
            claims,
            BINDING,
            narrowing(**value),
            'b' * 32,
            NOW,
        )
        == 'denied'
    )


def test_a_childs_lifetime_is_clamped_to_its_parents():
    spec, state, claims = session()
    state, child = machine.delegate(
        state,
        claims,
        BINDING,
        narrowing(lifetime_seconds=3600),
        'b' * 32,
        Clock(2000, 1100),
    )
    grant = state.grants[1]
    assert (grant.issued_at, grant.expires_at, grant.deadline) == (
        2000,
        2800,
        1900,
    )
    state, inherit = machine.delegate(
        state, claims, BINDING, narrowing(), 'd' * 32, Clock(2000, 1100)
    )
    assert state.grants[2].expires_at == 2800
    invariants(state)
    short = machine.delegate(
        state,
        claims,
        BINDING,
        narrowing(lifetime_seconds=10),
        'e' * 32,
        Clock(2000, 1100),
    )[0]
    # The shorter child expires first; its parent carries on.
    assert code_of(machine.admit, short, replace(child, grant_id='e' * 32, expires_at=2010),
                   BINDING, VIEW, Clock(2010, 1110)) == 'expired'  # fmt: skip
    assert machine.admit(short, claims, BINDING, VIEW, Clock(2010, 1110))


def test_revoking_a_grant_revokes_everything_beneath_it_and_nothing_above():
    """REVOKE-01 over the grant tree."""
    spec, state, root = session()
    state, child = machine.delegate(
        state, root, BINDING, narrowing(), 'b' * 32, NOW
    )
    state, grandchild = machine.delegate(
        state, child, BINDING, narrowing(), 'd' * 32, NOW
    )
    state, sibling = machine.delegate(
        state, root, BINDING, narrowing(), 'e' * 32, NOW
    )
    revoked = machine.revoke(state, child.grant_id)
    assert (
        code_of(machine.admit, revoked, child, BINDING, VIEW, NOW) == 'revoked'
    )
    assert (
        code_of(machine.admit, revoked, grandchild, BINDING, VIEW, NOW)
        == 'revoked'
    )
    assert machine.admit(revoked, sibling, BINDING, VIEW, NOW)
    assert machine.admit(revoked, root, BINDING, VIEW, NOW)
    assert machine.revoke(revoked, child.grant_id) == revoked  # idempotent
    assert (
        code_of(
            machine.delegate,
            revoked,
            child,
            BINDING,
            narrowing(),
            'f' * 32,
            NOW,
        )
        == 'revoked'
    )
    everything = machine.revoke(state)
    for claims in (root, child, grandchild, sibling):
        assert (
            code_of(machine.admit, everything, claims, BINDING, VIEW, NOW)
            == 'revoked'
        )
    assert code_of(machine.revoke, state, '0' * 32) == 'invalid_request'


def test_renounce_gives_up_only_the_presented_grant():
    spec, state, root = session()
    state, child = machine.delegate(
        state, root, BINDING, narrowing(), 'b' * 32, NOW
    )
    after = machine.renounce(state, child, BINDING)
    assert code_of(machine.admit, after, child, BINDING, VIEW, NOW) == 'revoked'
    assert machine.admit(after, root, BINDING, VIEW, NOW)
    other = replace(BINDING, channel='d' * 32)
    assert code_of(machine.renounce, state, child, other) == 'wrong_binding'


def test_delegation_depth_and_count_are_bounded():
    spec, state, claims = session()
    current = claims
    for depth in range(machine.MAX_DEPTH):
        state, current = machine.delegate(
            state, current, BINDING, narrowing(), format(depth + 1, '032x'), NOW
        )
    assert state.grants[-1].depth == machine.MAX_DEPTH
    assert (
        code_of(
            machine.delegate,
            state,
            current,
            BINDING,
            narrowing(),
            'f' * 32,
            NOW,
        )
        == 'denied'
    )
    invariants(state)
    spec, state, claims = session()
    for index in range(machine.MAX_GRANTS - 1):
        state, _ = machine.delegate(
            state, claims, BINDING, narrowing(), format(index + 1, '032x'), NOW
        )
    assert len(state.grants) == machine.MAX_GRANTS
    assert (
        code_of(
            machine.delegate, state, claims, BINDING, narrowing(), 'f' * 32, NOW
        )
        == 'exhausted'
    )


def test_delegation_needs_a_fresh_wellformed_identifier():
    spec, state, claims = session()
    assert (
        code_of(
            machine.delegate, state, claims, BINDING, narrowing(), ROOT, NOW
        )
        == 'internal_error'
    )
    assert (
        code_of(
            machine.delegate, state, claims, BINDING, narrowing(), 'short', NOW
        )
        == 'internal_error'
    )


def test_describe_reports_the_tightest_limit_in_the_lineage():
    spec, state, root = session()
    state, _ = run(state, spec, root, VIEW)
    state, child = machine.delegate(
        state, root, BINDING, narrowing(max_requests=5, max_body_bytes=40, lifetime_seconds=30),
        'b' * 32, NOW,
    )  # fmt: skip
    view = machine.describe(state, child, BINDING, NOW)
    assert view['remaining_requests'] == 4  # the parent already spent one
    assert (view['expires_at'], view['max_body_bytes']) == (1030, 40)
    assert view['parent'] == ROOT and view['writes'] == 'deny'
    assert [op['name'] for op in view['operations']] == ['issue.view']
    assert view['operations'][0]['parameters'] == {'issue': [23]}
    # Nothing about the host, the destination or the credential source.
    assert 'api.example.org' not in repr(view) and 'mytool' not in repr(view)
    assert (
        code_of(machine.describe, state, child, BINDING, Clock(1030, 130))
        == 'expired'
    )
