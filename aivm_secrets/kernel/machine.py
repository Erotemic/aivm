"""The secret-use state machine.

This module is the reference monitor. It is a deterministic, sequential
transition system over immutable values:

* every function is total: it returns a new :class:`State` or raises
  :class:`SecretsError` with a fixed code, **and a raise never changes
  state** -- the caller simply keeps the state it already had;
* no function reads a clock, draws randomness, opens a file or socket, or
  sees a provider credential. Time arrives as an explicit :class:`Clock`
  sample and fresh identifiers arrive as arguments.

That shape is deliberate: it is the subset of safe Rust that Charon/Aeneas
translate to Lean, so each function below is intended to be ported one for
one and to carry the theorem named in its docstring (see
``docs/planning/aivm-secrets-formal-assurance.md``).

The only way to obtain an :class:`AuthorizedEffect` is :func:`emit_preflight`
or :func:`emit_final`. The executor accepts nothing else, which is how a
decision made here becomes the only route to credentialed egress (EFFECT-01).

Requests are processed one at a time: ``State.ticket`` is the single open
reservation. Revocation, approval and closing are *not* serialized behind a
request, so they can land between a preflight and its final effect; the
final emission samples liveness again and refuses (REVOKE-01).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from ..errors import SecretsError
from . import codec, grammar, scope
from .model import (
    Arguments,
    Binding,
    Claims,
    Clock,
    Effect,
    Request,
    check_effect,
)
from .scope import Narrowing, OperationScope, Scope
from .service import ServiceSpec

MAX_GRANTS = 64
MAX_DEPTH = 4
MAX_APPROVALS = 16
MAX_APPROVAL_TTL = 900
WRITE_MODES = ('deny', 'approve', 'allow')


@dataclass(frozen=True)
class Grant:
    """One node of the grant tree. ``parent == ''`` marks the session root."""

    grant_id: str
    parent: str
    depth: int
    scope: Scope
    issued_at: int
    expires_at: int
    deadline: int
    max_requests: int
    max_body_bytes: int
    used: int = 0
    active: bool = True


@dataclass(frozen=True)
class Ticket:
    """A budget reservation for exactly one request.

    It records the request's digest and validated resource, so the effects
    emitted under it cannot be exchanged for those of another request.
    """

    serial: int
    grant_id: str
    operation: str
    resource: Arguments
    request_digest: str
    write: bool
    phase: str = 'reserved'


@dataclass(frozen=True)
class Approval:
    digest: str
    expires_at: int


@dataclass(frozen=True)
class State:
    binding: Binding
    policy_digest: str
    write_mode: str
    max_attempts: int
    grants: tuple[Grant, ...]
    approvals: tuple[Approval, ...] = ()
    ticket: Ticket | None = None
    serial: int = 0
    attempts: int = 0
    active: bool = True


@dataclass(frozen=True)
class AuthorizedEffect:
    """An effect the kernel has decided may be sent, and proof of which.

    Constructed only by this module. ``final`` distinguishes the one final
    effect of a request from its read-only preflight.
    """

    serial: int
    grant_id: str
    request_digest: str
    final: bool
    effect: Effect


def open_session(
    spec: ServiceSpec,
    binding: Binding,
    grant_id: str,
    clock: Clock,
    *,
    write_mode: str,
) -> tuple[State, Claims]:
    """Create the root grant of a session from a parsed service spec."""
    if type(write_mode) is not str or write_mode not in WRITE_MODES:
        raise SecretsError('invalid_policy')
    grammar.hex_string(grant_id, 32, code='internal_error')
    root = Grant(
        grant_id,
        '',
        0,
        spec.scope(),
        clock.wall,
        clock.wall + spec.lifetime_seconds,
        clock.mono + spec.lifetime_seconds,
        spec.max_requests,
        spec.max_body_bytes,
    )
    state = State(
        binding,
        spec.digest,
        write_mode,
        4 * spec.max_requests + 16,
        (root,),
    )
    return state, _claims(state, root)


def _claims(state: State, grant: Grant) -> Claims:
    return Claims(
        state.binding,
        state.policy_digest,
        grant.grant_id,
        grant.issued_at,
        grant.expires_at,
    )


def _find(state: State, grant_id: str) -> Grant | None:
    for grant in state.grants:
        if grant.grant_id == grant_id:
            return grant
    return None


def _lineage(state: State, grant_id: str) -> tuple[Grant, ...]:
    """The grant and all of its ancestors, leaf first."""
    chain = []
    wanted = grant_id
    for _ in range(MAX_DEPTH + 1):
        grant = _find(state, wanted)
        if grant is None:
            raise SecretsError('wrong_binding')
        chain.append(grant)
        if grant.parent == '':
            return tuple(chain)
        wanted = grant.parent
    raise SecretsError('internal_error')


def _authenticate(
    state: State, claims: Claims, binding: Binding
) -> tuple[Grant, ...]:
    """BIND-01: claims are honoured only on the channel they were sealed for.

    ``binding`` is what the transport established about this connection;
    ``claims`` is what the capability says. Both must equal the session's
    own binding, and the claim must name a grant this session issued.
    """
    if not state.active:
        raise SecretsError('revoked')
    if (
        claims.binding != binding
        or binding != state.binding
        or claims.policy_digest != state.policy_digest
    ):
        raise SecretsError('wrong_binding')
    chain = _lineage(state, claims.grant_id)
    leaf = chain[0]
    if (
        claims.issued_at != leaf.issued_at
        or claims.expires_at != leaf.expires_at
    ):
        raise SecretsError('wrong_binding')
    return chain


def _require_live(state: State, chain: tuple[Grant, ...], clock: Clock) -> None:
    """REVOKE-01 and TIME-01, for a grant and every ancestor.

    A grant is live at a sample when nothing above it is revoked, the wall
    clock lies in its half-open validity interval, and its monotonic
    deadline has not passed. Rolling the wall clock back satisfies the
    interval again but never the deadline.
    """
    if not state.active:
        raise SecretsError('revoked')
    for grant in chain:
        if not grant.active:
            raise SecretsError('revoked')
    for grant in chain:
        if not grant.issued_at <= clock.wall < grant.expires_at:
            raise SecretsError('expired')
        if clock.mono >= grant.deadline:
            raise SecretsError('expired')


def _permitted(chain: tuple[Grant, ...], request: Request) -> OperationScope:
    """AUTH-01: the request lies inside the grant and every ancestor.

    Delegation already guarantees a child's scope is inside its parent's.
    Checking each ancestor anyway makes admission correct without relying on
    that invariant. Returns the leaf grant's view of the operation.
    """
    found = None
    for grant in chain:
        operation = scope.find(grant.scope, request.operation)
        if operation is None:
            raise SecretsError('denied')
        if scope.check_arguments(operation, request) > grant.max_body_bytes:
            raise SecretsError('denied')
        if found is None:
            found = operation
    if found is None:
        raise SecretsError('internal_error')
    return found


def note_attempt(state: State) -> State:
    """Charge one received frame, valid or not, against a finite cap.

    The cap bounds audit growth from hostile traffic independently of the
    request budget. It never resets, so exhaustion is permanent.
    """
    if state.attempts >= state.max_attempts:
        raise SecretsError('exhausted')
    return replace(state, attempts=state.attempts + 1)


def approval_digest(policy_digest: str, grant_id: str, request: Request) -> str:
    """Identity of one exact write: its service, grant and canonical bytes."""
    return codec.digest(
        {
            'policy': policy_digest,
            'grant': grant_id,
            'request': request.to_dict(),
        }
    )


def admit(
    state: State,
    claims: Claims,
    binding: Binding,
    request: Request,
    clock: Clock,
) -> State:
    """Authorize one request and reserve its budget (AUTH-01, BUDGET-01).

    On success the returned state holds an open :class:`Ticket`, every
    grant in the lineage has been debited exactly once, and -- in
    ``approve`` mode -- the matching one-shot approval has been consumed
    (APPROVAL-01). No provider I/O has happened yet, and a failure after
    this point never refunds the reservation.
    """
    if state.ticket is not None:
        raise SecretsError('internal_error')
    chain = _authenticate(state, claims, binding)
    _require_live(state, chain, clock)
    for grant in chain:
        if grant.used >= grant.max_requests:
            raise SecretsError('exhausted')
    operation = _permitted(chain, request)
    leaf = chain[0]
    approvals = state.approvals
    if operation.write:
        if state.write_mode == 'deny':
            raise SecretsError('denied')
        if state.write_mode == 'approve':
            wanted = approval_digest(
                state.policy_digest, leaf.grant_id, request
            )
            kept = tuple(item for item in approvals if item.digest != wanted)
            usable = [
                item
                for item in approvals
                if item.digest == wanted and clock.wall < item.expires_at
            ]
            if not usable:
                raise SecretsError('approval_required')
            approvals = kept
    names = {name for name, _ in operation.parameters}
    ticket = Ticket(
        state.serial,
        leaf.grant_id,
        request.operation,
        tuple(item for item in request.arguments if item[0] in names),
        request.digest,
        operation.write,
    )
    debited = {grant.grant_id for grant in chain}
    return replace(
        state,
        grants=tuple(
            replace(grant, used=grant.used + 1)
            if grant.grant_id in debited
            else grant
            for grant in state.grants
        ),
        approvals=approvals,
        ticket=ticket,
        serial=state.serial + 1,
    )


def _open_ticket(
    state: State, spec: ServiceSpec, request: Request
) -> tuple[Ticket, tuple[Grant, ...]]:
    """The open reservation, if it is the one made for exactly this request."""
    ticket = state.ticket
    if ticket is None:
        raise SecretsError('internal_error')
    if (
        spec.digest != state.policy_digest
        or request.digest != ticket.request_digest
    ):
        raise SecretsError('internal_error')
    return ticket, _lineage(state, ticket.grant_id)


def emit_preflight(
    state: State, spec: ServiceSpec, request: Request, clock: Clock
) -> tuple[State, AuthorizedEffect | None]:
    """Authorize the read-only fact fetch of the open request, if it has one.

    A preflight is always a ``GET`` built by the service spec from the
    admitted request. It reuses the request's reservation.
    """
    ticket, chain = _open_ticket(state, spec, request)
    if ticket.phase != 'reserved':
        raise SecretsError('internal_error')
    effect = spec.preflight(request)
    if effect is None:
        return state, None
    check_effect(effect)
    if effect.is_write:
        raise SecretsError('denied')
    _require_live(state, chain, clock)
    return (
        replace(state, ticket=replace(ticket, phase='preflight')),
        AuthorizedEffect(
            ticket.serial, ticket.grant_id, ticket.request_digest, False, effect
        ),
    )


def emit_final(
    state: State,
    spec: ServiceSpec,
    request: Request,
    facts: Any,
    clock: Clock,
) -> tuple[State, AuthorizedEffect | None]:
    """Authorize the one final effect of the open request (EFFECT-01).

    The effect is *computed here* from the spec, the admitted request and
    the preflight facts; no caller can hand in a route. Liveness is sampled
    again at this point, which is the linearization point of dispatch:
    expiry or revocation that lands after admission, during audit I/O or
    during a preflight is observed here. ``None`` means the request has no
    final effect and the validated facts are its answer.
    """
    ticket, chain = _open_ticket(state, spec, request)
    needs_facts = spec.preflight(request) is not None
    if ticket.phase != ('preflight' if needs_facts else 'reserved'):
        raise SecretsError('internal_error')
    effect = spec.final(request, facts if needs_facts else None)
    if effect is None:
        if ticket.write:
            raise SecretsError('denied')
    else:
        check_effect(effect)
        if effect.is_write != ticket.write:
            raise SecretsError('denied')
    _require_live(state, chain, clock)
    state = replace(state, ticket=replace(ticket, phase='final'))
    if effect is None:
        return state, None
    return state, AuthorizedEffect(
        ticket.serial, ticket.grant_id, ticket.request_digest, True, effect
    )


def settle(state: State) -> State:
    """Close the open reservation. Its budget is spent whatever happened."""
    return replace(state, ticket=None)


def delegate(
    state: State,
    claims: Claims,
    binding: Binding,
    narrowing: Narrowing,
    grant_id: str,
    clock: Clock,
) -> tuple[State, Claims]:
    """Mint a strictly smaller child grant (ATTEN-01).

    The child's scope is a subset of its parent's, its expiry and deadline
    are no later, and its limits are no larger. It receives no budget of its
    own: every admission under it also debits each ancestor, so a tree of
    children can never spend more than the root allows.
    """
    chain = _authenticate(state, claims, binding)
    _require_live(state, chain, clock)
    parent = chain[0]
    if len(state.grants) >= MAX_GRANTS:
        raise SecretsError('exhausted')
    if parent.depth >= MAX_DEPTH:
        raise SecretsError('denied')
    grammar.hex_string(grant_id, 32, code='internal_error')
    if _find(state, grant_id) is not None:
        raise SecretsError('internal_error')
    max_requests = parent.max_requests
    if narrowing.max_requests is not None:
        max_requests = narrowing.max_requests
    max_body_bytes = parent.max_body_bytes
    if narrowing.max_body_bytes is not None:
        max_body_bytes = narrowing.max_body_bytes
    if (
        max_requests > parent.max_requests
        or max_body_bytes > parent.max_body_bytes
    ):
        raise SecretsError('denied')
    expires_at, deadline = parent.expires_at, parent.deadline
    if narrowing.lifetime_seconds is not None:
        expires_at = min(expires_at, clock.wall + narrowing.lifetime_seconds)
        deadline = min(deadline, clock.mono + narrowing.lifetime_seconds)
    child = Grant(
        grant_id,
        parent.grant_id,
        parent.depth + 1,
        scope.narrow(parent.scope, narrowing),
        clock.wall,
        expires_at,
        deadline,
        max_requests,
        max_body_bytes,
    )
    state = replace(state, grants=state.grants + (child,))
    return state, _claims(state, child)


def approve(state: State, digest: str, clock: Clock, ttl: int) -> State:
    """Record a host operator's one-shot approval of one exact write.

    Reachable only from the host control channel; no guest frame maps to
    this transition (APPROVAL-01).
    """
    if state.write_mode != 'approve':
        raise SecretsError('denied')
    grammar.hex_string(digest, 64)
    grammar.integer(ttl, 1, MAX_APPROVAL_TTL)
    kept = tuple(
        item
        for item in state.approvals
        if item.digest != digest and clock.wall < item.expires_at
    )
    if len(kept) >= MAX_APPROVALS:
        raise SecretsError('exhausted')
    return replace(
        state, approvals=kept + (Approval(digest, clock.wall + ttl),)
    )


def revoke(state: State, grant_id: str = '') -> State:
    """Revoke one grant and everything beneath it, or the whole session.

    Idempotent. There is no inverse transition: authority is only regained
    by opening a new session with a new key.
    """
    if grant_id == '':
        return replace(state, active=False)
    if _find(state, grant_id) is None:
        raise SecretsError('invalid_request')
    return replace(
        state,
        grants=tuple(
            replace(grant, active=False)
            if grant.grant_id == grant_id
            else grant
            for grant in state.grants
        ),
    )


def renounce(state: State, claims: Claims, binding: Binding) -> State:
    """A holder gives up its own grant. Authority can only shrink this way."""
    chain = _authenticate(state, claims, binding)
    return revoke(state, chain[0].grant_id)


def describe(
    state: State, claims: Claims, binding: Binding, clock: Clock
) -> dict[str, Any]:
    """What the presented grant currently permits. Reveals no host detail."""
    chain = _authenticate(state, claims, binding)
    _require_live(state, chain, clock)
    leaf = chain[0]
    return {
        'grant': leaf.grant_id,
        'parent': leaf.parent,
        'writes': state.write_mode,
        'expires_at': min(grant.expires_at for grant in chain),
        'remaining_requests': min(
            grant.max_requests - grant.used for grant in chain
        ),
        'max_body_bytes': min(grant.max_body_bytes for grant in chain),
        'operations': [operation.to_wire() for operation in leaf.scope],
    }
