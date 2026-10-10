"""Service-neutral, serialized capability broker.

Only the host-trusted adapter can produce routes. All outbound effects are
mediated by session binding, policy, request budgets and pre-dispatch audit.
Neither a guest CLI name nor a credential resolver conveys authorization.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from .adapters import build_adapter
from .audit import AuditLog
from .envelope import EnvelopeCodec
from .errors import SecretsError
from .kernel import Binding, Claims, State, exact_keys, integer, reserve
from .wire import MAX_REPLY, dumps, loads


def failure(code: str) -> dict[str, Any]:
    error = SecretsError(code)
    return {'version': 1, 'ok': False,
            'error': {'code': error.code, 'message': str(error)}}


class Broker:
    def __init__(self, policy: Any, binding: Binding, credential: str,
                 audit_path: Path, *, allow_writes: bool = False,
                 provider: Any = None, wall_clock: Callable[[], float] = time.time,
                 monotonic_clock: Callable[[], float] = time.monotonic):
        if type(allow_writes) is not bool:
            raise SecretsError('invalid_policy')
        self.policy = type(policy).parse(policy.to_dict())
        self.binding = Binding.parse(asdict(binding))
        self._adapter, self._provider = build_adapter(self.policy, provider)
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._deadline = monotonic_clock() + policy.lifetime_seconds
        self._codec: EnvelopeCodec | None = EnvelopeCodec()
        now = int(wall_clock())
        claims = Claims(binding, policy.digest, secrets.token_hex(16),
                        now, now + policy.lifetime_seconds)
        self.capability = self._codec.seal(claims, credential)
        self._claims = claims
        self._allow_writes = allow_writes
        self._state = State()
        self._lock = threading.RLock()
        self._attempts = 0
        self._max_attempts = 4 * policy.max_requests + 16
        self._audit = AuditLog(audit_path, binding.channel)
        self._closed = False
        try:
            self._audit.record('session_open', '', timestamp=now)
        except SecretsError:
            self._audit.close()
            raise

    def _live(self) -> bool:
        return self._monotonic_clock() < self._deadline

    def _check(self, request: Any, claims: Claims, *, reserve_budget: bool) -> None:
        # No effect may skip scope validation, including the second step of a
        # multi-effect plan. The second check uses the pre-reservation count.
        self._adapter.check_scope(request)
        state = (self._state if reserve_budget else
                 State(self._state.active, self._state.used - 1))
        new = reserve(self.policy.digest, self.policy.max_requests,
                      self.policy.max_body_bytes, claims, self.binding, state,
                      now=int(self._wall_clock()), monotonic_live=self._live(),
                      operation=request.operation,
                      allowed_operations=frozenset(self.policy.operations),
                      is_write=self._adapter.is_write(request),
                      allow_writes=self._allow_writes,
                      body_bytes=self._adapter.body_bytes(request))
        if reserve_budget:
            self._state = new

    def handle(self, raw: bytes) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._codec is None:
                return failure('revoked')
            self._attempts += 1
            if self._attempts > self._max_attempts:
                self._state = State(False, self._state.used)
                return failure('exhausted')
            request_id = secrets.token_hex(16)
            request = None
            dispatched_write = False
            try:
                wire = exact_keys(loads(raw), {'version', 'capability', 'request'})
                integer(wire['version'], 1, 1)
                request = self._adapter.parse(wire['request'])
                opened = self._codec.open(wire['capability'])
                if opened.claims.grant_id != self._claims.grant_id:
                    raise SecretsError('wrong_binding')
                self._check(request, opened.claims, reserve_budget=True)
                self._audit.record('authorized', request_id, timestamp=int(self._wall_clock()),
                                   request=request)
                self._check(request, opened.claims, reserve_budget=False)
                preflight_route = self._adapter.preflight(request)
                if preflight_route is not None:
                    if preflight_route.method != 'GET':
                        raise SecretsError('denied')
                    facts = self._provider.execute(preflight_route, opened.credential)
                    route = self._adapter.effect(request, facts)
                    self._check(request, opened.claims, reserve_budget=False)
                else:
                    facts = None
                    route = self._adapter.effect(request, None)
                if route is None:
                    result = facts
                else:
                    # All final effects, including direct reads, have an
                    # auditable dispatch boundary and a fresh live check.
                    self._audit.record('dispatch', request_id, timestamp=int(self._wall_clock()),
                                       request=request)
                    self._check(request, opened.claims, reserve_budget=False)
                    effect_is_write = route.method != 'GET'
                    if effect_is_write != self._adapter.is_write(request):
                        raise SecretsError('denied')
                    dispatched_write = effect_is_write
                    result = self._provider.execute(route, opened.credential)
                reply = {'version': 1, 'ok': True, 'result': result}
                pagination = self._adapter.pagination(request, result)
                if pagination is not None:
                    reply['pagination'] = pagination
                encoded = dumps(reply)
                # Reflection tripwire, not a general information-flow proof.
                secret_json = dumps(opened.credential)[1:-1]
                if len(encoded) > MAX_REPLY - 1 or secret_json in encoded:
                    raise SecretsError('upstream_response')
                self._audit.record('completed', request_id, timestamp=int(self._wall_clock()),
                                   request=request)
                return reply
            except SecretsError as ex:
                code = ex.code
                if code == 'audit_failed':
                    self._state = State(False, self._state.used)
                if dispatched_write:
                    code = 'outcome_unknown'
            except Exception:
                code = 'outcome_unknown' if dispatched_write else 'internal_error'
            try:
                self._audit.record('rejected_or_failed', request_id,
                                   timestamp=int(self._wall_clock()), request=request, code=code)
            except SecretsError:
                self._state = State(False, self._state.used)
                code = 'outcome_unknown' if dispatched_write else 'audit_failed'
            return failure(code)

    def revoke(self) -> None:
        with self._lock:
            self._state = State(False, self._state.used)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._state = State(False, self._state.used)
            self._codec = None
            self.capability = ''
            try:
                self._audit.record('session_close', '', timestamp=int(self._wall_clock()))
            finally:
                self._audit.close()
