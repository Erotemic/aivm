"""Serialized orchestration around the pure authorization core.

A denial before dispatch emits no provider request. Each accepted operation
reserves budget before I/O. Revocation waits for the current request: it is not
cancellation or rollback of an already-dispatched GitHub operation.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .core import (Binding, Claims, Policy, PRFacts, Request, State, authorize,
                   effect_route, exact_keys, integer, metadata_route)
from .envelope import EnvelopeCodec
from .errors import SecretsError
from .provider import GitHubProvider
from .wire import MAX_REPLY, dumps, loads


def failure(code: str) -> dict[str, Any]:
    error = SecretsError(code)
    return {'version': 1, 'ok': False,
            'error': {'code': error.code, 'message': str(error)}}


class Broker:
    def __init__(self, policy: Policy, binding: Binding, credential: str,
                 audit_path: Path, *, allow_writes: bool = False,
                 provider: Any = None, wall_clock: Callable[[], float] = time.time,
                 monotonic_clock: Callable[[], float] = time.monotonic):
        # Validate host API inputs too; a future Rust boundary will do the same.
        if type(allow_writes) is not bool:
            raise SecretsError('invalid_policy')
        self.policy = Policy.parse(policy.to_dict())
        self.binding = Binding.parse(asdict(binding))
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
        self._provider = provider if provider is not None else GitHubProvider()
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

    def _check(self, request: Request, claims: Claims, *, reserve: bool) -> None:
        # A second check after metadata uses the pre-reservation budget count,
        # but current revocation/time. It does not authorize a second operation.
        state = self._state if reserve else State(self._state.active, self._state.used - 1)
        next_state = authorize(self.policy, claims, self.binding, request, state,
                               now=int(self._wall_clock()), monotonic_live=self._live(),
                               allow_writes=self._allow_writes)
        if reserve:
            self._state = next_state

    def handle(self, raw: bytes) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._codec is None:
                return failure('revoked')
            self._attempts += 1
            if self._attempts > self._max_attempts:
                self._state = State(False, self._state.used)
                # Bound audit growth even for unauthenticated garbage.
                return failure('exhausted')
            request_id = secrets.token_hex(16)
            request = None
            dispatched_write = False
            try:
                wire = exact_keys(loads(raw), {'version', 'capability', 'request'})
                integer(wire['version'], 1, 1)
                request = Request.parse(wire['request'])
                opened = self._codec.open(wire['capability'])
                if opened.claims.grant_id != self._claims.grant_id:
                    raise SecretsError('wrong_binding')
                self._check(request, opened.claims, reserve=True)
                self._audit.record('authorized', request_id, timestamp=int(self._wall_clock()),
                                   request=request)
                self._check(request, opened.claims, reserve=False)
                metadata = self._provider.execute(metadata_route(request), opened.credential)
                facts = PRFacts.parse(metadata)
                route = effect_route(self.policy, request, facts)
                self._check(request, opened.claims, reserve=False)
                if route is None:
                    result = metadata
                else:
                    self._audit.record('dispatch', request_id, timestamp=int(self._wall_clock()),
                                       request=request)
                    self._check(request, opened.claims, reserve=False)
                    dispatched_write = route.method != 'GET'
                    result = self._provider.execute(route, opened.credential)
                reply = {'version': 1, 'ok': True, 'result': result}
                if request.operation in {'pr.comments', 'pr.reviews', 'pr.review-comments'}:
                    if type(result) is not list or len(result) > 100:
                        raise SecretsError('upstream_response')
                    reply['pagination'] = {'page': request.page, 'per_page': 100,
                                           'possibly_more': len(result) == 100}
                if request.operation == 'pr.checks':
                    if (type(result) is not dict or type(result.get('check_runs')) is not list
                            or len(result['check_runs']) > 100):
                        raise SecretsError('upstream_response')
                    reply['pagination'] = {'page': request.page, 'per_page': 100,
                                           'possibly_more': len(result['check_runs']) == 100}
                encoded = dumps(reply)
                # Reflection tripwire, not a general information-flow proof.
                # Check escaped JSON form too, since opaque tokens may contain
                # characters escaped by the serializer.
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
