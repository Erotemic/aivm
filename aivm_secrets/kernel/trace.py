"""Replay a scripted trace through the kernel, with no I/O at all.

This is the kernel's conformance harness. A trace is plain JSON: a policy, a
write mode and a list of steps. Replaying it yields one outcome per step. The
frozen vectors under ``tests/secrets_vectors`` are traces with their expected
outcomes, and any other implementation of the kernel -- the planned Rust
crate, its Lean extraction -- must produce the same outcomes from the same
files.

A trace drives exactly the transition sequence the broker does; it differs
only in that time, provider facts and grant identifiers are supplied by the
script instead of by the world. Grants are named in a trace; a name maps to a
fixed identifier so that outcomes are reproducible byte for byte.

Steps (``clock`` is ``{"wall": int, "mono": int}``):

``{"do": "request", "grant": NAME, "request": WIRE, "clock": C}``
    optional ``"facts"`` (the preflight answer), ``"final_clock"`` (a later
    sample for the final emission) and ``"binding"`` (overrides of the
    transport-established binding, to model a wrong channel).
``{"do": "delegate", "grant": NAME, "as": NEW, "narrowing": WIRE, "clock": C}``
``{"do": "describe", "grant": NAME, "clock": C}``
``{"do": "renounce", "grant": NAME}``
``{"do": "approve", "grant": NAME, "request": WIRE, "ttl": int, "clock": C}``
``{"do": "revoke", "grant": NAME or ""}``
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..errors import SecretsError
from . import machine
from .model import Binding, Claims, Clock, Effect
from .scope import Narrowing
from .service import ServiceSpec, parse_policy

BINDING = Binding(1000, 'principal-trace', 'vm-trace', 'c' * 32)
ROOT = 'root'


def grant_identifier(index: int) -> str:
    return format(index, '032x')


def effect_view(effect: Effect) -> dict[str, Any]:
    """An effect exactly as the executor would put it on the wire."""
    view: dict[str, Any] = {
        'method': effect.method,
        'target': effect.target,
        'accept': effect.accept,
        'response': effect.response,
    }
    if effect.body is not None:
        view['body'] = dict(effect.body)
    return view


class Trace:
    """One session's kernel state plus the names its grants go by."""

    def __init__(
        self, policy: Any, *, write_mode: str = 'deny', clock: Any = None
    ):
        self.spec: ServiceSpec = parse_policy(policy)
        start = _clock(clock or {'wall': 1000, 'mono': 100})
        self.state, root = machine.open_session(
            self.spec,
            BINDING,
            grant_identifier(0),
            start,
            write_mode=write_mode,
        )
        self.claims: dict[str, Claims] = {ROOT: root}

    def step(self, step: dict[str, Any]) -> dict[str, Any]:
        """Apply one step. A denial is an outcome, never an exception."""
        try:
            return self._apply(step)
        except SecretsError as ex:
            return {'code': ex.code}
        finally:
            self.state = machine.settle(self.state)

    def _claims(self, step: dict[str, Any]) -> Claims:
        name = step.get('grant', ROOT)
        if name not in self.claims:
            raise SecretsError('invalid_request')
        return self.claims[name]

    def _apply(self, step: dict[str, Any]) -> dict[str, Any]:
        do = step['do']
        if do == 'revoke':
            name = step.get('grant', '')
            target = self.claims[name].grant_id if name else ''
            self.state = machine.revoke(self.state, target)
            return {'code': 'ok'}
        claims = self._claims(step)
        if do == 'renounce':
            self.state = machine.note_attempt(self.state)
            self.state = machine.renounce(self.state, claims, BINDING)
            return {'code': 'ok'}
        clock = _clock(step['clock'])
        if do == 'approve':
            request = self.spec.parse_request(step['request'])
            digest = machine.approval_digest(
                self.state.policy_digest, claims.grant_id, request
            )
            self.state = machine.approve(self.state, digest, clock, step['ttl'])
            return {'code': 'ok'}
        self.state = machine.note_attempt(self.state)
        binding = replace(BINDING, **step.get('binding', {}))
        if do == 'describe':
            view = machine.describe(self.state, claims, binding, clock)
            return {'code': 'ok', 'grant': _stable(view)}
        if do == 'delegate':
            narrowing = Narrowing.parse(step['narrowing'])
            if step['as'] in self.claims:
                raise SecretsError('invalid_request')
            self.state, child = machine.delegate(
                self.state,
                claims,
                binding,
                narrowing,
                grant_identifier(len(self.claims)),
                clock,
            )
            self.claims[step['as']] = child
            view = machine.describe(self.state, child, binding, clock)
            return {'code': 'ok', 'grant': _stable(view)}
        if do != 'request':
            raise SecretsError('invalid_request')
        request = self.spec.parse_request(step['request'])
        self.state = machine.admit(self.state, claims, binding, request, clock)
        outcome: dict[str, Any] = {
            'code': 'ok',
            'preflight': None,
            'effect': None,
        }
        self.state, preflight = machine.emit_preflight(
            self.state, self.spec, request, clock
        )
        if preflight is not None:
            outcome['preflight'] = effect_view(preflight.effect)
        later = _clock(step.get('final_clock', step['clock']))
        self.state, final = machine.emit_final(
            self.state, self.spec, request, step.get('facts'), later
        )
        if final is not None:
            outcome['effect'] = effect_view(final.effect)
        return outcome


def _clock(value: dict[str, int]) -> Clock:
    return Clock(value['wall'], value['mono'])


def _stable(view: dict[str, Any]) -> dict[str, Any]:
    """The part of a grant description that does not name identifiers."""
    return {
        key: view[key]
        for key in (
            'writes',
            'expires_at',
            'remaining_requests',
            'max_body_bytes',
            'operations',
        )
    }


def run_trace(trace: dict[str, Any]) -> list[dict[str, Any]]:
    """Replay a whole trace document and return one outcome per step."""
    session = Trace(
        trace['policy'],
        write_mode=trace.get('write_mode', 'deny'),
        clock=trace.get('clock'),
    )
    return [session.step(step) for step in trace['steps']]
