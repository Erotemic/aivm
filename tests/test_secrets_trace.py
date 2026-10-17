"""Generated adversarial traces against an independent reference model.

The kernel is replayed over thousands of randomly generated event sequences
-- requests in and out of scope, delegation trees, revocations, approvals,
clocks that jump forward and roll back, wrong channels -- and after every
step two things are checked:

* the outcome equals the prediction of ``Model`` below, a deliberately naive
  restatement of the rules that shares no code with the kernel; and
* the kernel state satisfies the structural invariants of BUDGET-01 and
  ATTEN-01.

This is evidence over composed traces, which single-transition tests cannot
give. It is still testing, not proof.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from aivm_secrets.kernel.trace import Trace, run_trace
from tests.secrets_helpers import https_policy
from tests.test_secrets_machine import invariants

OPERATIONS: dict[str, dict[str, Any]] = {
    'profile.read': {'write': False, 'params': {}, 'fields': {}},
    'issue.view': {'write': False, 'params': {'issue': {23, 24}}, 'fields': {}},
    'issue.list': {
        'write': False,
        'params': {'page': set(range(1, 51))},
        'fields': {},
    },
    'issue.comment': {
        'write': True,
        'params': {'issue': {23, 24}},
        'fields': {'body': 100},
    },
}


class Model:
    """What should happen, written as plainly as the rules can be stated."""

    def __init__(self, write_mode: str):
        self.mode = write_mode
        self.session = True
        self.attempts = 0
        self.max_attempts = 4 * 5 + 16
        self.approvals: dict[tuple[str, str], int] = {}
        self.grants: dict[str, dict[str, Any]] = {
            'root': {
                'parent': None, 'depth': 0, 'alive': True, 'used': 0, 'limit': 5,
                'body': 100, 'start': 1000, 'end': 2800, 'deadline': 1900,
                'ops': {
                    name: {**op, 'params': {k: set(v) for k, v in op['params'].items()}}
                    for name, op in OPERATIONS.items()
                },
            }
        }  # fmt: skip

    def lineage(self, name):
        chain = []
        while name is not None:
            chain.append(self.grants[name])
            name = self.grants[name]['parent']
        return chain

    def charge(self):
        if self.attempts >= self.max_attempts:
            return False
        self.attempts += 1
        return True

    def holder(self, step, *, timed=True):
        """Failures common to every verb that presents a capability."""
        if not self.session:
            return 'revoked'
        if step.get('binding'):
            return 'wrong_binding'
        chain = self.lineage(step['grant'])
        if not timed:
            return None
        if not all(grant['alive'] for grant in chain):
            return 'revoked'
        wall, mono = step['clock']['wall'], step['clock']['mono']
        for grant in chain:
            if (
                not grant['start'] <= wall < grant['end']
                or mono >= grant['deadline']
            ):
                return 'expired'
        return None

    @staticmethod
    def shape(op, arguments):
        """``invalid_request`` | ``denied`` | body size, for one grant's view."""
        for name in arguments:
            if name not in op['params'] and name not in op['fields']:
                return 'invalid_request'
        if any(name not in arguments for name in op['params']):
            return 'invalid_request'
        for name in op['fields']:
            if name not in arguments or not isinstance(arguments[name], str):
                return 'invalid_request'
        for name, allowed in op['params'].items():
            value = arguments[name]
            if isinstance(value, bool) or value not in allowed:
                return 'denied'
        size = 0
        for name, cap in op['fields'].items():
            length = len(arguments[name].encode())
            if length > cap:
                return 'denied'
            size += length
        return size

    def request(self, step):
        if not self.charge():
            return 'exhausted'
        wire = step['request']
        arguments = wire.get('arguments', {})
        for value in arguments.values():
            well_typed = (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            ) or (isinstance(value, str) and value != '')
            if not well_typed:
                return 'invalid_request'
        problem = self.holder(step)
        if problem:
            return problem
        chain = self.lineage(step['grant'])
        if any(grant['used'] >= grant['limit'] for grant in chain):
            return 'exhausted'
        for grant in chain:
            op = grant['ops'].get(wire['operation'])
            if op is None:
                return 'denied'
            size = self.shape(op, arguments)
            if isinstance(size, str):
                return size
            if size > grant['body']:
                return 'denied'
        if OPERATIONS[wire['operation']]['write']:
            if self.mode == 'deny':
                return 'denied'
            if self.mode == 'approve':
                key = (step['grant'], repr(sorted(wire.items(), key=repr)))
                if self.approvals.get(key, 0) <= step['clock']['wall']:
                    return 'approval_required'
                del self.approvals[key]
        for grant in chain:
            grant['used'] += 1
        return 'ok'

    def approve(self, step):
        if self.mode != 'approve':
            return 'denied'
        wall = step['clock']['wall']
        key = (step['grant'], repr(sorted(step['request'].items(), key=repr)))
        kept = {
            k: v for k, v in self.approvals.items() if k != key and v > wall
        }
        if len(kept) >= 16:
            return 'exhausted'
        kept[key] = wall + step['ttl']
        self.approvals = kept
        return 'ok'

    def delegate(self, step):
        if not self.charge():
            return 'exhausted'
        problem = self.holder(step)
        if problem:
            return problem
        parent = self.grants[step['grant']]
        if len(self.grants) >= 64:
            return 'exhausted'
        if parent['depth'] >= 4:
            return 'denied'
        wanted = step['narrowing']
        limit = wanted.get('max_requests', parent['limit'])
        body = wanted.get('max_body_bytes', parent['body'])
        if limit > parent['limit'] or body > parent['body']:
            return 'denied'
        ops = {}
        for name, narrowed in wanted['operations'].items():
            if name not in parent['ops']:
                return 'denied'
            wider = parent['ops'][name]
            params = {}
            for key, allowed in wider['params'].items():
                if key in narrowed:
                    chosen = narrowed[key]
                    if isinstance(chosen, dict):
                        chosen = range(chosen['min'], chosen['max'] + 1)
                    if not set(chosen) <= allowed:
                        return 'denied'
                    params[key] = set(chosen)
                else:
                    params[key] = set(allowed)
            if any(key not in wider['params'] for key in narrowed):
                return 'denied'
            ops[name] = {**wider, 'params': params}
        wall, mono = step['clock']['wall'], step['clock']['mono']
        life = wanted.get('lifetime_seconds')
        self.grants[step['as']] = {
            'parent': step['grant'], 'depth': parent['depth'] + 1, 'alive': True,
            'used': 0, 'limit': limit, 'body': body, 'start': wall, 'ops': ops,
            'end': parent['end'] if life is None else min(parent['end'], wall + life),
            'deadline': (
                parent['deadline'] if life is None
                else min(parent['deadline'], mono + life)
            ),
        }  # fmt: skip
        return 'ok'

    def step(self, step):
        do = step['do']
        if do == 'revoke':
            if step['grant']:
                self.grants[step['grant']]['alive'] = False
            else:
                self.session = False
            return 'ok'
        if do == 'approve':
            return self.approve(step)
        if do == 'request':
            return self.request(step)
        if do == 'delegate':
            return self.delegate(step)
        if not self.charge():
            return 'exhausted'
        problem = self.holder(step, timed=do == 'describe')
        if problem:
            return problem
        if do == 'renounce':
            self.grants[step['grant']]['alive'] = False
        return 'ok'

    def remaining(self, name):
        return min(g['limit'] - g['used'] for g in self.lineage(name))


def generate(rng: random.Random, model: Model, clock: dict, index: int) -> dict:
    """One plausible-or-hostile step, chosen with knowledge of live grants."""
    # Mostly forward, sometimes a large jump, sometimes a wall-clock rollback.
    clock['mono'] += rng.choice([0, 0, 1, 5, 30, 200])
    clock['wall'] += rng.choice([0, 0, 1, 5, 30, 200, -50, -400])
    step: dict = {'clock': dict(clock), 'grant': rng.choice(list(model.grants))}
    roll = rng.random()
    if roll < 0.55:
        step['do'] = 'request'
        operation = rng.choice(list(OPERATIONS) + ['issue.delete'])
        arguments: dict = {}
        if operation in ('issue.view', 'issue.comment'):
            arguments['issue'] = rng.choice([23, 23, 24, 24, 25, '23', True])
        if operation == 'issue.list':
            arguments['page'] = rng.choice([1, 2, 50, 51, 0])
        if operation == 'issue.comment':
            arguments['body'] = rng.choice(
                ['hi', 'x' * 40, 'x' * 100, 'x' * 101, 'é' * 51]
            )
        if rng.random() < 0.06:
            arguments['url'] = 'https://attacker.invalid'
        if rng.random() < 0.05 and arguments:
            del arguments[rng.choice(list(arguments))]
        step['request'] = {'operation': operation, 'arguments': arguments}
        if rng.random() < 0.04:
            step['binding'] = {'channel': 'd' * 32}
    elif roll < 0.72:
        step['do'] = 'delegate'
        step['as'] = f'g{index}'
        operations: dict = {}
        for name in rng.sample(
            list(OPERATIONS) + ['issue.delete'], rng.randint(1, 3)
        ):
            narrowed: dict = {}
            if name in ('issue.view', 'issue.comment') and rng.random() < 0.7:
                narrowed['issue'] = rng.choice(
                    [[23], [24], [23, 24], [25], [23, 99]]
                )
            if name == 'issue.list' and rng.random() < 0.7:
                narrowed['page'] = rng.choice(
                    [{'min': 1, 'max': 5}, {'min': 2, 'max': 50}, {'min': 0, 'max': 9},
                     [1, 2, 3], {'min': 40, 'max': 60}]
                )  # fmt: skip
            if rng.random() < 0.04:
                narrowed['project'] = [1]
            operations[name] = narrowed
        narrowing: dict = {'operations': operations}
        if rng.random() < 0.5:
            narrowing['max_requests'] = rng.choice([1, 2, 3, 5, 6])
        if rng.random() < 0.4:
            narrowing['lifetime_seconds'] = rng.choice([1, 30, 600, 3600])
        if rng.random() < 0.3:
            narrowing['max_body_bytes'] = rng.choice([10, 50, 100, 101])
        step['narrowing'] = narrowing
    elif roll < 0.80:
        step['do'] = 'approve'
        step['ttl'] = rng.choice([1, 30, 300])
        step['request'] = {
            'operation': 'issue.comment',
            'arguments': {
                'issue': rng.choice([23, 24]),
                'body': rng.choice(['hi', 'x' * 40, 'x' * 100]),
            },
        }
    elif roll < 0.88:
        step['do'] = 'describe'
    elif roll < 0.93:
        step['do'] = 'renounce'
    else:
        step['do'] = 'revoke'
        if rng.random() < 0.15:
            step['grant'] = ''
    return step


@pytest.mark.parametrize('write_mode', ['deny', 'approve', 'allow'])
def test_generated_traces_match_the_reference_model(write_mode):
    seen: dict[str, int] = {}
    for seed in range(400):
        rng = random.Random(f'{write_mode}-{seed}')
        trace = Trace(https_policy(), write_mode=write_mode)
        model = Model(write_mode)
        clock = {'wall': 1000, 'mono': 100}
        history = []
        for index in range(rng.randint(5, 60)):
            step = generate(rng, model, clock, index)
            history.append(step)
            expected = model.step(step)
            outcome = trace.step(step)
            assert outcome['code'] == expected, (seed, index, history[-3:])
            if step['do'] == 'describe' and expected == 'ok':
                remaining = outcome['grant']['remaining_requests']
                assert remaining == model.remaining(step['grant'])
            if step['do'] == 'request' and expected == 'ok':
                # EFFECT-01: an admitted request yields exactly one effect,
                # of the class its operation was authorized as.
                effect = outcome['effect']
                wire = step['request']
                assert effect['target'].startswith('/v1/')
                is_write = OPERATIONS[wire['operation']]['write']
                assert (effect['method'] != 'GET') == is_write
                assert ('body' in effect) == is_write
            invariants(trace.state)
            seen[expected] = seen.get(expected, 0) + 1
    # The generator must actually reach each kind of outcome, or agreement
    # with the model would be vacuous.
    always = {'ok', 'denied', 'invalid_request', 'revoked', 'expired',
              'exhausted', 'wrong_binding'}  # fmt: skip
    assert always <= set(seen), seen
    assert all(seen[code] >= 25 for code in always), seen
    assert ('approval_required' in seen) == (write_mode == 'approve')


def test_a_trace_is_deterministic_and_pure_data():
    document = {
        'policy': https_policy(),
        'write_mode': 'allow',
        'steps': [
            {'do': 'request', 'grant': 'root', 'clock': {'wall': 1000, 'mono': 100},
             'request': {'operation': 'issue.list', 'arguments': {'page': 3}}},
            {'do': 'delegate', 'grant': 'root', 'as': 'helper',
             'clock': {'wall': 1001, 'mono': 101},
             'narrowing': {'operations': {'issue.view': {'issue': [24]}}, 'max_requests': 1}},
            {'do': 'request', 'grant': 'helper', 'clock': {'wall': 1002, 'mono': 102},
             'request': {'operation': 'issue.view', 'arguments': {'issue': 24}}},
            {'do': 'request', 'grant': 'helper', 'clock': {'wall': 1002, 'mono': 102},
             'request': {'operation': 'issue.view', 'arguments': {'issue': 24}}},
            {'do': 'revoke', 'grant': ''},
            {'do': 'request', 'grant': 'root', 'clock': {'wall': 1003, 'mono': 103},
             'request': {'operation': 'profile.read'}},
        ],
    }  # fmt: skip
    first = run_trace(document)
    assert first == run_trace(document)
    assert [outcome['code'] for outcome in first] == [
        'ok', 'ok', 'ok', 'exhausted', 'ok', 'revoked',
    ]  # fmt: skip
    assert first[0]['effect'] == {
        'method': 'GET',
        'target': '/v1/issues?page=3&state=open',
        'accept': 'application/json',
        'response': 'json',
    }
    assert first[1]['grant']['remaining_requests'] == 1
