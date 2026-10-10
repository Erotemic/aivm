"""Deterministic, offline fixtures for the secret broker."""

import copy
import os
from pathlib import Path

from aivm_secrets.broker import Broker
from aivm_secrets.core import Binding, Policy
from aivm_secrets.wire import dumps

TOKEN = 'github_pat_TEST_ONLY_NOT_A_REAL_CREDENTIAL_123456789'


def policy_data(**changes):
    data = {'schema': 1, 'repository': 'TauCetiProject/TauCeti',
            'pr_numbers': [13861, 13862],
            'operations': ['pr.view', 'pr.diff', 'pr.comments', 'pr.reviews',
                           'pr.review-comments', 'pr.checks', 'pr.comment', 'pr.edit'],
            'author': 'Erotemic', 'head_repository': 'Erotemic/TauCeti',
            'lifetime_seconds': 1800, 'max_requests': 20, 'max_body_bytes': 8192}
    data.update(changes)
    return data


def write_policy_file(path: Path, **changes) -> Path:
    """Create a policy fixture safely, irrespective of the caller's umask.

    A group-writable default umask (0002) must not turn positive policy
    tests into `unsafe_file` failures. Use a private mode from creation,
    including on a host with permissive default file creation settings.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(dumps(policy_data(**changes)))
    return path


def metadata():
    return {'number': 13861, 'title': 'Proof repair', 'body': 'Example',
            'base': {'repo': {'full_name': 'TauCetiProject/TauCeti'}},
            'head': {'repo': {'full_name': 'Erotemic/TauCeti'}, 'sha': 'a' * 40},
            'user': {'login': 'Erotemic'}}


class FakeProvider:
    def __init__(self):
        self.calls = []
        self.metadata = metadata()
        self.result = []
        self.after_metadata = None

    def execute(self, route, credential):
        self.calls.append((route, credential))
        if route.method == 'GET' and route.path.endswith('/pulls/13861') and route.media == 'json':
            if self.after_metadata:
                self.after_metadata()
            return copy.deepcopy(self.metadata)
        if route.media == 'diff':
            return 'diff --git a/proof.lean b/proof.lean\n'
        if '/check-runs?' in route.path:
            return {'total_count': 1, 'check_runs': [{'name': 'lean', 'status': 'completed'}]}
        return copy.deepcopy(self.result)


class Clock:
    wall = 1000
    monotonic = 100


class Harness:
    def __init__(self, path: Path, *, provider=None, allow_writes=False, **policy_changes):
        self.provider = provider or FakeProvider()
        self.clock = Clock()
        self.policy = Policy.parse(policy_data(**policy_changes))
        self.binding = Binding(os.getuid(), 'principal-test', 'vm-test', 'b' * 32)
        self.audit = path / 'audit' / 'session.jsonl'
        self.broker = Broker(self.policy, self.binding, TOKEN, self.audit,
                             allow_writes=allow_writes, provider=self.provider,
                             wall_clock=lambda: self.clock.wall,
                             monotonic_clock=lambda: self.clock.monotonic)

    def raw(self, operation='pr.view', **changes):
        request = {'operation': operation, 'repository': 'TauCetiProject/TauCeti', 'pr': 13861}
        request.update(changes)
        return dumps({'version': 1, 'capability': self.broker.capability, 'request': request})

    def call(self, operation='pr.view', **changes):
        return self.broker.handle(self.raw(operation, **changes))
