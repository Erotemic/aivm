"""Frozen pure enrollment state vectors for Python and future Rust.

These are NOT proofs. The Rust test deliberately SKIPS until a configured,
independently built runner is provided; no fallback to Python is permitted.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aivm_secrets.identity.registry_runner import evaluate
from aivm_secrets.kernel import codec

CASES = Path(__file__).parent / 'secrets_vectors' / 'identity-registry-v1.jsonl'


def cases():
    return [json.loads(line) for line in CASES.read_text().splitlines()]


def run(argv, inputs):
    payload = b''.join(codec.dumps(entry['input']) + b'\n' for entry in inputs)
    result = subprocess.run(argv, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(inputs), result.stderr[-1000:]
    return [codec.loads(line) for line in lines]


def test_python_registry_runner_matches_frozen_vectors():
    items = cases()
    assert len(items) >= 60
    assert sum(item['expected_result']['ok'] for item in items) >= 10
    assert sum(not item['expected_result']['ok'] for item in items) >= 30
    reference = run([sys.executable, '-m',
                     'aivm_secrets.identity.registry_runner'], items)
    assert reference == [case['expected_result'] for case in items]
    assert reference == [evaluate(case['input']) for case in items]


def test_rust_registry_runner_requires_explicit_independent_executable():
    program = os.environ.get('AIVM_SECRETS_RUST_REGISTRY_RUNNER')
    if not program:
        pytest.skip('Rust enrollment kernel not yet implemented or verified')
    assert Path(program).is_file(), 'configured Rust runner missing'
    items = cases()
    rust = run([program], items)
    python = run([sys.executable, '-m',
                  'aivm_secrets.identity.registry_runner'], items)
    assert rust == python == [item['expected_result'] for item in items]


def test_registry_transitions_leave_input_unchanged():
    from aivm_secrets.identity.garrett.registry import enroll, revoke
    from aivm_secrets.identity.token import certificate_thumbprint
    state = {'schema': 1, 'subjects': {}}
    original = codec.dumps(state)
    args = {'issuer': 'aivm.test', 'audience': 'aivm-secrets.identity'}
    thumb = certificate_thumbprint(b'example DER')
    created = enroll(state, **args, subject='vm-a', thumbprint=thumb,
                     key_sha256='1' * 64, not_after=1000, replace=False)
    ended = revoke(created, **args, subject='vm-a')
    assert state == {'schema': 1, 'subjects': {}}
    assert codec.dumps(state) == original
    assert created['subjects']['vm-a']['active'] is True
    assert ended['subjects']['vm-a']['active'] is False
    assert created['subjects']['vm-a']['epoch'] == 0
    assert ended['subjects']['vm-a']['epoch'] == 1


def test_every_transition_copies_the_retired_key_lists() -> None:
    """No transition may alias, and later mutate, a list of its input."""
    from aivm_secrets.identity.garrett import registry
    from aivm_secrets.identity.token import certificate_thumbprint
    args = {'issuer': 'aivm.test', 'audience': 'aivm-secrets.identity'}
    one, two, three = (certificate_thumbprint(bytes([n])) for n in (1, 2, 3))
    state: dict[str, Any] = {'schema': 1, 'subjects': {
        'vm-a': {'epoch': 3, 'active': True, 'certificate_sha256': one,
                 'not_after': 1000, 'key_sha256': '1' * 64,
                 'retired_keys': ['0' * 64]},
        'vm-b': {'epoch': 1, 'active': False, 'certificate_sha256': two,
                 'not_after': 10, 'key_sha256': '2' * 64,
                 'retired_keys': ['3' * 64]}}}
    original = codec.dumps(state)
    results = [
        registry.enroll(state, **args, subject='vm-a', thumbprint=two,
                        key_sha256='4' * 64, not_after=2000, replace=True),
        registry.renew(state, **args, subject='vm-a', expected_epoch=3,
                       expected_thumbprint=one, thumbprint=two,
                       key_sha256='5' * 64, not_after=2000, now=100),
        registry.replace_if_current(state, **args, subject='vm-b',
                                    expected_epoch=1, expected_thumbprint=two,
                                    thumbprint=three, key_sha256='6' * 64,
                                    not_after=2000),
        registry.revoke(state, **args, subject='vm-a'),
        registry.revoke_all(state, **args),
        registry.forget(state, **args, subject='vm-b', now=10),
        registry.prune(state, **args, now=10),
        registry.revoke_if_current(state, **args, subject='vm-a',
                                   expected_epoch=3,
                                   expected_thumbprint=one)[0],
    ]
    for result in results:
        for name, row in result['subjects'].items():
            if name in state['subjects']:
                assert row['retired_keys'] is not state['subjects'][name]['retired_keys']
            row['retired_keys'].append('f' * 64)
    assert codec.dumps(state) == original


def test_a_full_registry_fits_the_runner_line_and_the_host_file() -> None:
    """MAX_SUBJECTS rows at their largest must remain writable and replayable."""
    from aivm_secrets.identity.enrollment import MAX_REGISTRY_BYTES
    from aivm_secrets.identity.garrett import registry
    from aivm_secrets.identity.registry_runner import MAX_LINE
    subjects = {}
    for n in range(registry.MAX_SUBJECTS):
        subjects[f'{n:03d}' + 'x' * 125] = {
            'epoch': 2**31 - 1, 'active': False,
            'certificate_sha256': 'gPk-jH0OHgg-aqsLBzAR2FjQkpUetLstWVzUMXPgRwQ',
            'not_after': 2**63 - 1, 'key_sha256': f'{n:064x}',
            'retired_keys': [f'{4096 + 16 * n + k:064x}'
                             for k in range(registry.MAX_RETIRED_KEYS)]}
    state = {'schema': 1, 'subjects': subjects}
    issuer, audience = 'i' * 128, 'a' * 128
    registry.validate(state, issuer=issuer, audience=audience)
    size = len(codec.dumps(state))
    assert size <= MAX_REGISTRY_BYTES
    line = codec.dumps({'version': 1, 'action': 'prune', 'issuer': issuer,
                        'audience': audience, 'state': state, 'now': 0})
    assert len(line) + 1 <= MAX_LINE
    assert evaluate(codec.loads(line, limit=MAX_LINE)) == {'ok': True,
                                                           'state': state}


def test_corpus_covers_every_registry_action() -> None:
    from aivm_secrets.identity.registry_runner import ACTIONS
    seen = {item['input'].get('action') for item in cases()
            if type(item['input'].get('action')) is str}
    assert set(ACTIONS) <= seen
    names = [item['name'] for item in cases()]
    assert len(names) == len(set(names))
    revoke_max = [item for item in cases() if item['name'] == 'revoke_epoch_3']
    # Fail-safe revocation: deactivated in place at the maximum epoch.
    assert revoke_max[0]['expected_result']['state']['subjects']['vm-alpha'][
        'active'] is False
