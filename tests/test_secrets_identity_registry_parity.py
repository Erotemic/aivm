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
    from aivm_secrets.identity.registry_model import enroll, revoke
    from aivm_secrets.identity.token import certificate_thumbprint
    state = {'schema': 1, 'subjects': {}}
    original = codec.dumps(state)
    args = {'issuer': 'aivm.test', 'audience': 'aivm-secrets.identity'}
    thumb = certificate_thumbprint(b'example DER')
    created = enroll(state, **args, subject='vm-a', thumbprint=thumb,
                     not_after=1000, replace=False)
    ended = revoke(created, **args, subject='vm-a')
    assert state == {'schema': 1, 'subjects': {}}
    assert codec.dumps(state) == original
    assert created['subjects']['vm-a']['active'] is True
    assert ended['subjects']['vm-a']['active'] is False
    assert created['subjects']['vm-a']['epoch'] == 0
    assert ended['subjects']['vm-a']['epoch'] == 1
