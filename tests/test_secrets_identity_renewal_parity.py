"""Frozen, provider-free renewal vectors for independent Python/Rust backends."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aivm_secrets.identity.registry_runner import evaluate
from aivm_secrets.primitives import codec

CASES = Path(__file__).parent / 'secrets_vectors' / 'identity-renewal-v1.jsonl'


def cases():
    return [json.loads(line) for line in CASES.read_text().splitlines()]


def run(argv, entries):
    raw = b''.join(codec.dumps(x['input']) + b'\n' for x in entries)
    result = subprocess.run(argv, input=raw, capture_output=True,
                            check=True, timeout=30)
    answers = [codec.loads(line) for line in result.stdout.splitlines()]
    assert len(answers) == len(entries), result.stderr[-3000:]
    return answers


def test_frozen_renewal_vectors_and_runner():
    entries = cases()
    assert len(entries) >= 40
    assert sum(x['expected_result']['ok'] for x in entries) >= 10
    assert sum(not x['expected_result']['ok'] for x in entries) >= 20
    expected = [x['expected_result'] for x in entries]
    assert [evaluate(x['input']) for x in entries] == expected
    assert run([sys.executable, '-m', 'aivm_secrets.identity.registry_runner'],
               entries) == expected


def test_rust_registry_backend_matches_renewal_contract_when_built():
    executable = os.getenv('AIVM_SECRETS_RUST_REGISTRY_RUNNER')
    if not executable:
        pytest.skip('Rust registry implementation is pending; no parity proof')
    assert Path(executable).is_file(), 'configured Rust runner missing'
    entries = cases()
    assert run([executable], entries) == run(
        [sys.executable, '-m', 'aivm_secrets.identity.registry_runner'], entries)
