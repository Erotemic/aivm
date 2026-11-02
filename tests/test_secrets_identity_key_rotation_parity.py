"""Independent Rust and Python contract fixtures for guest-key replacement."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from aivm_secrets.identity.key_rotation_runner import evaluate

CASES = Path(__file__).parent / 'secrets_vectors' / 'identity-key-rotation-v1.jsonl'


def cases():
    return [json.loads(line) for line in CASES.read_text().splitlines()]


def run(argv, cases):
    inp = ''.join(json.dumps(x['input']) + '\n' for x in cases)
    result = subprocess.run(argv, input=inp, text=True,
                            capture_output=True, check=True, timeout=15)
    return [json.loads(s) for s in result.stdout.splitlines()]


def test_python_contract_and_frozen_vectors():
    examples = cases()
    assert len(examples) >= 60
    assert sum(x['expected_result']['ok'] for x in examples) >= 10
    assert sum(not x['expected_result']['ok'] for x in examples) >= 35
    expected = [x['expected_result'] for x in examples]
    assert [evaluate(x['input']) for x in examples] == expected
    assert run([sys.executable, '-m', 'aivm_secrets.identity.key_rotation_runner'],
               examples) == expected


def test_reuse_rows_pin_the_same_key_renewal_rule() -> None:
    """REN-07 shares the corpus: enough accepted and refused reuse rows."""
    reuse = [x for x in cases() if x['input'].get('action') == 'reuse']
    assert len(reuse) >= 40
    assert sum(x['expected_result'] == {'ok': True} for x in reuse) >= 10
    assert sum(x['expected_result'] == {'ok': False, 'code': 'denied'}
               for x in reuse) >= 5
    assert sum(x['expected_result'].get('code') == 'invalid_capability'
               for x in reuse) >= 20
    names = [x['name'] for x in cases()]
    assert len(names) == len(set(names))


def test_rust_key_rotation_parity_once_implemented():
    runner = os.getenv('AIVM_SECRETS_RUST_KEY_ROTATION_RUNNER')
    if not runner:
        pytest.skip('independent Rust implementation not built yet')
    assert Path(runner).is_file()
    examples = cases()
    assert run([runner], examples) == run(
        [sys.executable, '-m', 'aivm_secrets.identity.key_rotation_runner'],
        examples)
