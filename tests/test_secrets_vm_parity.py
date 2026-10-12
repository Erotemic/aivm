"""Independent Rust runner remains a required future gate, not a Python alias."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aivm_secrets.identity.vm_runner import evaluate
from aivm_secrets.kernel import codec

VECTORS = (Path(__file__).parent / 'secrets_vectors' /
           'identity-managed-vm-v1.jsonl')


def cases():
    return [codec.loads(line) for line in VECTORS.read_bytes().splitlines()]


def compare(argv, inputs):
    run = subprocess.run(argv, input=b''.join(codec.dumps(x['input'])+b'\n'
                                           for x in inputs),
                         capture_output=True, check=True, timeout=20)
    values = [codec.loads(line) for line in run.stdout.splitlines()]
    assert len(values) == len(inputs), run.stderr[-1000:]
    return values


def test_python_vm_identity_runner():
    rows = cases()
    assert len(rows) >= 60
    assert sum(row['expected_result']['ok'] for row in rows) >= 10
    assert sum(not row['expected_result']['ok'] for row in rows) >= 40
    actual = compare([sys.executable, '-m',
                      'aivm_secrets.identity.vm_runner'], rows)
    assert actual == [row['expected_result'] for row in rows]
    assert actual == [evaluate(row['input']) for row in rows]


def test_rust_vm_identity_runner_requires_independent_binary():
    command = os.environ.get('AIVM_SECRETS_RUST_VM_RUNNER')
    if not command:
        pytest.skip('independent Rust managed-VM identity runner not yet implemented')
    assert Path(command).is_file()
    rows = cases()
    assert compare([command], rows) == compare(
        [sys.executable, '-m', 'aivm_secrets.identity.vm_runner'], rows)
