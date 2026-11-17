"""Independent Rust runner remains a required future gate, not a Python alias.

Replies are compared ``typed`` (as canonical JSON), because Python's ``==``
cannot tell ``"ok": true`` from ``"ok": 1``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aivm_secrets.identity.vm_runner import evaluate
from aivm_secrets.kernel import codec
from tests.secrets_helpers import reply_while_open, typed, typed_replies

VECTORS = (Path(__file__).parent / 'secrets_vectors' /
           'identity-managed-vm-v1.jsonl')
PYTHON = [sys.executable, '-m', 'aivm_secrets.identity.vm_runner']


def cases() -> list[dict[str, Any]]:
    return [codec.loads(line) for line in VECTORS.read_bytes().splitlines()]


def compare(argv: list[str], inputs: list[dict[str, Any]]) -> list[bytes]:
    run = subprocess.run(argv, input=b''.join(codec.dumps(x['input'])+b'\n'
                                           for x in inputs),
                         capture_output=True, check=True, timeout=20)
    values = [typed(codec.loads(line)) for line in run.stdout.splitlines()]
    assert len(values) == len(inputs), run.stderr[-1000:]
    return values


def test_python_vm_identity_runner() -> None:
    rows = cases()
    assert len(rows) >= 60
    assert sum(row['expected_result']['ok'] for row in rows) >= 10
    assert sum(not row['expected_result']['ok'] for row in rows) >= 40
    actual = compare([sys.executable, '-m',
                      'aivm_secrets.identity.vm_runner'], rows)
    assert actual == [typed(row['expected_result']) for row in rows]
    assert actual == [typed(evaluate(row['input'])) for row in rows]


def accepted_line() -> tuple[bytes, dict[str, Any]]:
    row = next(row for row in cases() if row['expected_result']['ok'])
    return codec.dumps(row['input']) + b'\n', row['expected_result']


def check_flushed(argv: list[str]) -> None:
    """Each reply is flushed, so a driver can wait for it line by line."""
    line, expected = accepted_line()
    assert typed(codec.loads(reply_while_open(argv, line))) == typed(expected)


def check_framing(argv: list[str]) -> None:
    """An oversized line is answered in its own position."""
    line, expected = accepted_line()
    oversized = b'"' + b'x' * 5000 + b'"\n'
    replies = typed_replies(argv, oversized + line + oversized + line)
    refused = {'ok': False, 'code': 'invalid_capability'}
    assert replies == [
        typed(reply) for reply in (refused, expected, refused, expected)
    ]


def test_python_vm_runner_replies_before_its_input_ends() -> None:
    check_flushed(PYTHON)


def test_python_vm_runner_answers_an_oversized_line_in_order() -> None:
    check_framing(PYTHON)


def test_rust_vm_identity_runner_requires_independent_binary() -> None:
    command = os.environ.get('AIVM_SECRETS_RUST_VM_RUNNER')
    if not command:
        pytest.skip('independent Rust managed-VM identity runner not yet implemented')
    assert Path(command).is_file()
    rows = cases()
    rust_out = compare([command], rows)
    assert rust_out == compare(
        [sys.executable, '-m', 'aivm_secrets.identity.vm_runner'], rows)
    assert rust_out == [typed(row['expected_result']) for row in rows]
    check_framing([command])
    check_flushed([command])
