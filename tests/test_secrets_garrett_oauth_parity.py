"""Frozen, external language-neutral OAuth transition contract."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aivm_secrets.identity.oauth_runner import evaluate
from aivm_secrets.primitives.codec import dumps

HERE = Path(__file__).resolve().parent
VECTORS = HERE / 'secrets_vectors/garrett-oauth-v1.jsonl'


def rows():
    return [json.loads(line) for line in VECTORS.read_text().splitlines()]


def runner(argv, cases):
    data = b''.join(dumps(row['input']) + b'\n' for row in cases)
    finished = subprocess.run(argv, input=data, capture_output=True, timeout=30)
    assert finished.returncode == 0, finished.stderr[-2000:]
    answers = [json.loads(line) for line in finished.stdout.splitlines()]
    assert len(answers) == len(cases)
    return answers


def test_reference_matches_frozen_contract():
    cases = rows()
    assert len(cases) >= 65
    assert len({row['id'] for row in cases}) == len(cases)
    assert sum(row['expected_result']['ok'] for row in cases) >= 6
    assert sum(not row['expected_result']['ok'] for row in cases) >= 40
    want = [row['expected_result'] for row in cases]
    assert [evaluate(row['input']) for row in cases] == want
    assert runner([sys.executable, '-m', 'aivm_secrets.identity.oauth_runner'], cases) == want


def test_rust_runner_is_optional_until_implemented():
    rust = os.environ.get('AIVM_SECRETS_RUST_OAUTH_RUNNER')
    if rust is None:
        pytest.skip('no independent Rust OAuth backend yet')
    assert Path(rust).is_file(), 'advertised Rust OAuth runner is missing'
    cases = rows()
    assert runner([rust], cases) == [row['expected_result'] for row in cases]
