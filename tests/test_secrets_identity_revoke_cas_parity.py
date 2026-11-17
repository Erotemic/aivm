"""Versioned replay corpus for conditional revocation under host registry CAS."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from aivm_secrets.identity.registry_runner import evaluate

CASES = Path(__file__).parent / 'secrets_vectors' / 'identity-revoke-cas-v1.jsonl'


def cases():
    return [json.loads(line) for line in CASES.read_text().splitlines()]


def run(argv, examples):
    data=''.join(json.dumps(x['input']) + '\n' for x in examples)
    proc=subprocess.run(argv,input=data,text=True,capture_output=True,
                        timeout=30,check=True)
    return [json.loads(line) for line in proc.stdout.splitlines()]


def test_frozen_host_compensation_vectors():
    items=cases()
    assert len(items)>=60
    expected=[x['expected_result'] for x in items]
    assert [evaluate(x['input']) for x in items] == expected
    assert run([sys.executable,'-m','aivm_secrets.identity.registry_runner'],items)==expected
    assert sum(v.get('revoked') is True for v in expected)>=10
    assert sum(v.get('revoked') is False for v in expected)>=30


def test_rust_registry_revoke_cas_parity_when_available():
    runner=os.environ.get('AIVM_SECRETS_RUST_REGISTRY_RUNNER')
    if not runner:
        pytest.skip('independent Rust registry runner pending')
    assert Path(runner).is_file()
    assert run([runner],cases()) == run([
        sys.executable,'-m','aivm_secrets.identity.registry_runner'],cases())
