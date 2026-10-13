"""Pure authority selection contract and cross-language parity gate."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.authority_runner import evaluate
from aivm_secrets.identity.garrett import authority
from aivm_secrets.primitives import codec

CASES = Path(__file__).parent / 'secrets_vectors/identity-trust-generation-v1.jsonl'


def rows():
    return [json.loads(line) for line in CASES.read_text().splitlines()]


def run(argv, entries):
    given = b''.join(codec.dumps(row['input']) + b'\n' for row in entries)
    done = subprocess.run(argv, input=given, capture_output=True,
                          timeout=30, check=True)
    actual = [codec.loads(line) for line in done.stdout.splitlines()]
    assert len(actual) == len(entries), done.stderr[-3000:]
    return actual


def test_frozen_authority_vectors_and_python_runner():
    cases = rows()
    assert len(cases) >= 50
    assert sum(row['expected_result']['ok'] for row in cases) >= 7
    assert sum(not row['expected_result']['ok'] for row in cases) >= 30
    expected = [row['expected_result'] for row in cases]
    assert [evaluate(row['input']) for row in cases] == expected
    assert run([sys.executable, '-m', 'aivm_secrets.identity.authority_runner'],
               cases) == expected


def test_rust_authority_backend_parity_when_available():
    runner = os.getenv('AIVM_SECRETS_RUST_AUTHORITY_RUNNER')
    if runner is None:
        pytest.skip('Rust authority implementation not yet built; no parity claim')
    assert Path(runner).is_file()
    entries = rows()
    assert run([runner], entries) == run(
        [sys.executable, '-m', 'aivm_secrets.identity.authority_runner'], entries)


def test_a_malformed_action_does_not_end_the_reply_stream() -> None:
    """B18: an unhashable action used to raise TypeError and kill the runner."""
    valid = {'version': 1, 'action': 'init', 'issuer': 'aivm.local',
             'audience': 'aivm-secrets.identity', 'created_at': 1,
             'ca_sha256': 'a' * 64}
    entries = [{'input': {'version': 1, 'action': ['x']}},
               {'input': {'version': 1, 'action': {}}},
               {'input': valid}]
    replies = run([sys.executable, '-m', 'aivm_secrets.identity.authority_runner'],
                  entries)
    assert replies[:2] == [{'ok': False, 'code': 'invalid_capability'}] * 2
    assert replies[2]['ok'] is True


def test_require_ca_is_the_rotation_compare_and_swap() -> None:
    state = authority.initial(issuer='aivm.local',
        audience='aivm-secrets.identity', created_at=100, ca_sha256='a' * 64)
    assert authority.require_ca(state, expected_sha256='a' * 64) == state
    with pytest.raises(SecretsError) as exc:
        authority.require_ca(state, expected_sha256='b' * 64)
    assert exc.value.code == 'revoked'
    rotated = authority.activate_ca(state, ca_generation=2, ca_sha256='b' * 64,
                                    server_generation=2)
    with pytest.raises(SecretsError) as exc:
        authority.require_ca(rotated, expected_sha256='a' * 64)
    assert exc.value.code == 'revoked'
    actions = {row['input'].get('action') for row in rows()
               if type(row['input'].get('action')) is str}
    assert 'require-ca' in actions


def test_sequential_renewal_and_ca_rotation_only_increase_generation():
    state = authority.initial(issuer='aivm.local',
        audience='aivm-secrets.identity', created_at=100, ca_sha256='a'*64)
    first = authority.activate_server(state, server_generation=2)
    next_state = authority.activate_ca(first, ca_generation=2,
                                      ca_sha256='b'*64, server_generation=3)
    assert next_state['ca']['generation'] > first['ca']['generation']
    assert next_state['server']['generation'] > first['server']['generation']
    assert next_state['server']['ca_generation'] == next_state['ca']['generation']
    assert first['ca']['sha256'] == state['ca']['sha256']
    with pytest.raises(SecretsError):
        authority.activate_ca(next_state, ca_generation=1, ca_sha256='c'*64,
                              server_generation=4)
    with pytest.raises(SecretsError):
        authority.activate_server(next_state, server_generation=3)
