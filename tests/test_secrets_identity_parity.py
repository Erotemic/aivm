"""Same machine-readable P4a decisions for reference Python and future Rust.

The Rust runner is NOT implemented yet. Set AIVM_SECRETS_RUST_IDENTITY_RUNNER
in the formal-verification CI job once it is built; when that is set this
suite must fail rather than fall back to Python. Python coverage is always run.

Replies are compared ``typed`` (as canonical JSON), because Python's ``==``
cannot tell ``"ok": true`` from ``"ok": 1``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aivm_secrets.identity.runner import MAX_LINE, evaluate
from aivm_secrets.kernel import codec
from tests.secrets_helpers import reply_while_open, typed, typed_replies

CASES = Path(__file__).parent / 'secrets_vectors' / 'identity-v1.jsonl'
PYTHON = [sys.executable, '-m', 'aivm_secrets.identity.runner']


def corpus() -> list[dict[str, Any]]:
    return [json.loads(line) for line in CASES.read_text().splitlines()]


def run_jsonl(argv: list[str], cases: list[dict[str, Any]]) -> list[bytes]:
    raw = b''.join(codec.dumps(case['input']) + b'\n' for case in cases)
    result = subprocess.run(argv, input=raw, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(cases), (len(lines), len(cases), result.stderr[-1000:])
    return [typed(codec.loads(line)) for line in lines]


def test_python_reference_runner_matches_frozen_vectors() -> None:
    cases = corpus()
    assert len(cases) >= 60
    actual = run_jsonl([sys.executable, '-m', 'aivm_secrets.identity.runner'], cases)
    expected = [typed(case['expected_result']) for case in cases]
    assert actual == expected
    assert actual == [typed(evaluate(case['input'])) for case in cases]


def test_the_corpus_holds_an_oversized_line_that_is_not_last() -> None:
    """Only a row with later rows behind it can catch a reordered reply."""
    sizes = [len(codec.dumps(case['input']) + b'\n') for case in corpus()]
    oversized = [index for index, size in enumerate(sizes) if size > MAX_LINE]
    assert oversized and oversized[0] < len(sizes) - 1


def check_framing(argv: list[str]) -> None:
    """An oversized line's reply comes back in its own position (B17).

    It used to be written through the unflushed text layer and so came out
    after every later reply.
    """
    valid = codec.dumps(corpus()[0]['input']) + b'\n'
    oversized = b'"' + b'x' * MAX_LINE + b'"\n'
    undecodable = b'\xff' * (MAX_LINE + 1) + b'\n'
    replies = typed_replies(argv, oversized + valid + undecodable + valid)
    refused = {'ok': False, 'code': 'invalid_capability'}
    assert replies == [
        typed(reply) for reply in (refused, {'ok': True}, refused, {'ok': True})
    ]


def check_flushed(argv: list[str]) -> None:
    """A reply is flushed before the runner reads its next line."""
    line = codec.dumps(corpus()[0]['input']) + b'\n'
    assert typed(codec.loads(reply_while_open(argv, line))) == typed({'ok': True})


def test_python_runner_answers_an_oversized_line_in_order() -> None:
    check_framing(PYTHON)


def test_python_runner_replies_before_its_input_ends() -> None:
    check_flushed(PYTHON)


def test_rust_runner_matches_python_and_frozen_vectors_when_built() -> None:
    rust = os.environ.get('AIVM_SECRETS_RUST_IDENTITY_RUNNER')
    if not rust:
        pytest.skip('Rust implementation is pending; no parity or proof is claimed')
    assert Path(rust).is_file(), 'Configured Rust identity runner does not exist'
    cases = corpus()
    reference = run_jsonl([sys.executable, '-m', 'aivm_secrets.identity.runner'], cases)
    rust_out = run_jsonl([rust], cases)
    assert rust_out == reference
    assert rust_out == [typed(case['expected_result']) for case in cases]
    check_framing([rust])
    check_flushed([rust])


def test_deterministic_crypto_interop_fixture(monkeypatch):
    """Freeze exact JWT/JWS/AEAD bytes for a future independent Rust codec."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aivm_secrets.identity import token as token_module
    from aivm_secrets.identity.garrett.claims import IdentityClaims, IdentityExpectation
    from aivm_secrets.identity.token import (
        IdentityTokenIssuer, IdentityTokenVerifier,
    )

    fixture = json.loads((CASES.parent / 'identity-crypto-v1.json').read_text())
    seed = bytes.fromhex(fixture['private_key_seed_hex'])
    key = bytes.fromhex(fixture['encryption_key_hex'])
    nonce = bytes.fromhex(fixture['aes_gcm_nonce_hex'])
    claims = IdentityClaims.parse(fixture['claims'])
    signing = Ed25519PrivateKey.from_private_bytes(seed)
    issuer = IdentityTokenIssuer(signing, key, key_id=fixture['kid'])
    monkeypatch.setattr(token_module.os, 'urandom', lambda size: nonce if size == 12 else b'\0'*size)
    actual = issuer.issue(claims, fixture['inner_capability'])
    assert actual == fixture['expected_jwt']
    expected = IdentityExpectation(claims.issuer, claims.audience,
                                   claims.subject, claims.epoch)
    verifier = IdentityTokenVerifier(signing.public_key(), key,
                                     key_id=fixture['kid'], expected=expected)
    opened = verifier.open(actual,
        authenticated_peer_der=bytes.fromhex(fixture['certificate_der_hex']),
        now=150)
    assert opened.broker_capability == fixture['inner_capability']
