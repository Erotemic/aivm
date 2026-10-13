"""Security and parity gates for the self-contained Garrett protocol core.

These are empirical checks, not Rust/Lean proofs. The crypto/TLS/host adapters
remain in the existing implementation and have separate integration tests.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.garrett import (
    IdentityClaims, IdentityExpectation, prepare_issue,
)
from aivm_secrets.identity.garrett import registry, vm
from aivm_secrets.identity.garrett_runner import evaluate
from aivm_secrets.primitives import binding, codec, epochs, validity

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / 'tests/secrets_vectors/garrett-protocol-v1.jsonl'
PURE_ROOTS = (ROOT / 'aivm_secrets/primitives',
              ROOT / 'aivm_secrets/identity/garrett')
ALLOWED = {'__future__', 'dataclasses', 'typing', 'json', 'hashlib', 'uuid'}


def cases():
    return [json.loads(line) for line in VECTORS.read_text().splitlines()]


def call_runner(program: list[str], rows: list[dict]) -> list[dict]:
    given = b''.join(codec.dumps(row['input']) + b'\n' for row in rows)
    result = subprocess.run(program, input=given, capture_output=True,
                            check=True, timeout=30)
    actual = [codec.loads(line) for line in result.stdout.splitlines()]
    assert len(actual) == len(rows), result.stderr[-3000:]
    return actual


def test_pure_protocol_reference_runner_matches_frozen_vectors():
    rows = cases()
    assert len(rows) >= 35
    assert sum(row['expected_result']['ok'] for row in rows) >= 4
    assert sum(not row['expected_result']['ok'] for row in rows) >= 25
    expected = [row['expected_result'] for row in rows]
    assert [evaluate(row['input']) for row in rows] == expected
    assert call_runner([sys.executable, '-m',
                        'aivm_secrets.identity.garrett_runner'], rows) == expected


def test_rust_runner_must_be_a_real_independent_backend():
    executable = os.getenv('AIVM_SECRETS_RUST_GARRETT_RUNNER')
    if executable is None:
        pytest.skip('the Rust Garrett protocol implementation is not built')
    assert Path(executable).is_file(), 'configured Rust runner absent'
    rows = cases()
    rust = call_runner([executable], rows)
    python = call_runner([sys.executable, '-m',
                          'aivm_secrets.identity.garrett_runner'], rows)
    assert rust == python == [row['expected_result'] for row in rows]


def test_validity_is_exclusive_at_expiry_and_rejects_bool():
    validity.require_active(4, 4, 5)
    for now in (3, 5, True):
        with pytest.raises(SecretsError) as exc:
            validity.require_active(now, 4, 5)
        assert exc.value.code == 'invalid_capability'


def test_epoch_increment_is_bounded_and_monotone():
    assert epochs.advance(0, maximum=4) == 1
    assert epochs.advance(3, maximum=4) == 4
    with pytest.raises(SecretsError) as exc:
        epochs.advance(4, maximum=4)
    assert exc.value.code == 'revoked'
    with pytest.raises(SecretsError):
        epochs.require_current(2, 3)
    epochs.require_current(2, 2)


def test_binding_checks_all_authenticated_fields():
    binding.require_match('same', 'same')
    with pytest.raises(SecretsError):
        binding.require_match('peer-a', 'peer-b')
    with pytest.raises(SecretsError):
        binding.require_match(5, 5)


def test_issuer_does_not_mutate_enrollment_and_cannot_issue_after_revocation():
    row = cases()[0]['input']
    state = json.loads(json.dumps(row['state']))
    encoded = codec.dumps(state)
    result = prepare_issue(state, issuer=row['issuer'], audience=row['audience'],
                           subject=row['subject'], token_id=row['token_id'],
                           now=row['now'], lifetime=row['lifetime'])
    assert isinstance(result.claims, IdentityClaims)
    assert codec.dumps(state) == encoded
    with pytest.raises(FrozenInstanceError):
        result.claims = None
    after = registry.revoke(state, issuer=row['issuer'],
                            audience=row['audience'], subject=row['subject'])
    with pytest.raises(SecretsError) as exc:
        prepare_issue(after, issuer=row['issuer'], audience=row['audience'],
                      subject=row['subject'], token_id=row['token_id'],
                      now=row['now'], lifetime=row['lifetime'])
    assert exc.value.code == 'invalid_capability'


def test_only_canonical_garrett_modules_define_identity_decisions():
    """No compatibility facades for identity protocols that were never deployed."""
    from aivm_secrets.identity import IdentityClaims as public_claims
    from aivm_secrets.identity import IdentityExpectation as public_expectation
    assert public_claims is IdentityClaims
    assert public_expectation is IdentityExpectation
    assert not (ROOT / 'aivm_secrets/identity/model.py').exists()
    assert not (ROOT / 'aivm_secrets/identity/registry_model.py').exists()
    assert not (ROOT / 'aivm_secrets/identity/vm_model.py').exists()


def test_primitives_and_garrett_core_have_no_host_or_kernel_dependencies():
    """Only pure stdlib and explicit shared primitives are available."""
    files = [file for folder in PURE_ROOTS for file in folder.glob('*.py')]
    assert len(files) >= 10
    denied_calls = {'open', 'input', 'eval', 'exec', 'compile', '__import__',
                    'getattr', 'setattr'}
    for file in files:
        tree = ast.parse(file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split('.')[0] in ALLOWED, (file, alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    assert (node.module or '').split('.')[0] in ALLOWED, file
                else:
                    assert not any(x in (node.module or '').split('.')
                                   for x in ('host', 'kernel', 'transport', 'aivm'))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in denied_calls, (file, node.func.id)
            assert not isinstance(node, (ast.Global, ast.Nonlocal,
                                         ast.AsyncFunctionDef, ast.Await)), file


def test_protocol_package_imports_without_runtime_adapters():
    # Fresh interpreter, no logging, socket/TLS or host broker imported.
    program = ('import sys\n'
               'import aivm_secrets.identity.garrett\n'
               'loaded=[x for x in sys.modules if x.startswith('
               '"aivm_secrets.host") or x.startswith('
               '"aivm_secrets.kernel") or x.startswith('
               '"aivm_secrets.identity.enrollment") or x.startswith('
               '"aivm_secrets.identity.token")]\n'
               'print(loaded)\n')
    done = subprocess.run([sys.executable, '-c', program],
                          cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == '[]'
