"""Replay the frozen protocol-v1 conformance corpus.

The vectors under ``tests/secrets_vectors`` are data any implementation of
the kernel can consume. See the README beside them for what is specification
and what is a regression pin.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aivm_secrets.errors import MESSAGES, SecretsError
from aivm_secrets.host.envelope import EnvelopeCodec
from aivm_secrets.kernel import codec, grammar
from aivm_secrets.kernel.model import Claims
from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.kernel.trace import run_trace

ROOT = Path(__file__).parent / 'secrets_vectors' / 'v1'
TRACES = sorted((ROOT / 'traces').glob('*.json'))


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding='utf-8'))


def includes(actual, expected) -> bool:
    """Conformance relation: ``expected`` is a recursive subset of ``actual``."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and includes(actual[key], value)
            for key, value in expected.items()
        )
    return actual == expected


@pytest.mark.parametrize(
    'case', load('codec.json')['cases'], ids=lambda c: c['name']
)
def test_codec_vectors(case):
    if not case['valid']:
        with pytest.raises(SecretsError):
            codec.loads(case['text'])
        return
    value = codec.loads(case['text'])
    canonical = codec.dumps(value)
    assert canonical.decode('ascii') == case['canonical']
    assert codec.digest(value) == case['sha256']
    assert hashlib.sha256(canonical).hexdigest() == case['sha256']
    assert codec.dumps(codec.loads(canonical)) == canonical  # a fixed point


def test_codec_limits_are_the_documented_ones():
    limits = load('codec.json')['limits']
    assert limits == {
        'max_frame_bytes': codec.MAX_FRAME,
        'max_depth': codec.MAX_DEPTH,
    }


@pytest.mark.parametrize('name', sorted(load('grammar.json')['validators']))
def test_grammar_vectors(name):
    cases = load('grammar.json')['validators'][name]
    validator = getattr(grammar, name)
    for value in cases['accept']:
        assert validator(value) == value
    for value in cases['reject']:
        with pytest.raises(SecretsError):
            validator(value)
    assert cases['accept'] and cases['reject']


@pytest.mark.parametrize(
    'case', load('policy.json')['cases'], ids=lambda c: c['name']
)
def test_policy_vectors(case):
    if not case['valid']:
        with pytest.raises(SecretsError) as caught:
            parse_policy(case['policy'])
        assert caught.value.code == 'invalid_policy'
        return
    spec = parse_policy(case['policy'])
    assert spec.to_dict() == case['canonical']
    assert spec.digest == case['sha256']
    assert (
        spec.digest
        == hashlib.sha256(codec.dumps(case['canonical'])).hexdigest()
    )
    assert [operation.to_wire() for operation in spec.scope()] == case['scope']
    assert parse_policy(case['canonical']) == spec


@pytest.mark.parametrize('path', TRACES, ids=lambda path: path.stem)
def test_trace_vectors(path):
    document = json.loads(path.read_text(encoding='utf-8'))
    outcomes = run_trace(document)
    assert len(outcomes) == len(document['steps'])
    for index, (step, outcome) in enumerate(zip(document['steps'], outcomes)):
        assert includes(outcome, step['expect']), (path.name, index, outcome)
        assert outcome['code'] == 'ok' or outcome['code'] in MESSAGES


def test_trace_corpus_has_the_required_witnesses():
    """Vacuity guards from the assurance plan's CI gates.

    A theorem with no trace, or a corpus with no authorized read, authorized
    write, legal narrowing or budget exhaustion, would let a kernel that
    refuses everything pass.
    """
    documents = [json.loads(path.read_text()) for path in TRACES]
    covered = {name for document in documents for name in document['theorems']}
    assert {
        'AUTH-01', 'EFFECT-01', 'BIND-01', 'TIME-01', 'REVOKE-01', 'BUDGET-01',
        'ATTEN-01', 'APPROVAL-01',
    } <= covered  # fmt: skip
    steps = [step for document in documents for step in document['steps']]

    def effect(step):
        return (step['expect'].get('effect') or {}).get('method')

    assert any(effect(step) == 'GET' for step in steps), 'authorized read'
    assert any(effect(step) in ('POST', 'PATCH') for step in steps), (
        'authorized write'
    )
    assert any(
        step['do'] == 'delegate' and step['expect']['code'] == 'ok'
        for step in steps
    ), 'legal narrowing'
    assert any(step['expect']['code'] == 'exhausted' for step in steps)
    refused = {step['expect']['code'] for step in steps} - {'ok'}
    assert {
        'denied', 'invalid_request', 'expired', 'revoked', 'exhausted',
        'wrong_binding', 'approval_required', 'resource_mismatch',
    } <= refused  # fmt: skip


def test_envelope_vector_opens_to_exactly_its_claims():
    vector = load('envelope.json')
    opened = EnvelopeCodec(bytes.fromhex(vector['key_hex'])).open(
        vector['capability']
    )
    assert opened.claims == Claims.parse(vector['claims'])
    assert opened.credential == vector['credential']
    assert codec.dumps(
        {'claims': vector['claims'], 'credential': vector['credential']}
    ) == vector['plaintext'].encode('ascii')
    with pytest.raises(SecretsError):
        EnvelopeCodec(bytes(32)).open(vector['capability'])
