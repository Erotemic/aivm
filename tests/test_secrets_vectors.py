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


def case_bytes(case: dict) -> bytes:
    """A codec case's input: its ``text`` as UTF-8, or its raw ``hex``."""
    if 'hex' in case:
        return bytes.fromhex(case['hex'])
    return case['text'].encode('utf-8')


@pytest.mark.parametrize(
    'case', load('codec.json')['cases'], ids=lambda c: c['name']
)
def test_codec_vectors(case):
    if not case['valid']:
        with pytest.raises(SecretsError):
            codec.loads(case_bytes(case))
        return
    value = codec.loads(case_bytes(case))
    canonical = codec.dumps(value)
    assert canonical.decode('ascii') == case['canonical']
    assert codec.digest(value) == case['sha256']
    assert hashlib.sha256(canonical).hexdigest() == case['sha256']
    assert codec.dumps(codec.loads(canonical)) == canonical  # a fixed point


def test_codec_corpus_has_the_required_witnesses() -> None:
    """Vacuity guards: each hardening rule is witnessed both ways."""
    cases = load('codec.json')['cases']
    for case in cases:
        assert ('text' in case) != ('hex' in case), case['name']
        if 'hex' in case:
            assert case['hex'] == bytes.fromhex(case['hex']).hex(), case['name']
    raw = [case for case in cases if 'hex' in case]
    assert any(case['valid'] for case in raw)
    assert sum(not case['valid'] for case in raw) >= 8
    # Raw bytes that are not UTF-8 can only be stated in hex.
    undecodable = []
    for case in raw:
        try:
            bytes.fromhex(case['hex']).decode('utf-8')
        except UnicodeDecodeError:
            undecodable.append(case)
    assert len(undecodable) >= 5 and not any(c['valid'] for c in undecodable)
    escapes = [case for case in cases
               if '\\ud' in case.get('text', '').lower()]
    assert any(case['valid'] for case in escapes), 'a surrogate pair'
    assert sum(not case['valid'] for case in escapes) >= 5, 'lone surrogates'
    by_name = {case['name']: case for case in cases}
    assert by_name['negative zero is the integer zero']['canonical'] == '[0]'


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


def test_the_shorthand_and_the_manifest_it_stands_for_are_one_policy():
    """Schema 1 has no behaviour of its own: its digest is its expansion's."""
    cases = {case['name']: case for case in load('policy.json')['cases']}
    shorthand = cases['github pull requests']
    written_out = cases['github: the manifest the shorthand stands for']
    assert shorthand['policy']['schema'] == 1
    assert written_out['policy']['schema'] == 2
    assert shorthand['sha256'] == written_out['sha256']
    assert shorthand['canonical'] == written_out['canonical']


def test_policy_corpus_has_the_required_witnesses():
    cases = load('policy.json')['cases']
    valid = [case for case in cases if case['valid']]
    operations = [
        op for case in valid for op in case['canonical']['operations']
    ]
    # Vacuity guards: a parser that refused every new construct would pass
    # the negative cases alone.
    assert any(
        op['effect'] == 'write' and op.get('method') == 'GET'
        for op in operations
    )
    assert any(op.get('returns') == 'check' for op in operations)
    assert any(case['canonical']['checks'] for case in valid)
    assert any(case['canonical']['cli'] for case in valid)
    assert sum(not case['valid'] for case in cases) >= 40


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
    # The class of an effect is declared, so both of these must be witnessed
    # with the same method.
    for declared in (True, False):
        assert any(
            effect(step) == 'GET' and step['expect'].get('write') is declared
            for step in steps
        ), f'GET authorized with write={declared}'
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
