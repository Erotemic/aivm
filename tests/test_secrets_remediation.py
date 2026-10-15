"""Regression tests for the host boundary and fixed GraphQL effects."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.egress import HTTPSExecutor, tls_context
from aivm_secrets.host.session import runtime_root, session_directory
from aivm_secrets.kernel import codec, presets
from aivm_secrets.kernel.model import Effect, Egress, check_effect
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import (
    REPO,
    SERVICE_TOKEN,
    TLSService,
    github_policy,
    metadata,
    must,
)


def _threads_spec():
    return parse_policy(github_policy(operations=['pr.review-threads']))


def _threads_request(spec, **extra):
    return spec.parse_request({
        'operation': 'pr.review-threads',
        'arguments': dict(repository=REPO, pr=13861, **extra),
    })


def test_runtime_root_rejects_guest_writable_xdg_directory(tmp_path, monkeypatch):
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o700)
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(shared))
    with pytest.raises(SecretsError) as err:
        runtime_root((shared,))
    assert err.value.code == 'shared_source'
    with pytest.raises(SecretsError) as err:
        session_directory('f' * 32, (shared,))
    assert err.value.code == 'shared_source'
    assert not (shared / 'aivm-secrets').exists()


def test_runtime_root_rejects_symlink_into_guest_tree(tmp_path, monkeypatch):
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o700)
    symlink = tmp_path / 'link'
    symlink.symlink_to(shared, target_is_directory=True)
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(symlink))
    with pytest.raises(SecretsError) as err:
        runtime_root((shared,))
    assert err.value.code == 'shared_source'


def test_tls_context_does_not_open_keylog_from_ambient_environment(tmp_path, monkeypatch):
    keylog = tmp_path / 'captured-keys.log'
    monkeypatch.setenv('SSLKEYLOGFILE', str(keylog))
    with TLSService(tmp_path) as service:
        pins = service.egress()
        dest = Egress(
            service.host, pins['port'], pins['address'], pins['ca_file'],
            'bearer',
        )
        tls = tls_context(dest)
        assert tls.keylog_filename is None
        service.routes[('GET', '/v1/a')] = {'ok': True}
        from aivm_secrets.kernel.machine import AuthorizedEffect
        effect = AuthorizedEffect(
            0, 'a' * 32, 'd' * 64, True, False, Effect('GET', '/v1/a')
        )
        assert HTTPSExecutor(dest).execute(effect, SERVICE_TOKEN) == {'ok': True}
        assert not keylog.exists()


def test_graphql_is_fixed_query_not_a_generic_read_post():
    spec = _threads_spec()
    req = _threads_request(spec)
    operation = spec.operations[0]
    assert operation.graphql_operation == 'AivmReviewThreads'
    effect = must(spec.final(req, metadata()))
    assert (effect.method, effect.path) == ('POST', '/graphql')
    assert effect.graphql and not effect.is_write
    assert check_effect(effect) is effect
    body = dict(effect.body)
    assert body['operation_name'] == 'AivmReviewThreads'
    assert json.loads(body['variables']) == {
        'owner': 'taucetiproject', 'name': 'tauceti', 'number': 13861,
    }
    assert spec == parse_policy(spec.to_dict())
    changed = copy.deepcopy(spec.to_dict())
    changed['operations'][0]['graphql']['document'] += ' # reviewed'
    assert parse_policy(changed).digest != spec.digest
    # Only the declared scope can select a PR/repository; the guest cannot
    # provide an alternative GraphQL document, variable map, or URL.
    for bad in ({'query': 'mutation X { deleteEverything }'},
                {'pr': 12345}, {'repository': 'attacker/elsewhere'}):
        wrong = dict(repository=REPO, pr=13861)
        wrong.update(bad)
        with pytest.raises(SecretsError):
            parsed = spec.parse_request({
                'operation': 'pr.review-threads', 'arguments': wrong,
            })
            from aivm_secrets.kernel.scope import check_arguments, find
            operation = find(spec.scope(), parsed.operation)
            assert operation is not None
            check_arguments(operation, parsed)


@pytest.mark.parametrize('document', [
    'mutation AivmReviewThreads { dangerous }',
    'query AivmReviewThreads { safe } mutation Other { dangerous }',
    'query WrongName { safe }',
    '{ dangerous }',
    'query AivmReviewThreads { safe } subscription Other { leak }',
])
def test_manifest_rejects_mutation_or_ambiguous_graphql(document):
    manifest = presets.github_pr(
        github_policy(operations=['pr.review-threads'])
    )
    manifest['operations'][0]['graphql']['document'] = document
    with pytest.raises(SecretsError) as err:
        parse_policy(manifest)
    assert err.value.code == 'invalid_policy'


def test_generic_service_supports_fixed_query_templates():
    from tests.secrets_helpers import https_policy
    op = {
        'name': 'widget.count', 'effect': 'read',
        'method': 'POST', 'path': '/graphql',
        'parameters': {'widget': [7, 8]},
        'graphql': {
            'operation': 'WidgetCount',
            'document': 'query WidgetCount($widget: Int!) { widget(id: $widget) { count } }',
            'variables': {'widget': 'widget'},
        },
    }
    spec = parse_policy(https_policy(operations=[op]))
    req = spec.parse_request({
        'operation': 'widget.count', 'arguments': {'widget': 7},
    })
    effect = must(spec.final(req, None))
    assert not effect.is_write and effect.graphql
    assert effect.body is not None
    assert json.loads(dict(effect.body)['variables']) == {'widget': 7}
    assert spec == parse_policy(spec.to_dict())


def test_real_tls_graphql_query_binds_only_policy_variables(tmp_path):
    spec = _threads_spec()
    req = _threads_request(spec)
    with TLSService(tmp_path) as service:
        p = service.egress()
        dest = Egress(service.host, p['port'], p['address'], p['ca_file'])
        executor = HTTPSExecutor(replace(dest, headers=spec.egress.headers))
        from aivm_secrets.kernel.machine import AuthorizedEffect
        def admit(effect, *, final):
            return AuthorizedEffect(
                0, 'a'*32, req.digest, final, False, effect,
            )
        get = '/repos/taucetiproject/tauceti/pulls/13861'
        service.routes[('GET', get)] = metadata()
        service.routes[('POST', '/graphql')] = {
            'data': {'repository': {'pullRequest': {
                'reviewThreads': {'nodes': [], 'pageInfo': {
                    'hasNextPage': False, 'endCursor': None,
                }},
            }}},
        }
        facts = executor.execute(
            admit(must(spec.preflight(req)), final=False), SERVICE_TOKEN
        )
        effect = must(spec.final(req, facts))
        result = executor.execute(admit(effect, final=True), SERVICE_TOKEN)
        assert result['data']['repository']['pullRequest']['reviewThreads']['nodes'] == []
        assert [r['method'] for r in service.requests] == ['GET', 'POST']
        posted = json.loads(service.requests[-1]['body'])
        assert set(posted) == {'query', 'operationName', 'variables'}
        assert posted['operationName'] == 'AivmReviewThreads'
        assert posted['variables'] == {
            'owner': 'taucetiproject', 'name': 'tauceti', 'number': 13861,
        }
        assert 'mutation' not in posted['query']
        assert all(r['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
                   for r in service.requests)
