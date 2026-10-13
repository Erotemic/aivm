"""Provider-neutral Garrett OAuth issuance, refresh and protected storage."""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_transport import (
    HostCallback, PinnedOAuthHTTP, authorization_url, exchange_code,
    new_pending, refresh_token,
)
from aivm_secrets.identity.oauth_vault import OAuthVault
from aivm_secrets.identity.garrett.oauth_contract import (
    PendingAuthorization, accept_callback, assess_token_response, require_active,
)


def provider(**overrides):
    raw = {
        'schema': 1, 'name': 'synthetic', 'client_id': 'client-id',
        'authorization_url': 'https://login.example.org/authorize',
        'token_url': 'https://login.example.org/token',
        'resource_host': 'api.example.org', 'callback_port': 18765,
        'scopes': ['read'],
    }
    raw.update(overrides)
    return OAuthProvider.parse(raw)


def reply(access='ACCESS_SECRET', refresh='REFRESH_SECRET', ttl=7200):
    return {'access_token': access, 'refresh_token': refresh,
            'token_type': 'Bearer', 'expires_in': ttl, 'scope': 'read'}


class FakeOAuth:
    def __init__(self, responses):
        self.responses = list(responses)
        self.seen = []

    def post(self, profile, form, **kwargs):
        self.seen.append(dict(form))
        return self.responses.pop(0)


def test_provider_rejects_hostile_urls_and_insecure_refresh_modes():
    for url in ('http://login.example.org/token', 'https://a@b.example.org/x',
                'https://login.example.org:8443/x',
                'https://login.example.org/x?token=1',
                'https://127.0.0.1/t', 'https://localhost/t',
                'https://login.example.org/x#z'):
        with pytest.raises(SecretsError):
            provider(token_url=url)
    with pytest.raises(SecretsError):
        provider(refresh_rotation=False)
    assert provider(refresh_rotation=False,
                    client_secret_file='/var/tmp/test-secret').refresh_rotation is False


def test_pkce_state_and_callback_contract():
    p = provider()
    pending = PendingAuthorization.create('STATE', 'VERIFIER', p.redirect_uri,
                                          now=200, ttl=100)
    url = authorization_url(p, pending)
    query = parse_qs(urlsplit(url).query)
    assert query['code_challenge'] == [base64.urlsafe_b64encode(
        hashlib.sha256(b'VERIFIER').digest()).rstrip(b'=').decode()]
    assert query['code_challenge_method'] == ['S256']
    assert query['response_type'] == ['code']
    assert 'VERIFIER' not in url
    assert accept_callback(pending, {'code': 'CODE', 'state': 'STATE'}, now=200) == 'CODE'
    for params, now in (
        ({'code': 'CODE', 'state': 'BAD'}, 200),
        ({'code': 'CODE', 'state': 'STATE'}, 300),
        ({'code': 'CODE', 'state': 'STATE', 'extra': 'x'}, 200),
        ({'code': 'CODE', 'state': 'STATE', 'iss': 'https://bad.example'}, 200),
        ({'code': '', 'state': 'STATE'}, 200),
    ):
        with pytest.raises(SecretsError):
            accept_callback(pending, params, now=now)


def test_exchange_refresh_rotation_and_scope_attenuation():
    p = provider()
    pending = PendingAuthorization.create('STATE', 'VERIFIER', p.redirect_uri,
                                          now=100, ttl=100)
    transport = FakeOAuth([reply('ACCESS1', 'REFRESH1'),
                           reply('ACCESS2', 'REFRESH2')])
    first = exchange_code(p, pending, {'code': 'CODE', 'state': 'STATE'},
                          now=120, transport=transport)
    assert first.access_token == 'ACCESS1'
    assert first.generation == 0
    assert transport.seen[0]['code_verifier'] == 'VERIFIER'
    second = refresh_token(p, first, now=200, transport=transport)
    assert second.access_token == 'ACCESS2' and second.refresh_token == 'REFRESH2'
    assert second.generation == 1
    assert transport.seen[1]['refresh_token'] == 'REFRESH1'
    for data in (reply('X', 'REFRESH1'),
                 {**reply('X','REFRESH3'), 'scope': 'admin'},
                 {**reply('X','REFRESH3'), 'token_type': 'MAC'},
                 {**reply('X','REFRESH3'), 'expires_in': -1},
                 {**reply('X','REFRESH3'), 'expires_in': True}):
        with pytest.raises(SecretsError):
            assess_token_response(data, now=200, allowed_scopes=('read',),
                                  previous=first)


def test_vault_never_persists_plain_credentials_and_denies_rollback_to_other_profile(tmp_path):
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    token = assess_token_response(reply(), now=100, allowed_scopes=p.scopes)
    assert vault.enroll(p, 'vm-1', token)['epoch'] == 0
    stored = next((tmp_path / 'vault').glob('*.json'))
    content = stored.read_bytes()
    assert b'ACCESS_SECRET' not in content and b'REFRESH_SECRET' not in content
    assert vault.credential_for_session(p, 'vm-1', resource_host='api.example.org', now=101) == 'ACCESS_SECRET'
    with pytest.raises(SecretsError):
        vault.credential_for_session(p, 'vm-1', resource_host='evil.example.org', now=101)
    with pytest.raises(SecretsError):
        vault.enroll(p, 'vm-1', token)
    assert vault.revoke(p, 'vm-1')['epoch'] == 1
    with pytest.raises(SecretsError):
        vault.credential_for_session(p, 'vm-1', resource_host='api.example.org', now=101)
    assert vault.enroll(p, 'vm-1', token, replace=True)['epoch'] == 2
    # A policy/manifest update cannot silently inherit an old token.
    with pytest.raises(SecretsError):
        vault.status(replace(p, resource_host='other.example.org'), 'vm-1')
    content = stored.read_bytes()
    stored.write_bytes(content.replace(b'0', b'1', 1))
    with pytest.raises(SecretsError):
        vault.status(p, 'vm-1')


def test_expired_grant_is_refreshed_once_and_persisted_atomically(tmp_path):
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', assess_token_response(
        reply('FIRST', 'REFRESH1', 120), now=100, allowed_scopes=p.scopes))
    upstream = FakeOAuth([reply('SECOND', 'REFRESH2', 120)])
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=180, transport=upstream) == 'SECOND'
    assert len(upstream.seen) == 1
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=181, transport=upstream) == 'SECOND'
    assert len(upstream.seen) == 1
    assert vault.status(p, 'vm-1')['expires_at'] == 300
    with pytest.raises(SecretsError):
        vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                     now=200, force_refresh=True,
                                     transport=FakeOAuth([reply('FAIL', 'REFRESH2')]))
    # An ambiguous provider reply does not replace the durable grant.
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=181) == 'SECOND'


def test_no_expired_bearer_without_refresh(tmp_path):
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    first = assess_token_response({
        'access_token': 'TOKEN1', 'token_type': 'bearer',
        'expires_in': 50,
    }, now=100, allowed_scopes=p.scopes)
    vault.enroll(p, 'vm-1', first)
    with pytest.raises(SecretsError) as e:
        vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host, now=105)
    assert e.value.code == 'expired'


def test_host_callback_accepts_only_authorized_one_shot():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    p = provider(callback_port=port)
    pending = new_pending(p)
    import http.client
    with HostCallback(p, pending) as listener:
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        conn.request('GET', '/oauth/callback?code=x&state=wrong')
        # Call handle_request since listener does not start a background thread.
        listener._httpd.handle_request()
        response = conn.getresponse()
        assert response.status == 400
        response.read()
        conn.close()
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        conn.request('GET', f'/oauth/callback?code=good&state={pending.state}')
        listener._httpd.handle_request()
        response = conn.getresponse()
        assert response.status == 200
        response.read()
        conn.close()
        assert listener.parameters == {'code': 'good', 'state': pending.state}


def test_pinned_https_does_not_follow_redirect_or_accept_oversized(monkeypatch):
    class Response:
        status = 302
        def getheader(self, name, default=''):
            return default
        def read(self, count):
            return b''
    class Connection:
        def __init__(self, host, port, *, timeout, context):
            assert host == 'login.example.org' and port == 443
            assert context.keylog_filename is None
        def request(self, method, target, data, headers):
            assert method == 'POST' and target == '/token'
            assert 'Authorization' not in headers
        def getresponse(self):
            return Response()
        def close(self):
            pass
    import http.client
    monkeypatch.setattr(http.client, 'HTTPSConnection', Connection)
    with pytest.raises(SecretsError):
        PinnedOAuthHTTP().post(provider(), {'grant_type': 'authorization_code', 'code': 'a'})


def test_refresh_with_omitted_scope_preserves_attenuated_grant():
    # OAuth refresh can omit `scope`; this must *not* silently widen an
    # already-downscoped grant back to the provider's configured scope set.
    allowed = ('read', 'read:private')
    old = assess_token_response({
        'token_type': 'Bearer', 'access_token': 'OLD',
        'refresh_token': 'REFRESH1', 'expires_in': 500, 'scope': 'read',
    }, now=100, allowed_scopes=allowed)
    updated = assess_token_response({
        'token_type': 'Bearer', 'access_token': 'NEW',
        'refresh_token': 'REFRESH2', 'expires_in': 500,
    }, now=120, allowed_scopes=allowed, previous=old)
    assert updated.scopes == ('read',) and updated.generation == 1
