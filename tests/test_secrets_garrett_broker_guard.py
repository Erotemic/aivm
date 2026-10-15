"""An OAuth revocation controls every authorized effect in the live broker."""
import threading
import time

import pytest

from aivm_secrets.identity.garrett.oauth_contract import assess_token_response
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_vault import OAuthVault
from tests.secrets_helpers import Harness


def profile():
    return OAuthProvider.parse({
        'schema': 1, 'name': 'synthetic', 'client_id': 'id',
        'authorization_url': 'https://login.example.org/authorize',
        'token_url': 'https://login.example.org/token',
        'resource_host': 'api.example.org', 'callback_port': 18765,
        'scopes': ['read'],
    })


def setup(tmp_path):
    p = profile()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    grant = assess_token_response({
        'access_token': 'SYNTHETIC_HOST_ONLY_CREDENTIAL',
        'token_type': 'Bearer', 'expires_in': 3600,
        'scope': 'read', 'refresh_token': 'ROTATING_REFRESH_TOKEN',
    }, now=int(time.time()), allowed_scopes=list(p.scopes))
    vault.enroll(p, 'vm-a', grant)
    snapshot = vault.session_snapshot(p, 'vm-a', resource_host=p.resource_host)
    instance = Harness(tmp_path / 'harness')
    instance.broker._credential_guard = lambda: vault.active_lease(p, 'vm-a', snapshot)
    return vault, p, instance


def test_revocation_stops_the_existing_authorized_broker(tmp_path):
    vault, p, h = setup(tmp_path)
    try:
        assert h.call()['ok'] is True
        prior = len(h.executor.calls)
        vault.revoke(p, 'vm-a')
        reply = h.call()
        assert reply['ok'] is False and reply['error']['code'] == 'revoked'
        assert len(h.executor.calls) == prior
    finally:
        h.broker.close()


def test_refresh_invalidates_previous_session(tmp_path):
    vault, p, h = setup(tmp_path)
    from tests.test_secrets_garrett_oauth import FakeOAuth, reply
    try:
        assert h.call()['ok']
        # This refresh replaces the access token even if the prior one is
        # nominally still valid; the old broker must not execute again.
        vault.credential_for_session(p, 'vm-a', resource_host=p.resource_host,
            force_refresh=True, transport=FakeOAuth([reply('NEW_ACCESS','NEW_REFRESH')]))
        assert h.call()['error']['code'] == 'revoked'
    finally:
        h.broker.close()


def test_completed_revocation_linearizes_after_in_flight_request(tmp_path):
    vault, p, h = setup(tmp_path)
    started = threading.Event()
    finish = threading.Event()
    revoked = threading.Event()
    original = h.executor.execute
    def execute(*args):
        started.set()
        assert finish.wait(4)
        return original(*args)
    h.executor.execute = execute
    replies = []
    worker = threading.Thread(target=lambda: replies.append(h.call()))
    reaper = threading.Thread(target=lambda: (vault.revoke(p,'vm-a'),revoked.set()))
    try:
        worker.start()
        assert started.wait(4)
        reaper.start()
        assert not revoked.wait(0.08), 'revocation returned during in-flight effect'
        finish.set()
        worker.join(timeout=5)
        reaper.join(timeout=5)
        assert not worker.is_alive() and not reaper.is_alive()
        assert replies[0]['ok'] is True
        assert revoked.is_set()
        calls = len(h.executor.calls)
        assert h.call()['error']['code'] == 'revoked'
        assert len(h.executor.calls) == calls
    finally:
        finish.set()
        worker.join(timeout=5)
        reaper.join(timeout=5) if reaper.ident is not None else None
        h.broker.close()
