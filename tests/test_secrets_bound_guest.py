"""Standard-library guest client uses mTLS in bound mode, never raw frames."""
from __future__ import annotations

import os
import threading

import pytest

from aivm_secrets import guest
from aivm_secrets.errors import SecretsError
from aivm_secrets.host.server import LocalServer
from aivm_secrets.identity.service import UnixIdentityService
from tests.test_secrets_identity_service import start, view_request


def test_guest_shim_real_mtls_and_denied_unauthorized_operation(tmp_path, monkeypatch):
    authority, key, entry, jwt, harness = start(tmp_path)
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_MODE', 'mtls-v1')
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_CA', str(authority.root / 'ca.pem'))
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_CERT', entry['certificate'])
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_KEY', str(key))
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            listen = tmp_path / 'bridge' / 'session.sock'
            with UnixIdentityService(authority=authority,
                                     broker_socket=broker.socket_path,
                                     listen=listen, max_connections=2) as bridge:
                thread = threading.Thread(target=bridge.serve)
                thread.start()
                answer = guest.exchange(str(listen), jwt.read_text(), view_request())
                assert answer['ok'] and answer['result']['number'] == 13861
                denied = guest.exchange(str(listen), jwt.read_text(),
                                        {'operation': 'pr.merge', 'arguments': {}})
                assert denied['ok'] is False
                assert len(harness.executor.calls) == 1
                thread.join(timeout=10)
                assert not thread.is_alive()
    finally:
        harness.broker.close()


def test_guest_rejects_unknown_identity_mode_without_plaintext_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv('AIVM_SECRETS_IDENTITY_MODE', 'mtls-v99')
    with pytest.raises((OSError, ValueError)):
        guest.exchange(str(tmp_path / 'no-socket'), 'aivs1.example',
                       {'operation': 'x', 'arguments': {}})
