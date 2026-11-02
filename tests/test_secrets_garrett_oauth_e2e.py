"""Synthetic OAuth -> encrypted vault -> authorized broker -> real mTLS.

No real provider, token, VM or GitHub permission. The protocol uses the same
AES-GCM, Ed25519, TLS 1.3, kernel and host-broker implementations as runtime.
"""
import json
import threading
import time
from pathlib import Path

from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.certificates import create_csr, inspect_csr
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_transport import (
    new_pending, exchange_code,
)
from aivm_secrets.identity.oauth_vault import OAuthVault
from aivm_secrets.identity.service import UnixIdentityService
from aivm_secrets.identity.client import bound_call
from aivm_secrets.host.server import LocalServer
from tests.secrets_helpers import Harness, REPO


class SyntheticTokenService:
    def post(self, profile, fields, **kwargs):
        assert fields['grant_type'] == 'authorization_code'
        assert fields['code'] == 'synthetic-code'
        assert fields['code_verifier']
        return {'access_token': 'SYNTHETIC_PROVIDER_ACCESS_TOKEN',
                'refresh_token': 'SYNTHETIC_PROVIDER_REFRESH_TOKEN',
                'token_type': 'bearer', 'expires_in': 3600,
                'scope': 'read'}


def test_full_local_garrett_chain_and_revocation(tmp_path):
    profile = OAuthProvider.parse({
        'schema':1, 'name':'synthetic', 'client_id':'fake',
        'authorization_url':'https://login.example.org/authorize',
        'token_url':'https://login.example.org/token',
        'resource_host':'api.example.org', 'callback_port':18765,
        'scopes':['read'],
    })
    vault = OAuthVault.initialize(tmp_path/'oauth')
    now = int(time.time())
    pending = new_pending(profile, now=now)
    acquired = exchange_code(profile, pending,
        {'code':'synthetic-code', 'state':pending.state},
        now=now, transport=SyntheticTokenService())
    vault.enroll(profile, 'vm-test', acquired)
    snapshot = vault.session_snapshot(profile, 'vm-test',
                                      resource_host=profile.resource_host)
    assert snapshot.credential == 'SYNTHETIC_PROVIDER_ACCESS_TOKEN'
    h = Harness(tmp_path/'harness', token=snapshot.credential)
    h.broker._credential_guard = lambda: vault.active_lease(profile, 'vm-test', snapshot)

    authority = IdentityAuthority.initialize(tmp_path/'identity', issuer='aivm.local',
                                             audience='aivm-secrets.identity')
    key, csr = tmp_path/'guest.key', tmp_path/'guest.csr'
    create_csr(private_key=key, request_file=csr)
    enrollment = authority.enroll(subject='vm-test', csr=csr.read_bytes(),
        approve_fingerprint=inspect_csr(csr.read_bytes()))
    jwt_file = tmp_path/'bound.jwt'
    authority.issue(subject='vm-test', broker_capability=h.capability,
                    output=jwt_file)
    assert snapshot.credential not in jwt_file.read_text()
    assert h.capability not in jwt_file.read_text()
    try:
        with LocalServer(h.broker, tmp_path/'broker') as broker:
            with UnixIdentityService(authority=authority,
                    broker_socket=broker.socket_path,
                    listen=tmp_path/'bridge'/'identity.sock',
                    max_connections=2, idle_seconds=12) as service:
                thread=threading.Thread(target=service.serve)
                thread.start()
                def call():
                    return bound_call(socket_path=service.listen,
                        ca=authority.tls_paths()[2],
                        certificate=Path(enrollment['certificate']),
                        private_key=key, jwt_file=jwt_file,
                        request={'operation':'pr.view','arguments':{
                            'repository':REPO,'pr':13861}})
                try:
                    first = call()
                    assert first['ok'] and first['result']['number'] == 13861
                    assert h.executor.calls[0][1] == snapshot.credential
                    # Local credential revocation prevents another provider
                    # effect even while mTLS certificate+JWT remain valid.
                    vault.revoke(profile, 'vm-test')
                    second = call()
                    assert second['ok'] is False
                    assert second['error']['code'] == 'revoked'
                    assert len(h.executor.calls) == 1
                finally:
                    thread.join(timeout=10)
                    assert not thread.is_alive()
    finally:
        h.broker.close()
