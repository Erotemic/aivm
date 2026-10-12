"""Real Unix socket + TLS 1.3 + pinned enrollment + original broker.

All secrets are synthetic. No VM, public listener, OAuth or real provider.
"""
from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.server import LocalServer, read_frame
from aivm_secrets.identity.enrollment import IdentityAuthority, create_csr
from aivm_secrets.identity.service import UnixIdentityService
from aivm_secrets.kernel import codec
from tests.secrets_helpers import Harness, REPO, TOKEN


def start(tmp_path):
    authority = IdentityAuthority.initialize(
        tmp_path / 'host', issuer='aivm.test', audience='aivm-secrets.identity')
    key = tmp_path / 'vm-key.pem'
    csr = tmp_path / 'vm.csr'
    fp = create_csr(private_key=key, request_file=csr)
    entry = authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                             approve_fingerprint=fp)
    harness = Harness(tmp_path)
    jwt = tmp_path / 'bound.jwt'
    authority.issue(subject='vm-alpha', broker_capability=harness.capability,
                    output=jwt)
    return authority, key, entry, jwt, harness


def call(path, authority, entry, key, jwt, request, *, use_key=True):
    ctx = ssl.create_default_context(cafile=str(authority.root / 'ca.pem'))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if use_key:
        ctx.load_cert_chain(entry['certificate'], str(key))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
        raw.settimeout(5)
        raw.connect(str(path))
        with ctx.wrap_socket(raw, server_hostname='localhost') as channel:
            frame = {'version': 1, 'capability': jwt.read_text(),
                     'request': request}
            channel.sendall(codec.dumps(frame) + b'\n')
            reply = read_frame(channel, limit=codec.MAX_FRAME, timeout=5)
            return codec.loads(reply)


def view_request():
    return {'operation': 'pr.view',
            'arguments': {'repository': REPO, 'pr': 13861}}


def test_authenticated_unix_bridge_uses_existing_broker_and_live_revocation(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    bridgepath = tmp_path / 'bridge' / 'session.sock'
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            with UnixIdentityService(
                authority=authority, broker_socket=broker.socket_path,
                listen=bridgepath, max_connections=3,
                idle_seconds=12) as service:
                runner = threading.Thread(target=service.serve)
                runner.start()
                reply = call(bridgepath, authority, entry, key, jwt, view_request())
                assert reply['ok'] and reply['result']['number'] == 13861
                assert len(harness.executor.calls) == 1
                assert harness.executor.calls[0][1] == TOKEN
                assert TOKEN not in json.dumps(reply)
                # Authorized client does not get any extra operation by TLS.
                other = call(bridgepath, authority, entry, key, jwt, {
                    'operation': 'pr.merge', 'arguments': {},
                })
                assert other['error']['code'] == 'denied'
                assert len(harness.executor.calls) == 1
                # A certificate that worked one request ago is revoked on
                # disk, without restarting TLS or the existing broker.
                authority.revoke('vm-alpha')
                rejected = call(bridgepath, authority, entry, key, jwt, view_request())
                assert rejected['error']['code'] == 'invalid_capability'
                assert len(harness.executor.calls) == 1
                runner.join(timeout=10)
                assert not runner.is_alive()
            assert not bridgepath.exists()
    finally:
        harness.broker.close()


def test_other_enrolled_certificate_cannot_use_original_identity_token(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    second_key, second_csr = tmp_path / 'other.key', tmp_path / 'other.csr'
    second_fp = create_csr(private_key=second_key, request_file=second_csr)
    other = authority.enroll(subject='vm-beta', csr=second_csr.read_bytes(),
                             approve_fingerprint=second_fp)
    listen = tmp_path / 'bridge' / 'session.sock'
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            with UnixIdentityService(
                authority=authority, broker_socket=broker.socket_path,
                listen=listen, max_connections=1) as service:
                thread = threading.Thread(target=service.serve)
                thread.start()
                result = call(listen, authority, other, second_key, jwt, view_request())
                assert result['error']['code'] == 'invalid_capability'
                assert not harness.executor.calls
                thread.join(timeout=8)
                assert not thread.is_alive()
    finally:
        harness.broker.close()


def test_bridge_is_opt_in_and_never_clobbers_existing_socket(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            listen = tmp_path / 'bridge' / 'existing.sock'
            listen.parent.mkdir(mode=0o700)
            listen.write_text('never overwrite')
            service = UnixIdentityService(authority=authority,
                                          broker_socket=broker.socket_path,
                                          listen=listen, max_connections=1)
            with pytest.raises(SecretsError):
                with service:
                    pass
            assert listen.read_text() == 'never overwrite'
            with pytest.raises(SecretsError):
                UnixIdentityService(authority=authority,
                                    broker_socket=broker.socket_path,
                                    listen=tmp_path / 'bridge' / 'other.sock',
                                    max_connections=100000)
    finally:
        harness.broker.close()


def test_client_without_certificate_fails_tls_handshake(tmp_path):
    authority, key, entry, jwt, harness = start(tmp_path)
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            listen = tmp_path / 'bridge' / 'auth.sock'
            with UnixIdentityService(authority=authority,
                                     broker_socket=broker.socket_path,
                                     listen=listen, max_connections=1) as service:
                thread = threading.Thread(target=service.serve)
                thread.start()
                with pytest.raises((ssl.SSLError, OSError, SecretsError)):
                    call(listen, authority, entry, key, jwt, view_request(),
                         use_key=False)
                thread.join(timeout=8)
                assert not thread.is_alive()
                assert not harness.executor.calls
    finally:
        harness.broker.close()
