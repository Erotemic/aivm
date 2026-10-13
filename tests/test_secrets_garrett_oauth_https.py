"""Real local TLS token exchange with pinned hostname; no external provider.

Only name resolution is faked: ``socket.create_connection`` sends the
provider's ``login.example.org:443`` to a loopback port. TLS, HTTP, the
token-endpoint client and the vault are the production code.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.client
import json
import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from aivm_secrets.errors import MESSAGES, SecretsError
from aivm_secrets.host.audit import verify
from aivm_secrets.identity import oauth_transport
from aivm_secrets.identity.garrett.oauth_contract import assess_token_response
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_transport import PinnedOAuthHTTP
from aivm_secrets.identity.oauth_vault import OAuthVault
from tests.secrets_helpers import TLSService, write_private

PROVIDER_HOST = 'login.example.org'
REAL_CONNECT = socket.create_connection


def _server_material(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic OAuth CA')])
    root = (x509.CertificateBuilder().subject_name(root_name)
        .issuer_name(root_name).public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                       critical=False)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                      key_encipherment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                      encipher_only=False, decipher_only=False), critical=True)
        .sign(root_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'login.example.org')]))
        .issuer_name(root_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       root_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                      key_encipherment=True, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('login.example.org')]),
                       critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .sign(root_key, hashes.SHA256()))
    ca = tmp_path / 'ca.pem'
    cert = tmp_path / 'leaf.pem'
    private = tmp_path / 'leaf.key'
    # Read as a trusted host file: its mode must not depend on the umask.
    write_private(ca, root.public_bytes(serialization.Encoding.PEM), 0o644)
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return ca, cert, private


def _profile():
    return OAuthProvider.parse({
        'schema': 1, 'name': 'synthetic', 'client_id': 'id',
        'authorization_url': 'https://login.example.org/authorize',
        'token_url': 'https://login.example.org/token',
        'resource_host': 'api.example.org', 'callback_port': 18765,
        'scopes': ['read'],
    })


@pytest.mark.parametrize('status', [200, 302])
def test_actual_tls_token_exchange_verifies_name_and_refuses_redirect(
        tmp_path, monkeypatch, status):
    ca, cert, private = _server_material(tmp_path)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(str(cert), str(private))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(4)
    address = listener.getsockname()
    observed = []
    errors = []
    body = b'{"access_token":"SYNTHETIC","token_type":"Bearer","expires_in":3600}'

    def serve():
        try:
            raw, _ = listener.accept()
            with raw, server_ctx.wrap_socket(raw, server_side=True) as connection:
                connection.settimeout(3)
                buffer = b''
                while b'\r\n\r\n' not in buffer or len(buffer) < (
                    buffer.find(b'\r\n\r\n') + 4 + int(next((row.split(b':',1)[1].strip()
                       for row in buffer.split(b'\r\n') if row.lower().startswith(b'content-length:')),
                       b'0'))):
                    data = connection.recv(4096)
                    if not data:
                        break
                    buffer += data
                    if len(buffer) > 16000:
                        raise AssertionError('oversized synthetic request')
                observed.append(buffer)
                if status == 302:
                    payload = (b'HTTP/1.1 302 Found\r\nLocation: https://other.example.org/token\r\n'
                               b'Content-Length: 0\r\nConnection: close\r\n\r\n')
                else:
                    payload = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                               b'Content-Length: ' + str(len(body)).encode() +
                               b'\r\nConnection: close\r\n\r\n' + body)
                connection.sendall(payload)
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    worker = threading.Thread(target=serve)
    worker.start()
    original_connect = socket.create_connection

    def local_connect(destination, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, **kwargs):
        # Only DNS/routing is mocked: the production HTTPS client still
        # negotiates TLS and authenticates login.example.org through SNI.
        assert destination[0] == 'login.example.org' and destination[1] == 443
        return original_connect(address, timeout=timeout, source_address=source_address)

    monkeypatch.setattr(socket, 'create_connection', local_connect)
    monkeypatch.setenv('SSLKEYLOGFILE', str(tmp_path / 'leaked.keys'))
    try:
        transport = PinnedOAuthHTTP(ca_file=str(ca))
        if status == 302:
            with pytest.raises(SecretsError):
                transport.post(_profile(), {'grant_type':'authorization_code', 'code':'x'})
        else:
            result = transport.post(_profile(),
                {'grant_type':'authorization_code', 'code':'x'})
            assert result['access_token'] == 'SYNTHETIC'
    finally:
        worker.join(timeout=5)
    assert not worker.is_alive(), errors
    assert not errors, errors
    assert len(observed) == 1
    assert observed[0].startswith(b'POST /token HTTP/1.1')
    assert b'Host: login.example.org' in observed[0]
    assert b'grant_type=authorization_code' in observed[0]
    assert not (tmp_path / 'leaked.keys').exists()


def route(monkeypatch: pytest.MonkeyPatch, port: int) -> list[tuple[str, int]]:
    """Resolve the provider to a loopback port; record every connection."""
    original = REAL_CONNECT
    dialed: list[tuple[str, int]] = []

    def connect(address: tuple[str, int], timeout: Any = None,
                source_address: Any = None, **kwargs: Any) -> socket.socket:
        assert address == (PROVIDER_HOST, 443)
        dialed.append(address)
        return original(('127.0.0.1', port), timeout, source_address)

    monkeypatch.setattr(socket, 'create_connection', connect)
    return dialed


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def answer(status: int, body: bytes, kind: str = 'application/json') -> Any:
    def respond(seen: dict) -> tuple[int, dict[str, str], bytes]:
        return status, {'Content-Type': kind}, body
    return respond


def refresh_form() -> dict[str, str]:
    return {'grant_type': 'refresh_token', 'refresh_token': 'R1',
            'client_id': 'id'}


def hashed_store(ca: Path, directory: Path) -> Path:
    """A CA directory as OpenSSL looks one up: ``<subject-hash>.0``.

    A directory holding a plain ``ca.pem`` is never consulted, so naming one
    in ``SSL_CERT_DIR`` would prove nothing.
    """
    openssl = shutil.which('openssl')
    if openssl is None:
        pytest.skip('naming a hashed CA directory entry needs the openssl CLI')
    digest = subprocess.run(
        [openssl, 'x509', '-hash', '-noout', '-in', str(ca)],
        capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    directory.mkdir()
    (directory / f'{digest}.0').write_bytes(ca.read_bytes())
    return directory


def trusts(store: Path, port: int) -> bool:
    """Whether a client trusting ``store`` alone accepts the server on ``port``."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if store.is_dir():
        context.load_verify_locations(capath=str(store))
    else:
        context.load_verify_locations(cafile=str(store))
    with REAL_CONNECT(('127.0.0.1', port), timeout=5) as raw:
        try:
            with context.wrap_socket(raw, server_hostname=PROVIDER_HOST):
                return True
        except ssl.SSLCertVerificationError:
            return False


@pytest.mark.parametrize('variable', ['SSL_CERT_FILE', 'SSL_CERT_DIR'])
def test_ambient_trust_store_variables_cannot_choose_the_token_endpoint(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    # The operator's shell names a hostile CA -- the one that signed this
    # impostor of login.example.org -- as its whole trust store.
    with TLSService(tmp_path, host=PROVIDER_HOST) as impostor:
        impostor.routes[('POST', '/token')] = {
            'access_token': 'IMPOSTOR', 'token_type': 'Bearer'}
        ca = impostor.files['ca']
        store = (ca if variable == 'SSL_CERT_FILE'
                 else hashed_store(ca, tmp_path / 'hashed'))
        # Control: a client that honoured this store would trust the impostor.
        assert trusts(store, impostor.port)
        for name in ('SSL_CERT_FILE', 'SSL_CERT_DIR'):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv(variable, str(store))
        dialed = route(monkeypatch, impostor.port)
        with pytest.raises(SecretsError) as refused:
            PinnedOAuthHTTP().post(_profile(), refresh_form())
        # The handshake failed, so not one byte of the request was sent.
        assert (refused.value.code, refused.value.detail) == (
            'credential_source', 'refresh_not_sent')
        assert dialed and impostor.seen() == []
        # Control: the same server is reachable when its CA is pinned.
        pinned = PinnedOAuthHTTP(ca_file=str(ca))
        assert pinned.post(_profile(), refresh_form())['access_token'] == 'IMPOSTOR'
        assert len(impostor.seen('POST')) == 1


@pytest.mark.parametrize('respond, reason, status', [
    pytest.param(answer(400, b'{"error":"invalid_grant","error_description":'
                             b'"PROVIDER TEXT"}'),
                 'refresh_rejected', 400, id='400-invalid-grant'),
    pytest.param(answer(400, b'{"error":"invalid_request"}'),
                 'refresh_in_doubt', 400, id='400-other-error'),
    pytest.param(answer(400, b'invalid_grant', 'text/plain'),
                 'refresh_in_doubt', 400, id='400-not-json'),
    pytest.param(answer(401, b'{"error":"invalid_grant"}'),
                 'refresh_in_doubt', 401, id='401-invalid-grant'),
    pytest.param(answer(503, b'{"error":"temporarily_unavailable"}'),
                 'refresh_in_doubt', 503, id='503'),
    pytest.param(answer(200, b'{"error":"invalid_grant"}'),
                 'refresh_in_doubt', 200, id='200-with-error'),
])
def test_a_failed_refresh_says_what_is_known_about_the_request(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, respond: Any,
        reason: str, status: int) -> None:
    with TLSService(tmp_path, host=PROVIDER_HOST) as endpoint:
        endpoint.routes[('POST', '/token')] = respond
        route(monkeypatch, endpoint.port)
        transport = PinnedOAuthHTTP(ca_file=str(endpoint.files['ca']))
        with pytest.raises(SecretsError) as failed:
            transport.post(_profile(), refresh_form())
    assert (failed.value.code, failed.value.detail, failed.value.status) == (
        'credential_source', reason, status)
    assert 'PROVIDER' not in failed.value.for_operator()
    assert len(endpoint.seen('POST')) == 1


def test_a_refused_connection_is_not_sent(
        monkeypatch: pytest.MonkeyPatch) -> None:
    route(monkeypatch, closed_port())
    with pytest.raises(SecretsError) as failed:
        PinnedOAuthHTTP().post(_profile(), {'grant_type': 'authorization_code',
                                            'code': 'x'})
    assert failed.value.detail == 'exchange_not_sent'


def _vault(tmp_path: Path) -> tuple[OAuthVault, OAuthProvider]:
    profile = _profile()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(profile, 'vm-1', assess_token_response({
        'access_token': 'FIRST', 'refresh_token': 'REFRESH1',
        'token_type': 'Bearer', 'expires_in': 120,
    }, now=100, allowed_scopes=['read']))
    return vault, profile


def vault_events(vault: OAuthVault) -> Counter:
    """The vault's audit events; every record's code is a closed error code."""
    events: Counter = Counter()
    for path in (vault.root / 'audit').glob('*.jsonl'):
        verify(path)
        for line in path.read_text().splitlines():
            record = json.loads(line)
            assert record['code'] in ('', *MESSAGES), record
            events[record['event']] += 1
    return events


def test_an_unreachable_provider_leaves_the_vault_usable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault, profile = _vault(tmp_path)
    route(monkeypatch, closed_port())
    with pytest.raises(SecretsError) as failed:
        vault.session_snapshot(profile, 'vm-1', resource_host=profile.resource_host,
                               now=180)
    assert failed.value.detail == 'refresh_not_sent'
    assert vault.status(profile, 'vm-1')['refresh_state'] == 'none'
    events = vault_events(vault)
    assert (events['oauth_refresh_intent'], events['oauth_refresh_not_sent'],
            events['oauth_refresh_in_doubt']) == (1, 1, 0)
    # Nothing was spent, so the next session may simply try again.
    with TLSService(tmp_path, host=PROVIDER_HOST) as endpoint:
        endpoint.routes[('POST', '/token')] = {
            'access_token': 'SECOND', 'refresh_token': 'REFRESH2',
            'token_type': 'Bearer', 'expires_in': 120}
        route(monkeypatch, endpoint.port)
        lease = vault.session_snapshot(
            profile, 'vm-1', resource_host=profile.resource_host, now=180,
            transport=PinnedOAuthHTTP(ca_file=str(endpoint.files['ca'])))
    assert lease.credential == 'SECOND' and lease.generation == 1
    assert 'refresh_token=REFRESH1' in endpoint.seen('POST')[0]['body']


@pytest.mark.parametrize('silence', ['reply-lost', 'reply-late'])
def test_a_refresh_sent_without_a_usable_reply_stays_in_doubt(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, silence: str) -> None:
    # The provider reads the whole refresh request -- and may rotate the
    # token -- but its answer never arrives: the connection drops, or the
    # reply comes after the client gave up. Only a failure before the
    # handshake completed may count as "not sent".
    release = threading.Event()

    def lost(seen: dict) -> tuple[int, dict[str, str], bytes]:
        raise ConnectionAbortedError('the reply is lost after the request')

    def late(seen: dict) -> tuple[int, dict[str, str], bytes]:
        release.wait(10)
        return 200, {}, b'{}'

    # Shortened from 10 s so the late reply is quick to wait out.
    monkeypatch.setattr(oauth_transport, 'TOKEN_TIMEOUT', 0.5)
    vault, profile = _vault(tmp_path)
    try:
        with TLSService(tmp_path, host=PROVIDER_HOST) as endpoint:
            endpoint.routes[('POST', '/token')] = (
                lost if silence == 'reply-lost' else late)
            route(monkeypatch, endpoint.port)
            transport = PinnedOAuthHTTP(ca_file=str(endpoint.files['ca']))
            with pytest.raises(SecretsError) as failed:
                vault.session_snapshot(profile, 'vm-1',
                                       resource_host=profile.resource_host,
                                       now=180, transport=transport)
            assert (failed.value.code, failed.value.detail) == (
                'credential_source', 'refresh_in_doubt')
            assert vault.status(profile, 'vm-1')['refresh_state'] == 'in_doubt'
            # The next session start does not present REFRESH1 again.
            with pytest.raises(SecretsError) as refused:
                vault.session_snapshot(profile, 'vm-1',
                                       resource_host=profile.resource_host,
                                       now=181, transport=transport)
            assert refused.value.detail == 'refresh_in_doubt'
            posts = endpoint.seen('POST')
            assert len(posts) == 1 and 'refresh_token=REFRESH1' in posts[0]['body']
    finally:
        release.set()
    assert vault_events(vault)['oauth_refresh_in_doubt'] == 1


def test_an_unreachable_retry_keeps_the_record_in_doubt(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault, profile = _vault(tmp_path)
    with TLSService(tmp_path, host=PROVIDER_HOST) as endpoint:
        endpoint.routes[('POST', '/token')] = answer(502, b'{}')
        route(monkeypatch, endpoint.port)
        with pytest.raises(SecretsError):
            vault.session_snapshot(
                profile, 'vm-1', resource_host=profile.resource_host, now=180,
                transport=PinnedOAuthHTTP(ca_file=str(endpoint.files['ca'])))
    assert vault.status(profile, 'vm-1')['refresh_state'] == 'in_doubt'
    route(monkeypatch, closed_port())
    with pytest.raises(SecretsError) as failed:
        vault.refresh(profile, 'vm-1', now=190, retry_in_doubt=True)
    # The retry never left the host; the earlier request is still unknown.
    assert failed.value.detail == 'refresh_not_sent'
    assert vault.status(profile, 'vm-1')['refresh_state'] == 'in_doubt'


def test_a_rejected_grant_requires_reauthorization(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault, profile = _vault(tmp_path)
    with TLSService(tmp_path, host=PROVIDER_HOST) as endpoint:
        endpoint.routes[('POST', '/token')] = answer(
            400, b'{"error":"invalid_grant"}')
        route(monkeypatch, endpoint.port)
        transport = PinnedOAuthHTTP(ca_file=str(endpoint.files['ca']))
        with pytest.raises(SecretsError) as failed:
            vault.session_snapshot(profile, 'vm-1',
                                   resource_host=profile.resource_host,
                                   now=180, transport=transport)
        assert failed.value.detail == 'refresh_rejected'
        status = vault.status(profile, 'vm-1')
        assert (status['refresh_state'], status['active']) == (
            'reauth_required', True)
        events = vault_events(vault)
        assert (events['oauth_refresh_rejected'],
                events['oauth_refresh_in_doubt']) == (1, 0)
        for retry in (False, True):
            with pytest.raises(SecretsError) as refused:
                vault.refresh(profile, 'vm-1', now=181, transport=transport,
                              retry_in_doubt=retry)
            assert refused.value.detail == 'reauth_required'
        with pytest.raises(SecretsError) as refused:
            vault.session_snapshot(profile, 'vm-1',
                                   resource_host=profile.resource_host, now=101)
        assert refused.value.detail == 'reauth_required'
        assert len(endpoint.seen('POST')) == 1
    vault.enroll(profile, 'vm-1', assess_token_response({
        'access_token': 'RELOGIN', 'token_type': 'Bearer', 'expires_in': 600,
        'refresh_token': 'REFRESH9'}, now=int(time.time()),
        allowed_scopes=['read']), replace=True)
    status = vault.status(profile, 'vm-1')
    assert (status['refresh_state'], status['epoch']) == ('none', 1)
