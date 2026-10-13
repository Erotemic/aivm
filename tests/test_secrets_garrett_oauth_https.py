"""Real local TLS token exchange with pinned hostname; no external provider."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.client
import socket
import ssl
import threading

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_transport import PinnedOAuthHTTP


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
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
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
