"""Real TLS 1.3 peer-certificate binding, with a real restricted Broker.

A fresh test CA signs server and two distinct client certificates; every
connection uses an actual ssl.SSLSocket, not user-supplied identity headers.
"""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import threading

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.model import IdentityClaims, IdentityExpectation
from aivm_secrets.identity.mtls import IdentityTLSBridge, server_context
from aivm_secrets.identity.token import (
    IdentityTokenIssuer, IdentityTokenVerifier, certificate_thumbprint,
)
from aivm_secrets.kernel import codec
from tests.secrets_helpers import Harness, REPO, TOKEN


def certificates(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    def name(text):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])
    def identity(builder, key, ca_public_key):
        return (builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key), False))
    ca = (x509.CertificateBuilder().subject_name(name('P4a test CA'))
          .issuer_name(name('P4a test CA')).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
             key_encipherment=False, data_encipherment=False, key_agreement=False,
             key_cert_sign=True, crl_sign=True, encipher_only=False,
             decipher_only=False), True).sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / 'ca.pem'
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {'ca': ca_path}
    for role in ('server', 'client1', 'client2'):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(name(role))
            .issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if role == 'server'
                else ExtendedKeyUsageOID.CLIENT_AUTH]), False))
        if role == 'server':
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
        cert = identity(builder, key, ca_key.public_key()).sign(ca_key, hashes.SHA256())
        cert_path = tmp_path / f'{role}.pem'
        key_path = tmp_path / f'{role}.key'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
             serialization.PrivateFormat.PKCS8,
             serialization.NoEncryption()))
        key_path.chmod(0o600)
        result[role] = (cert_path, key_path, cert.public_bytes(serialization.Encoding.DER))
    return result


def exchange(bridge, certs, frame, *, client='client1', no_cert=False):
    left, right = socket.socketpair()
    observed = []
    def host():
        try:
            bridge.serve_accepted(left)
        except (ssl.SSLError, OSError) as exc:
            observed.append(type(exc).__name__)
    thread = threading.Thread(target=host)
    thread.start()
    try:
        context = ssl.create_default_context(cafile=str(certs['ca']))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if not no_cert:
            context.load_cert_chain(str(certs[client][0]), str(certs[client][1]))
        with context.wrap_socket(right, server_hostname='localhost') as sock:
            sock.settimeout(5)
            sock.sendall(codec.dumps(frame) + b'\n')
            reply = b''
            while not reply.endswith(b'\n'):
                part = sock.recv(65536)
                if not part:
                    break
                reply += part
            return codec.loads(reply)
    finally:
        thread.join(timeout=6)
        assert not thread.is_alive(), 'test bridge did not terminate'


def setup(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import secrets
    certs = certificates(tmp_path)
    harness = Harness(tmp_path)
    public = IdentityClaims.parse({
        'iss': 'aivm.test', 'aud': 'aivm-secrets.remote', 'sub': 'vm-test',
        'jti': 'f' * 32, 'iat': 990, 'exp': 1050, 'epoch': 0,
        'cnf': {'x5t#S256': certificate_thumbprint(certs['client1'][2])},
    })
    expected = IdentityExpectation('aivm.test', 'aivm-secrets.remote', 'vm-test', 0)
    signer = Ed25519PrivateKey.generate()
    key = secrets.token_bytes(32)
    issuer = IdentityTokenIssuer(signer, key, key_id='test-1')
    verifier = IdentityTokenVerifier(signer.public_key(), key,
                                     key_id='test-1', expected=expected)
    tls = server_context(certificate=certs['server'][0],
                         private_key=certs['server'][1], client_ca=certs['ca'])
    bridge = IdentityTLSBridge(context=tls, verifier=verifier,
                               broker=harness.broker,
                               wall_clock=lambda: harness.clock.wall)
    token = issuer.issue(public, harness.capability)
    frame = {'version': 1, 'capability': token, 'request': {
        'operation': 'pr.view', 'arguments': {'repository': REPO, 'pr': 13861},
    }}
    return harness, certs, bridge, token, frame


def test_real_mtls_binding_and_actual_broker_authorization(tmp_path):
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        reply = exchange(bridge, certs, frame)
        assert reply['ok'] and reply['result']['number'] == 13861
        assert len(harness.executor.calls) == 1
        assert harness.executor.calls[0][1] == TOKEN
        assert TOKEN not in json.dumps(reply)
        assert harness.capability not in token
        # A malformed operation reaches the ordinary broker, not a new power.
        bad = {**frame, 'request': {'operation': 'pr.merge', 'arguments': {}}}
        rejected = exchange(bridge, certs, bad)
        assert rejected['ok'] is False
        assert rejected['error']['code'] == 'denied'
        assert len(harness.executor.calls) == 1
    finally:
        harness.broker.close()


def test_wrong_cert_is_denied_before_the_broker(tmp_path):
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        result = exchange(bridge, certs, frame, client='client2')
        assert result['ok'] is False
        assert result['error']['code'] == 'invalid_capability'
        assert not harness.executor.calls
        assert harness.events() == ['session_open']
    finally:
        harness.broker.close()


def test_raw_capability_and_delegation_refused(tmp_path):
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        raw_cap = dict(frame)
        raw_cap['capability'] = harness.capability
        denied = exchange(bridge, certs, raw_cap)
        assert denied['error']['code'] == 'invalid_capability'
        delegate = {'version': 1, 'capability': token, 'delegate': {}}
        denied = exchange(bridge, certs, delegate)
        assert denied['error']['code'] == 'denied'
        assert harness.events() == ['session_open']
    finally:
        harness.broker.close()


def test_server_rejects_context_without_required_client_cert(tmp_path):
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        bad_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        bad_ctx.verify_mode = ssl.CERT_NONE
        with pytest.raises(SecretsError):
            IdentityTLSBridge(context=bad_ctx, verifier=bridge._verifier,
                              broker=harness.broker)
        assert bridge._context.keylog_filename is None
        assert bridge._context.minimum_version == ssl.TLSVersion.TLSv1_3
    finally:
        harness.broker.close()


def test_no_client_certificate_fails_during_tls_handshake(tmp_path):
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        with pytest.raises((ssl.SSLError, OSError)):
            exchange(bridge, certs, frame, no_cert=True)
        assert not harness.executor.calls
    finally:
        harness.broker.close()


def test_expired_or_revoked_epoch_does_not_reach_broker(tmp_path):
    from dataclasses import replace
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        # Issuer-local expiry is checked against an explicit host clock.
        harness.clock.wall = 1050
        expired = exchange(bridge, certs, frame)
        assert expired['error']['code'] == 'invalid_capability'
        harness.clock.wall = 1000
        bridge._verifier.expected = replace(bridge._verifier.expected, epoch=1)
        revoked = exchange(bridge, certs, frame)
        assert revoked['error']['code'] == 'invalid_capability'
        assert harness.events() == ['session_open']
        assert not harness.executor.calls
    finally:
        harness.broker.close()


def test_spoofed_identity_field_cannot_replace_verified_peer(tmp_path):
    harness, certs, bridge, token, frame = setup(tmp_path)
    try:
        spoof = dict(frame)
        spoof['peer_thumbprint'] = certificate_thumbprint(certs['client1'][2])
        denied = exchange(bridge, certs, spoof, client='client2')
        assert denied['ok'] is False
        assert denied['error']['code'] == 'invalid_request'
        assert not harness.executor.calls
        # The other receiver remains protected by the original AEAD envelope.
        assert harness.broker.handle(codec.dumps(frame))['error']['code'] == 'invalid_capability'
        assert not harness.executor.calls
    finally:
        harness.broker.close()
