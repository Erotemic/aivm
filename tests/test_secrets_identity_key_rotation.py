"""Host-side key rotation is an explicit, epoch-fenced replacement."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority, create_csr
from aivm_secrets.identity.token import certificate_thumbprint
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


def setup(tmp_path):
    authority = IdentityAuthority.initialize(tmp_path / 'authority',
        issuer='aivm.test', audience='aivm-secrets.identity')
    one_key, one_csr = tmp_path / 'one.key', tmp_path / 'one.csr'
    original_fp = create_csr(private_key=one_key, request_file=one_csr)
    original = authority.enroll(subject='vm-alpha', csr=one_csr.read_bytes(),
                                approve_fingerprint=original_fp)
    two_key, two_csr = tmp_path / 'two.key', tmp_path / 'two.csr'
    next_fp = create_csr(private_key=two_key, request_file=two_csr)
    return authority, (one_key, one_csr, original_fp, original), (two_key, two_csr, next_fp)


def der(cert):
    return x509.load_pem_x509_certificate(Path(cert).read_bytes()).public_bytes(Encoding.DER)


def rotate(authority, orig, candidate, **kwargs):
    key, csr, fingerprint = candidate
    _, _, _, old = orig
    return authority.rotate_client_key(
        subject='vm-alpha', csr=csr.read_bytes(),
        approve_fingerprint=fingerprint, expected_epoch=old['epoch'],
        expected_thumbprint=old['certificate_sha256'], **kwargs)


def test_distinct_key_advances_epoch_and_invalidates_old_identity(tmp_path):
    authority, old, candidate = setup(tmp_path)
    now = int(time.time())
    old_cert_der = der(old[3]['certificate'])
    token = tmp_path / 'old.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.SYNTHETIC',
                    output=token, now=now)
    new = rotate(authority, old, candidate, now=now)
    assert new['epoch'] == old[3]['epoch'] + 1
    assert new['certificate_sha256'] != old[3]['certificate_sha256']
    assert certificate_thumbprint(der(new['certificate'])) == new['certificate_sha256']
    old_pub = x509.load_der_x509_certificate(old_cert_der).public_key().public_numbers()
    new_pub = x509.load_der_x509_certificate(der(new['certificate'])).public_key().public_numbers()
    assert old_pub != new_pub
    assert candidate[0].read_bytes() != old[0].read_bytes()
    with pytest.raises(SecretsError):
        authority.expectation_for_peer(old_cert_der, now)
    expected = authority.expectation_for_peer(der(new['certificate']), now)
    with pytest.raises(SecretsError):
        authority.token_verifier(expected).open(token.read_text(),
            authenticated_peer_der=der(new['certificate']), now=now,
            expected=expected)


def test_same_key_and_wrong_fingerprint_fail_without_mutating_state(tmp_path):
    authority, old, candidate = setup(tmp_path)
    before = authority.status()['subjects']['vm-alpha'].copy()
    with pytest.raises(SecretsError) as exc:
        rotate(authority, old, old[:3])
    assert exc.value.code == 'denied'
    with pytest.raises(SecretsError) as exc:
        rotate(authority, old, (candidate[0],candidate[1],old[2]))
    assert exc.value.code == 'denied'
    assert authority.status()['subjects']['vm-alpha'] == before


def test_stale_cas_cannot_replace_newer_key(tmp_path):
    authority, old, candidate = setup(tmp_path)
    new = rotate(authority, old, candidate)
    assert new['epoch'] == 1
    with pytest.raises(SecretsError) as exc:
        rotate(authority, old, candidate)
    assert exc.value.code == 'revoked'
    authority.revoke('vm-alpha')
    with pytest.raises(SecretsError) as exc:
        authority.rotate_client_key(
            subject='vm-alpha', csr=old[1].read_bytes(),
            approve_fingerprint=old[2], expected_epoch=new['epoch'],
            expected_thumbprint=new['certificate_sha256'])
    assert exc.value.code == 'revoked'


def test_stored_enrollment_certificate_tampering_fails_closed(tmp_path):
    authority, old, candidate = setup(tmp_path)
    path = Path(old[3]['certificate'])
    path.write_bytes(b'not a certificate')
    path.chmod(0o600)
    with pytest.raises(SecretsError) as exc:
        rotate(authority, old, candidate)
    assert exc.value.code == 'invalid_capability'


def test_guarded_compensation_cannot_revoke_concurrent_replacement(tmp_path):
    authority, old, candidate = setup(tmp_path)
    first = rotate(authority, old, candidate)
    # Another operator installs another credential before delayed cleanup.
    current = authority.enroll(subject='vm-alpha', csr=old[1].read_bytes(),
        approve_fingerprint=old[2], replace=True)
    cleanup = authority.revoke_if_current(subject='vm-alpha',
        expected_epoch=first['epoch'],
        expected_thumbprint=first['certificate_sha256'])
    assert cleanup['revoked'] is False
    assert authority.status()['subjects']['vm-alpha']['active'] is True
    assert authority.status()['subjects']['vm-alpha']['epoch'] == current['epoch']
    # A matching compensation DOES revoke the identity it created.
    done = authority.revoke_if_current(subject='vm-alpha',
        expected_epoch=current['epoch'],
        expected_thumbprint=current['certificate_sha256'])
    assert done['revoked'] is True
    assert authority.status()['subjects']['vm-alpha']['active'] is False


def test_rotated_key_real_mtls_accepts_only_new_epoch(tmp_path):
    """The actual TLS client cert and private key change, not just a CSR."""
    import socket
    import ssl
    import threading
    from aivm_secrets.identity.mtls import IdentityTLSBridge, server_context
    from aivm_secrets.identity.model import IdentityExpectation
    from aivm_secrets.primitives import codec

    authority, old, candidate = setup(tmp_path)
    now = int(time.time())
    before = tmp_path / 'before.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.OLD',
                    output=before, now=now)
    new = rotate(authority, old, candidate, now=now)
    after = tmp_path / 'after.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.NEW',
                    output=after, now=now)
    cert, private, ca = authority.tls_paths()
    effects = []

    class Broker:
        def handle(self, frame):
            effects.append(codec.loads(frame))
            return {'ok': True, 'version': 1, 'result': {'accepted': True}}

    bridge = IdentityTLSBridge(
        context=server_context(certificate=cert, private_key=private, client_ca=ca),
        verifier=authority.token_verifier(IdentityExpectation(
            authority.issuer, authority.audience, 'init', 0)),
        broker=Broker(), expected_for_peer=authority.expectation_for_peer,
        wall_clock=lambda: now,
    )

    def request(guest_cert, guest_key, jwt):
        server, client = socket.socketpair()
        errors=[]
        def host():
            try:
                bridge.serve_accepted(server)
            except Exception as ex:
                errors.append(ex)
        thread=threading.Thread(target=host)
        thread.start()
        try:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
            tls.maximum_version = ssl.TLSVersion.TLSv1_3
            tls.check_hostname = True
            tls.verify_mode = ssl.CERT_REQUIRED
            tls.load_verify_locations(cafile=str(ca))
            tls.load_cert_chain(str(guest_cert), str(guest_key))
            with tls.wrap_socket(client, server_hostname='localhost') as conn:
                conn.settimeout(4)
                conn.sendall(codec.dumps({'version': 1, 'capability': jwt,
                                          'describe': True}) + b'\n')
                reply=b''
                while not reply.endswith(b'\n'):
                    chunk=conn.recv(65536)
                    if not chunk:
                        break
                    reply += chunk
                return codec.loads(reply)
        finally:
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert not errors

    rejected = request(old[3]['certificate'], old[0], before.read_text())
    assert rejected['ok'] is False
    assert rejected['error']['code'] == 'invalid_capability'
    assert effects == []
    accepted = request(new['certificate'], candidate[0], after.read_text())
    assert accepted['ok'] is True
    assert effects[0]['capability'] == 'aivs1.NEW'
