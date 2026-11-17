"""P4c identity renewal: synthetic credentials only, no running VM/provider."""
from __future__ import annotations

import json
import os
import ssl
import stat
import time
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.certificates import create_csr, inspect_csr
from aivm_secrets.identity.garrett import registry
from aivm_secrets.identity.mtls import server_context
from aivm_secrets.identity.token import certificate_thumbprint


def authority_and_client(tmp_path):
    authority = IdentityAuthority.initialize(
        tmp_path / 'authority', issuer='aivm.test',
        audience='aivm-secrets.identity')
    key = tmp_path / 'guest.key'
    csr = tmp_path / 'guest.csr'
    fp = create_csr(private_key=key, request_file=csr)
    old = authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                           approve_fingerprint=fp)
    return authority, key, csr, fp, old


def der(cert_file):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    return x509.load_pem_x509_certificate(
        Path(cert_file).read_bytes()).public_bytes(Encoding.DER)


def renew(authority, csr, fp, old, **kwargs):
    return authority.renew_client(
        subject='vm-alpha', csr=csr.read_bytes(), approve_fingerprint=fp,
        expected_epoch=old['epoch'],
        expected_thumbprint=old['certificate_sha256'], **kwargs)


def test_renew_same_guest_key_changes_cert_epoch_and_token_binding(tmp_path):
    authority, key, csr, fp, old = authority_and_client(tmp_path)
    now = int(time.time())
    old_der = der(old['certificate'])
    original_key = key.read_bytes()
    old_token_path = tmp_path / 'old.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.TEST_ONLY',
                    output=old_token_path, now=now)
    new = renew(authority, csr, fp, old, now=now)
    assert key.read_bytes() == original_key  # certificate-only renewal
    assert new['epoch'] == 1
    assert new['certificate_sha256'] != old['certificate_sha256']
    assert certificate_thumbprint(der(new['certificate'])) == new['certificate_sha256']
    with pytest.raises(SecretsError):
        authority.expectation_for_peer(old_der, now)
    expected = authority.expectation_for_peer(der(new['certificate']), now)
    assert expected.epoch == 1
    # The old JWT cannot be presented through the bridge under the new peer.
    with pytest.raises(SecretsError):
        authority.token_verifier(expected).open(
            old_token_path.read_text(),
            authenticated_peer_der=der(new['certificate']), now=now,
            expected=expected)
    fresh_path = tmp_path / 'new.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.FRESH',
                    output=fresh_path, now=now)
    assert authority.token_verifier(expected).open(
        fresh_path.read_text(), authenticated_peer_der=der(new['certificate']),
        now=now, expected=expected).broker_capability == 'aivs1.FRESH'


def test_client_renewal_rejects_stale_cas_and_revoked_state(tmp_path):
    authority, _, csr, fp, old = authority_and_client(tmp_path)
    new = renew(authority, csr, fp, old)
    before = authority.status()['subjects']['vm-alpha'].copy()
    for stale in (old, {**new, 'epoch': new['epoch'] - 1},
                  {**new, 'certificate_sha256': old['certificate_sha256']}):
        with pytest.raises(SecretsError) as exc:
            renew(authority, csr, fp, stale)
        assert exc.value.code == 'revoked'
    assert authority.status()['subjects']['vm-alpha'] == before
    authority.revoke('vm-alpha')
    with pytest.raises(SecretsError) as exc:
        renew(authority, csr, fp, new)
    assert exc.value.code == 'revoked'


def test_client_renewal_invalid_csr_or_key_confirmation_cannot_mutate(tmp_path):
    authority, _, csr, fp, old = authority_and_client(tmp_path)
    prior = authority.status()['subjects'].copy()
    with pytest.raises(SecretsError) as exc:
        authority.renew_client(subject='vm-alpha', csr=b'INVALID CSR',
            approve_fingerprint=fp, expected_epoch=old['epoch'],
            expected_thumbprint=old['certificate_sha256'])
    assert exc.value.code == 'invalid_capability'
    with pytest.raises(SecretsError) as exc:
        authority.renew_client(subject='vm-alpha', csr=csr.read_bytes(),
            approve_fingerprint='f' * 64, expected_epoch=old['epoch'],
            expected_thumbprint=old['certificate_sha256'])
    assert exc.value.code == 'denied'
    assert authority.status()['subjects'] == prior


def test_client_renewal_after_leaf_expiration_remains_bootstrap_only(tmp_path):
    authority, _, csr, fp, old = authority_and_client(tmp_path)
    # This does not authenticate using the expired leaf: the operator must
    # have a separate trusted, pinned bootstrap channel.
    now = old['not_after'] + 1
    next_record = renew(authority, csr, fp, old, now=now)
    assert next_record['epoch'] == old['epoch'] + 1


def test_server_rotation_uses_immutable_generations_and_valid_tls_pair(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    authority, _, _, _, _ = authority_and_client(tmp_path)
    old = authority.tls_paths()
    old_cert = der(old[0])
    stamp = int(time.time())
    first = authority.renew_server(now=stamp)
    assert first['generation'] == 2 and first['restart_required']
    rotated = authority.tls_paths()
    assert old[0] != rotated[0] and old[1] != rotated[1]
    assert der(old[0]) == old_cert
    assert rotated[0].is_file() and rotated[1].is_file()
    assert certificate_thumbprint(der(rotated[0])) == first['certificate_sha256']
    assert stat.S_IMODE(rotated[0].stat().st_mode) == 0o600
    context = server_context(certificate=rotated[0], private_key=rotated[1],
                             client_ca=rotated[2])
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert x509.load_der_x509_certificate(der(rotated[0])).not_valid_after_utc.timestamp() > stamp
    fresh = IdentityAuthority(authority.root)
    second = fresh.renew_server(now=stamp)
    assert second['generation'] == 3
    assert fresh.tls_paths()[0] != rotated[0]


def test_interrupted_server_rotation_preserves_previous_selection(tmp_path, monkeypatch):
    authority, _, _, _, _ = authority_and_client(tmp_path)
    old = authority.tls_paths()
    original = authority._write_selected_manifest
    def fail(state):
        raise SecretsError('audit_failed')
    monkeypatch.setattr(authority, '_write_selected_manifest', fail)
    with pytest.raises(SecretsError):
        authority.renew_server()
    assert authority.tls_paths() == old
    monkeypatch.setattr(authority, '_write_selected_manifest', original)
    next_record = authority.renew_server()
    assert next_record['generation'] == 3  # orphaned 2 never overwritten
    assert authority.tls_paths()[0].name == 'server-3.pem'


def test_malformed_server_selection_denied_no_legacy_fallback(tmp_path):
    authority, _, _, _, _ = authority_and_client(tmp_path)
    path = authority.root / 'authority.json'
    path.write_text('{"schema":2,"server":{"generation":99}}')
    path.chmod(0o600)
    with pytest.raises(SecretsError) as exc:
        authority.tls_paths()
    assert exc.value.code == 'invalid_capability'


def test_new_operations_do_not_change_default_vm_or_live_provider(tmp_path):
    authority, _, _, _, _ = authority_and_client(tmp_path)
    assert not (authority.root / 'server-selection.json').exists()
    assert set(authority.status()['subjects']) == {'vm-alpha'}
    assert (authority.root / 'server-generations/server-1.pem').is_file()


def test_pure_renewal_is_nonmutating_monotone_and_requires_cas():
    import base64
    def thumb(value):
        return base64.urlsafe_b64encode(bytes([value])*32).rstrip(b'=').decode('ascii')
    source = {'schema': 1, 'subjects': {'vm-alpha': {
        'epoch': 10, 'active': True, 'certificate_sha256': thumb(1),
        'not_after': 1000, 'key_sha256': '1' * 64, 'retired_keys': ['0' * 64],
    }}}
    original = json.loads(json.dumps(source))
    fresh = registry.renew(source, issuer='aivm.test', audience='bound',
                           subject='vm-alpha', expected_epoch=10,
                           expected_thumbprint=thumb(1), thumbprint=thumb(2),
                           key_sha256='2' * 64, not_after=2000, now=100)
    assert source == original
    assert fresh['subjects']['vm-alpha']['epoch'] == 11
    assert fresh['subjects']['vm-alpha']['retired_keys'] == ['0' * 64, '1' * 64]
    with pytest.raises(SecretsError):
        registry.renew(fresh, issuer='aivm.test', audience='bound',
                       subject='vm-alpha', expected_epoch=10,
                       expected_thumbprint=thumb(1), thumbprint=thumb(3),
                       key_sha256='2' * 64, not_after=3000, now=100)


def test_real_mtls_after_client_and_server_renewal_denies_old_peer(tmp_path):
    """TLS alone accepts CA-signed peers; the registry rejects the old leaf."""
    import socket
    import threading
    from aivm_secrets.identity.mtls import IdentityTLSBridge
    from aivm_secrets.identity.garrett.claims import IdentityExpectation
    from aivm_secrets.primitives import codec

    authority, key, csr, fp, old = authority_and_client(tmp_path)
    now = int(time.time())
    old_path = tmp_path / 'old.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.OLD',
                    output=old_path, now=now)
    new = renew(authority, csr, fp, old, now=now)
    fresh_path = tmp_path / 'fresh.jwt'
    authority.issue(subject='vm-alpha', broker_capability='aivs1.NEW',
                    output=fresh_path, now=now)
    authority.renew_server(now=now)
    cert, host_key, ca = authority.tls_paths()
    accepted = []

    class Broker:
        def handle(self, frame):
            accepted.append(codec.loads(frame))
            return {'ok': True, 'version': 1, 'result': {'accepted': True}}

    expected = IdentityExpectation(authority.issuer, authority.audience,
                                   'init', 0)
    bridge = IdentityTLSBridge(
        context=server_context(certificate=cert, private_key=host_key,
                               client_ca=ca),
        verifier=authority.token_verifier(expected), broker=Broker(),
        expected_for_peer=authority.expectation_for_peer,
        wall_clock=lambda: now,
    )

    def call(guest_cert, jwt):
        server, client = socket.socketpair()
        errors = []

        def serve():
            try:
                bridge.serve_accepted(server)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=str(ca))
            ctx.load_cert_chain(str(guest_cert), str(key))
            with ctx.wrap_socket(client, server_hostname='localhost') as tls:
                tls.settimeout(4)
                tls.sendall(codec.dumps({'version': 1, 'capability': jwt,
                                         'describe': True}) + b'\n')
                chunks = b''
                while not chunks.endswith(b'\n'):
                    data = tls.recv(65536)
                    if not data:
                        break
                    chunks += data
                return codec.loads(chunks)
        finally:
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert not errors

    old_reply = call(old['certificate'], old_path.read_text())
    assert old_reply['ok'] is False
    assert old_reply['error']['code'] == 'invalid_capability'
    assert not accepted
    new_reply = call(new['certificate'], fresh_path.read_text())
    assert new_reply['ok'] is True
    assert len(accepted) == 1
    assert accepted[0]['capability'] == 'aivs1.NEW'


def files_under(root: Path) -> dict[str, bytes]:
    return {str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob('*')) if path.is_file()}


def test_renewal_with_a_different_key_is_denied_without_any_write(
        tmp_path: Path) -> None:
    """REN-07: renew-client re-certifies the enrolled key and nothing else."""
    authority, _, _, _, old = authority_and_client(tmp_path)
    other_key, other_csr = tmp_path / 'other.key', tmp_path / 'other.csr'
    other_fp = create_csr(private_key=other_key, request_file=other_csr)
    before = files_under(authority.root)
    status = authority.status()
    with pytest.raises(SecretsError) as exc:
        renew(authority, other_csr, other_fp, old)
    assert exc.value.code == 'denied'
    assert authority.status() == status
    # No clients/*.pem, no audit file, no registry change: byte-identical.
    assert files_under(authority.root) == before
    assert len(list((authority.root / 'clients').iterdir())) == 1
    assert len(list((authority.root / 'audit').iterdir())) == 1


def test_renewal_after_key_rotation_refuses_the_rotated_away_key(
        tmp_path: Path) -> None:
    """B1: a stale CSR for the old key must not be re-certified."""
    authority, _, csr, fp, old = authority_and_client(tmp_path)
    new_key, new_csr = tmp_path / 'new.key', tmp_path / 'new.csr'
    new_fp = create_csr(private_key=new_key, request_file=new_csr)
    rotated = authority.rotate_client_key(
        subject='vm-alpha', csr=new_csr.read_bytes(),
        approve_fingerprint=new_fp, expected_epoch=old['epoch'],
        expected_thumbprint=old['certificate_sha256'])
    row = authority.status()['subjects']['vm-alpha']
    assert row['key_sha256'] == new_fp and row['retired_keys'] == [fp]
    before = files_under(authority.root)
    # The old guest helper sends the original client.csr on renewal.
    with pytest.raises(SecretsError) as exc:
        renew(authority, csr, fp, rotated)
    assert exc.value.code == 'denied'
    # Nor can an unconditional --replace bring the retired key back.
    with pytest.raises(SecretsError) as exc:
        authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                         approve_fingerprint=fp, replace=True)
    assert exc.value.code == 'denied'
    assert files_under(authority.root) == before
    # The rotated-to key renews normally.
    renewed = renew(authority, new_csr, new_fp, rotated)
    assert renewed['epoch'] == rotated['epoch'] + 1
    assert renewed['certificate_sha256'] != rotated['certificate_sha256']
    assert authority.status()['subjects']['vm-alpha']['key_sha256'] == new_fp


def test_renewal_without_the_enrolled_leaf_fails_closed(tmp_path: Path) -> None:
    authority, _, csr, fp, old = authority_and_client(tmp_path)
    Path(old['certificate']).unlink()
    status = authority.status()
    with pytest.raises(SecretsError) as exc:
        renew(authority, csr, fp, old)
    assert exc.value.code == 'invalid_capability'
    assert 'identity enroll --replace' in exc.value.detail
    assert authority.status() == status
    assert list((authority.root / 'clients').iterdir()) == []


def test_renewal_with_a_leaf_that_differs_from_the_registry_fails_closed(
        tmp_path: Path) -> None:
    authority, _, csr, fp, old = authority_and_client(tmp_path)
    path = authority.root / 'enrollments.json'
    data = json.loads(path.read_text())
    data['subjects']['vm-alpha']['key_sha256'] = 'f' * 64
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    with pytest.raises(SecretsError) as exc:
        renew(authority, csr, fp, old)
    assert exc.value.code == 'invalid_capability'
    assert authority.status()['subjects']['vm-alpha']['epoch'] == old['epoch']
