"""P4a offline host enrollment: no real VM or provider is contacted."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import (
    IdentityAuthority, create_csr, inspect_csr,
)
from aivm_secrets.identity.token import certificate_thumbprint


def make(tmp_path):
    root = tmp_path / 'authority'
    authority = IdentityAuthority.initialize(
        root, issuer='aivm.test', audience='aivm-secrets.identity')
    key = tmp_path / 'vm-key.pem'
    csr = tmp_path / 'vm.csr'
    fingerprint = create_csr(private_key=key, request_file=csr)
    return authority, key, csr, fingerprint


def enroll(authority, csr, fingerprint, *, subject='vm-alpha', **kwargs):
    return authority.enroll(subject=subject, csr=csr.read_bytes(),
                            approve_fingerprint=fingerprint, **kwargs)


def der_of(path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return x509.load_pem_x509_certificate(Path(path).read_bytes()).public_bytes(
        serialization.Encoding.DER)


def test_private_authority_contains_all_trust_material_and_refuses_reset(tmp_path):
    authority, key, csr, fp = make(tmp_path)
    assert authority.status()['subjects'] == {}
    for child in authority.root.iterdir():
        if child.is_file():
            assert stat.S_IMODE(child.stat().st_mode) == 0o600
        else:
            assert stat.S_IMODE(child.stat().st_mode) == 0o700
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    with pytest.raises(SecretsError):
        IdentityAuthority.initialize(authority.root, issuer='evil', audience='test')
    assert IdentityAuthority(authority.root).status() == authority.status()


def test_csr_proof_of_possession_and_operator_key_fingerprint(tmp_path):
    authority, key, csr, fingerprint = make(tmp_path)
    assert inspect_csr(csr.read_bytes()) == fingerprint
    with pytest.raises(SecretsError) as exc:
        enroll(authority, csr, 'f' * 64)
    assert exc.value.code == 'denied'
    assert authority.status()['subjects'] == {}
    data = csr.read_bytes()
    with pytest.raises(SecretsError):
        inspect_csr(data.replace(b'CERTIFICATE REQUEST', b'CERTIFICATE WRONG'))
    result = enroll(authority, csr, fingerprint)
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    cert = x509.load_pem_x509_certificate(Path(result['certificate']).read_bytes())
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == \
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    assert result['certificate_sha256'] == certificate_thumbprint(der_of(result['certificate']))
    assert result['epoch'] == 0


def test_issue_bound_token_then_revoke_without_restarting_bridge(tmp_path):
    authority, key, csr, fingerprint = make(tmp_path)
    entry = enroll(authority, csr, fingerprint)
    der = der_of(entry['certificate'])
    # Enrolled certificates are issued for the wall clock; the test uses it.
    import time
    t = int(time.time())
    result = authority.issue(subject='vm-alpha',
                             broker_capability='aivs1.TEST_ONLY_CAPABILITY',
                             output=tmp_path / 'bound.jwt', now=t)
    token = Path(result['output']).read_text()
    assert 'aivs1.' not in token
    assert stat.S_IMODE(Path(result['output']).stat().st_mode) == 0o600
    expectation = authority.expectation_for_peer(der, t)
    verifier = authority.token_verifier(expectation)
    opened = verifier.open(token, authenticated_peer_der=der, now=t,
                           expected=expectation)
    assert opened.broker_capability == 'aivs1.TEST_ONLY_CAPABILITY'
    assert opened.claims.subject == 'vm-alpha'
    assert opened.claims.epoch == 0
    revoked = authority.revoke('vm-alpha', now=t)
    assert revoked == {'subject': 'vm-alpha', 'epoch': 1, 'active': False}
    with pytest.raises(SecretsError) as exc:
        authority.expectation_for_peer(der, t)
    assert exc.value.code == 'invalid_capability'
    assert authority.revoke('vm-alpha') == revoked  # idempotent
    assert authority.status()['subjects']['vm-alpha']['active'] is False


def test_replace_rotates_epoch_and_invalidates_previous_cert(tmp_path):
    authority, key, csr, fingerprint = make(tmp_path)
    old = enroll(authority, csr, fingerprint)
    with pytest.raises(SecretsError):
        enroll(authority, csr, fingerprint)
    next_key = tmp_path / 'next.key'
    next_csr = tmp_path / 'next.csr'
    next_fp = create_csr(private_key=next_key, request_file=next_csr)
    new = enroll(authority, next_csr, next_fp, replace=True)
    assert new['epoch'] == 1
    assert new['certificate_sha256'] != old['certificate_sha256']
    import time
    with pytest.raises(SecretsError):
        authority.expectation_for_peer(der_of(old['certificate']), int(time.time()))
    expected = authority.expectation_for_peer(der_of(new['certificate']), int(time.time()))
    assert expected.subject == 'vm-alpha' and expected.epoch == 1


def test_private_host_storage_and_untrusted_root_refusals(tmp_path):
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o700)
    shared.chmod(0o700)
    with pytest.raises(SecretsError) as exc:
        IdentityAuthority.initialize(shared / 'host', issuer='aivm.test',
                                     audience='aivm.test', untrusted=(shared,))
    assert exc.value.code == 'shared_source'
    authority, key, csr, fingerprint = make(tmp_path)
    link = tmp_path / 'redirect'
    link.symlink_to(authority.root, target_is_directory=True)
    with pytest.raises(SecretsError):
        IdentityAuthority(link)
    # Do not allow a guest-writable directory to carry host JWT output.
    enroll(authority, csr, fingerprint)
    authority = IdentityAuthority(authority.root, untrusted=(shared,))
    with pytest.raises(SecretsError):
        authority.issue(subject='vm-alpha',
                        broker_capability='aivs1.TEST_ONLY_CAPABILITY',
                        output=shared / 'token.jwt')


def test_missing_or_corrupted_registry_fails_closed(tmp_path):
    authority, key, csr, fingerprint = make(tmp_path)
    enroll(authority, csr, fingerprint)
    registry = authority.root / 'enrollments.json'
    registry.write_text('{"schema":1,"subjects":{}} BAD')
    with pytest.raises(SecretsError):
        authority.status()
    # No silent recreation from an empty/corrupt store.
    with pytest.raises(SecretsError):
        authority.expectation_for_peer(b'cert bytes', 100)


def test_no_extensions_allowed_in_guest_csr(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'vm')]))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
           .sign(key, hashes.SHA256()))
    with pytest.raises(SecretsError):
        inspect_csr(csr.public_bytes(serialization.Encoding.PEM))


def test_audit_records_intent_before_enrollment_and_revocation(tmp_path):
    from aivm_secrets.host.audit import verify
    authority, key, csr, fingerprint = make(tmp_path)
    enroll(authority, csr, fingerprint)
    authority.revoke('vm-alpha')
    paths = list((authority.root / 'audit').glob('*.jsonl'))
    assert len(paths) == 2
    events = []
    for path in paths:
        verify(path)
        events.append([json.loads(row)['event'] for row in path.read_text().splitlines()])
        assert 'TEST_ONLY_CAPABILITY' not in path.read_text()
    assert ['identity_enroll_intent', 'identity_recorded'] in events
    assert ['identity_revoke_intent', 'identity_recorded'] in events
