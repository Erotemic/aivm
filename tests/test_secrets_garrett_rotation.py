"""Issuer rotation preserves binding and supports immediate explicit retirement."""
import time
import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority, create_csr
from aivm_secrets.identity.token import certificate_thumbprint


def test_issuer_rotation_and_retirement_are_enforced_per_presentation(tmp_path):
    now = int(time.time())
    authority = IdentityAuthority.initialize(tmp_path / 'identity',
        issuer='aivm.local', audience='aivm-secrets.identity', now=now)
    create_csr(private_key=tmp_path / 'key.pem', request_file=tmp_path / 'csr.pem')
    from aivm_secrets.identity.enrollment import inspect_csr
    issued = authority.enroll(subject='vm-demo', csr=(tmp_path / 'csr.pem').read_bytes(),
                             approve_fingerprint=inspect_csr((tmp_path / 'csr.pem').read_bytes()),
                             now=now)
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    from pathlib import Path
    peer_der = x509.load_pem_x509_certificate(
        Path(issued['certificate']).read_bytes()).public_bytes(Encoding.DER)
    expected = authority.expectation_for_peer(peer_der, now)
    old_verifier = authority.token_verifier(expected)
    authority.issue(subject='vm-demo', broker_capability='aivs1.fake',
                    output=tmp_path / 'old.jwt', now=now)
    old = (tmp_path / 'old.jwt').read_text()
    assert old_verifier.open(old, authenticated_peer_der=peer_der,
                             now=now, expected=expected).broker_capability == 'aivs1.fake'
    rotated = authority.rotate_issuer()
    assert rotated['active'] == 'local-2'
    authority.issue(subject='vm-demo', broker_capability='aivs1.fake',
                    output=tmp_path / 'new.jwt', now=now)
    new = (tmp_path / 'new.jwt').read_text()
    assert old_verifier.open(old, authenticated_peer_der=peer_der, now=now,
                             expected=expected)
    assert old_verifier.open(new, authenticated_peer_der=peer_der, now=now,
                             expected=expected)
    authority.retire_issuer('local-1')
    with pytest.raises(SecretsError):
        old_verifier.open(old, authenticated_peer_der=peer_der, now=now,
                          expected=expected)
    assert old_verifier.open(new, authenticated_peer_der=peer_der, now=now,
                             expected=expected)
    with pytest.raises(SecretsError):
        authority.retire_issuer('local-2')
