"""CA generation cutover, crash fencing and real TLS tests; synthetic only."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.certificates import create_csr
from aivm_secrets.identity.service import UnixIdentityService
from aivm_secrets.identity.token import certificate_thumbprint
from aivm_secrets.host.server import LocalServer
from tests.secrets_helpers import Harness, REPO
from aivm_secrets.identity.client import bound_call


def setup(tmp_path):
    authority = IdentityAuthority.initialize(tmp_path / 'identity',
        issuer='aivm.test', audience='aivm-secrets.identity')
    key = tmp_path / 'old.key'
    csr = tmp_path / 'old.csr'
    fp = create_csr(private_key=key, request_file=csr)
    row = authority.enroll(subject='vm-original', csr=csr.read_bytes(),
                           approve_fingerprint=fp)
    return authority, key, row


def der(cert):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    return x509.load_pem_x509_certificate(Path(cert).read_bytes()).public_bytes(Encoding.DER)


def assert_denied(fn, code=None):
    with pytest.raises(SecretsError) as caught:
        fn()
    if code is not None:
        assert caught.value.code == code


def test_ca_rotation_revokes_every_identity_and_fences_old_authorities(tmp_path):
    authority, old_key, original = setup(tmp_path)
    t = int(time.time())
    root_before = authority.tls_paths()
    original_peer = der(original['certificate'])
    jwt = tmp_path / 'token.jwt'
    authority.issue(subject='vm-original', broker_capability='aivs1.SYNTHETIC',
                    output=jwt, now=t)
    previous = authority.status()
    result = authority.rotate_ca(now=t)
    assert result['ca_generation'] == 2
    assert result['server_generation'] == 2
    assert result['enrollments_revoked'] is True
    assert result['restart_required'] is True
    assert result['ca_sha256'] != previous['ca_sha256']
    assert_denied(lambda: authority.expectation_for_peer(original_peer, t), 'revoked')
    assert_denied(lambda: authority.tls_paths(), 'revoked')
    assert_denied(lambda: authority.issue(subject='vm-original',
                  broker_capability='aivs1.X', output=tmp_path / 'other.jwt'),
                  'revoked')
    refreshed = IdentityAuthority(authority.root)
    assert refreshed.status()['subjects'] == {}
    assert refreshed.status()['ca_generation'] == 2
    assert refreshed.tls_paths() != root_before
    assert all(file.is_file() for file in refreshed.tls_paths())
    assert_denied(lambda: refreshed.expectation_for_peer(original_peer, t),
                  'invalid_capability')
    # Root signature, not merely a new filename, changed.
    from cryptography import x509
    ca_old = x509.load_pem_x509_certificate(root_before[2].read_bytes())
    ca_new = x509.load_pem_x509_certificate(refreshed.tls_paths()[2].read_bytes())
    assert ca_old.public_key() != ca_new.public_key()
    leaf = x509.load_der_x509_certificate(der(refreshed.tls_paths()[0]))
    leaf.verify_directly_issued_by(ca_new)
    with pytest.raises(Exception):
        leaf.verify_directly_issued_by(ca_old)
    # The new root does not silently re-enroll any old VM or reuse its tokens.
    next_key, next_csr = tmp_path / 'new.key', tmp_path / 'new.csr'
    fp = create_csr(private_key=next_key, request_file=next_csr)
    updated = refreshed.enroll(subject='vm-original', csr=next_csr.read_bytes(),
                               approve_fingerprint=fp, now=t)
    assert certificate_thumbprint(der(updated['certificate'])) == updated['certificate_sha256']
    expectation = refreshed.expectation_for_peer(der(updated['certificate']), t)
    assert_denied(lambda: refreshed.token_verifier(expectation).open(
        jwt.read_text(), authenticated_peer_der=der(updated['certificate']),
        now=t, expected=expectation))
    assert not (authority.root / 'ca.pem').exists()
    assert not (authority.root / 'server-selection.json').exists()
    assert not (authority.root / 'issuer.key').exists()
    assert not (authority.root / 'issuer.aes256').exists()


def test_root_staging_failure_never_revokes_unnecessarily(tmp_path, monkeypatch):
    authority, _, row = setup(tmp_path)
    t = int(time.time())
    root_before = authority.tls_paths()
    def fail(*args, **kwargs):
        raise SecretsError('audit_failed')
    original = authority._stage_pair
    monkeypatch.setattr(authority, '_stage_pair', fail)
    assert_denied(lambda: authority.rotate_ca(now=t), 'audit_failed')
    assert authority.tls_paths() == root_before
    assert authority.status()['subjects']['vm-original']['active']
    monkeypatch.setattr(authority, '_stage_pair', original)
    assert authority.rotate_ca(now=t)['ca_generation'] == 2


def test_root_commit_failure_revokes_before_activation_and_skips_orphans(tmp_path, monkeypatch):
    authority, _, _ = setup(tmp_path)
    old_tls = authority.tls_paths()
    t = int(time.time())
    original = authority._write_selected_manifest
    def fail(state):
        raise SecretsError('audit_failed')
    monkeypatch.setattr(authority, '_write_selected_manifest', fail)
    assert_denied(lambda: authority.rotate_ca(now=t), 'audit_failed')
    assert authority.tls_paths() == old_tls
    assert authority.status()['subjects'] == {}
    monkeypatch.setattr(authority, '_write_selected_manifest', original)
    result = authority.rotate_ca(now=t)
    assert result['ca_generation'] == 3
    assert result['server_generation'] == 3
    assert (authority.root / 'ca-generations/ca-2.key').is_file()
    assert IdentityAuthority(authority.root).status()['ca_generation'] == 3


def test_manifest_is_one_strict_selection_and_prior_schema_fails(tmp_path):
    authority, _, _ = setup(tmp_path)
    path = authority.root / 'authority.json'
    original = path.read_bytes()
    for invalid in (
        {'schema': 1, 'issuer': 'aivm.test', 'audience': 'aivm-secrets.identity'},
        {**json.loads(original), 'ca': {'generation': 1, 'sha256': 'b' * 64}},
        {**json.loads(original), 'server': {'generation': 1, 'ca_generation': 2}},
        {**json.loads(original), 'extra': True},
    ):
        path.write_text(json.dumps(invalid))
        path.chmod(0o600)
        assert_denied(lambda: IdentityAuthority(authority.root), 'invalid_capability')
    path.write_bytes(original)
    path.chmod(0o600)
    assert authority.status()['ca_generation'] == 1


def test_live_bound_bridge_does_not_dispatch_after_ca_cutover(tmp_path):
    authority, key, enrolled = setup(tmp_path)
    harness = Harness(tmp_path)
    jwt = tmp_path / 'token.jwt'
    authority.issue(subject='vm-original', broker_capability=harness.capability,
                    output=jwt)
    listen = tmp_path / 'bridge' / 'identity.sock'
    ca_before = authority.tls_paths()[2]
    request = {'operation': 'pr.view',
               'arguments': {'repository': REPO, 'pr': 13861}}
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            with UnixIdentityService(authority=authority,
                   broker_socket=broker.socket_path,
                   listen=listen, max_connections=2, idle_seconds=12) as service:
                runner = threading.Thread(target=service.serve)
                runner.start()
                before = bound_call(socket_path=listen, ca=ca_before,
                                    certificate=Path(enrolled['certificate']),
                                    private_key=key, jwt_file=jwt, request=request)
                assert before['ok'] and len(harness.executor.calls) == 1
                authority.rotate_ca()
                denied = bound_call(socket_path=listen, ca=ca_before,
                                    certificate=Path(enrolled['certificate']),
                                    private_key=key, jwt_file=jwt, request=request)
                assert not denied['ok']
                assert len(harness.executor.calls) == 1
                runner.join(timeout=7)
                assert not runner.is_alive()
    finally:
        harness.broker.close()
