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


def audit_events(root: Path) -> list[list[dict]]:
    """Every audit file's records, verified, in a stable order."""
    from aivm_secrets.host.audit import verify
    files = []
    for path in sorted((root / 'audit').glob('*.jsonl')):
        verify(path)
        files.append([json.loads(line) for line in path.read_text().splitlines()])
    return files


def tree(root: Path) -> dict[str, bytes]:
    """Every regular file under the authority, by relative path."""
    return {str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob('*')) if path.is_file()}


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
    result = authority.rotate_ca(expected_ca_sha256=previous['ca_sha256'], now=t)
    assert result['ca_generation'] == 2
    assert result['server_generation'] == 2
    assert result['enrollments_revoked'] is True
    assert result['restart_required'] is True
    assert result['ca_sha256'] != previous['ca_sha256']
    assert result['revoked'] == [{
        'subject': 'vm-original', 'epoch': original['epoch'],
        'certificate_sha256': original['certificate_sha256']}]
    assert_denied(lambda: authority.expectation_for_peer(original_peer, t), 'revoked')
    assert_denied(lambda: authority.tls_paths(), 'revoked')
    assert_denied(lambda: authority.issue(subject='vm-original',
                  broker_capability='aivs1.X', output=tmp_path / 'other.jwt'),
                  'revoked')
    refreshed = IdentityAuthority(authority.root)
    # Revoke-all, not an empty registry: the row stays, inactive, one epoch on.
    row = refreshed.status()['subjects']['vm-original']
    assert row == {**previous['subjects']['vm-original'],
                   'active': False, 'epoch': original['epoch'] + 1}
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
    # Epochs stay monotonic across the rotation: nothing issued under the old
    # root can carry the epoch of the re-enrollment.
    assert updated['epoch'] == original['epoch'] + 2
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
    sha = authority.status()['ca_sha256']
    assert_denied(lambda: authority.rotate_ca(expected_ca_sha256=sha, now=t),
                  'audit_failed')
    assert authority.tls_paths() == root_before
    assert authority.status()['subjects']['vm-original']['active']
    monkeypatch.setattr(authority, '_stage_pair', original)
    assert authority.rotate_ca(expected_ca_sha256=sha, now=t)['ca_generation'] == 2


def test_root_commit_failure_revokes_before_activation_and_skips_orphans(tmp_path, monkeypatch):
    authority, _, _ = setup(tmp_path)
    old_tls = authority.tls_paths()
    t = int(time.time())
    original = authority._write_selected_manifest
    def fail(state):
        raise SecretsError('audit_failed')
    monkeypatch.setattr(authority, '_write_selected_manifest', fail)
    sha = authority.status()['ca_sha256']
    assert_denied(lambda: authority.rotate_ca(expected_ca_sha256=sha, now=t),
                  'audit_failed')
    assert authority.tls_paths() == old_tls
    # Revoked before activation: the old root is still selected, but no row
    # is active any more (fail closed).
    assert authority.status()['ca_sha256'] == sha
    row = authority.status()['subjects']['vm-original']
    assert row['active'] is False and row['epoch'] == 1
    monkeypatch.setattr(authority, '_write_selected_manifest', original)
    result = authority.rotate_ca(expected_ca_sha256=sha, now=t)
    assert result['ca_generation'] == 3
    assert result['server_generation'] == 3
    # The retry revoked nothing new and did not advance the epoch again.
    assert result['revoked'] == []
    fresh = IdentityAuthority(authority.root)
    assert fresh.status()['subjects']['vm-original']['epoch'] == 1
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
                authority.rotate_ca(expected_ca_sha256=authority.ca_sha256)
                denied = bound_call(socket_path=listen, ca=ca_before,
                                    certificate=Path(enrolled['certificate']),
                                    private_key=key, jwt_file=jwt, request=request)
                assert not denied['ok']
                assert len(harness.executor.calls) == 1
                runner.join(timeout=7)
                assert not runner.is_alive()
    finally:
        harness.broker.close()


def test_ca_rotation_audits_each_revoked_enrollment_before_commit(tmp_path: Path) -> None:
    authority, _, original = setup(tmp_path)
    key, csr = tmp_path / 'second.key', tmp_path / 'second.csr'
    fp = create_csr(private_key=key, request_file=csr)
    second = authority.enroll(subject='vm-second', csr=csr.read_bytes(),
                              approve_fingerprint=fp)
    authority.revoke('vm-second')
    before = {str(path) for path in (authority.root / 'audit').iterdir()}
    result = authority.rotate_ca(expected_ca_sha256=authority.ca_sha256)
    # Only the active row is revoked; the already revoked one is untouched.
    assert result['revoked'] == [{
        'subject': 'vm-original', 'epoch': original['epoch'],
        'certificate_sha256': original['certificate_sha256']}]
    rows = IdentityAuthority(authority.root).status()['subjects']
    assert rows['vm-second']['epoch'] == second['epoch'] + 1
    added = [records for records in audit_events(authority.root)
             if records[0]['event'] == 'identity_ca_rotate_intent']
    assert len(added) == 1
    assert len({str(path) for path in (authority.root / 'audit').iterdir()}
               - before) == 1
    events = [(row['event'], row.get('resource'), row.get('digest'))
              for row in added[0]]
    assert events == [
        ('identity_ca_rotate_intent', {'subject': 'issuer'}, result['ca_sha256']),
        ('identity_revoke_intent', {'subject': 'vm-original', 'epoch': 0},
         original['certificate_sha256']),
        ('identity_recorded', {'subject': 'issuer'}, result['ca_sha256']),
    ]


def test_stale_or_repeated_ca_rotation_is_refused_before_any_change(tmp_path: Path) -> None:
    """A second run of the same command must not revoke newer enrollments."""
    authority, _, _ = setup(tmp_path)
    first_sha = authority.status()['ca_sha256']
    authority.rotate_ca(expected_ca_sha256=first_sha)
    fresh = IdentityAuthority(authority.root)
    key, csr = tmp_path / 'after.key', tmp_path / 'after.csr'
    fp = create_csr(private_key=key, request_file=csr)
    enrolled = fresh.enroll(subject='vm-after', csr=csr.read_bytes(),
                            approve_fingerprint=fp)
    files = tree(fresh.root)
    for stale, code in ((first_sha, 'revoked'),
                        (first_sha.upper(), 'invalid_capability'),
                        ('0' * 63, 'invalid_capability')):
        assert_denied(lambda: fresh.rotate_ca(expected_ca_sha256=stale), code)
        # Nothing staged, revoked or audited: byte-identical authority.
        assert tree(fresh.root) == files
    row = fresh.status()['subjects']['vm-after']
    assert row['active'] is True and row['epoch'] == enrolled['epoch']
    assert fresh.status()['ca_generation'] == 2


def test_reenrolling_the_same_key_after_ca_rotation_gets_a_higher_epoch(
        tmp_path: Path) -> None:
    authority, _, original = setup(tmp_path)
    csr = (tmp_path / 'old.csr').read_bytes()
    from aivm_secrets.identity.certificates import inspect_csr
    authority.rotate_ca(expected_ca_sha256=authority.ca_sha256)
    fresh = IdentityAuthority(authority.root)
    again = fresh.enroll(subject='vm-original', csr=csr,
                         approve_fingerprint=inspect_csr(csr))
    assert again['epoch'] == original['epoch'] + 2
    assert fresh.status()['subjects']['vm-original']['retired_keys'] == []


def test_ca_rotation_audits_the_revocations_before_the_registry_commit(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fault injection at the registry commit, as a crash there would be.

    A successful rotation's audit file has the same record order whether the
    revoke intents are written before or after the commit, so only a failed
    commit tells the two apart.
    """
    authority, _, original = setup(tmp_path)
    sha = authority.status()['ca_sha256']
    registry = (authority.root / 'enrollments.json').read_bytes()

    def crash(state: object) -> None:
        raise SecretsError('audit_failed')
    monkeypatch.setattr(authority, '_update', crash)
    assert_denied(lambda: authority.rotate_ca(expected_ca_sha256=sha),
                  'audit_failed')
    # Nothing was committed: the registry and the selected root are as before.
    assert (authority.root / 'enrollments.json').read_bytes() == registry
    assert authority.status()['ca_sha256'] == sha
    rotations = [records for records in audit_events(authority.root)
                 if records[0]['event'] == 'identity_ca_rotate_intent']
    assert len(rotations) == 1
    # The intent and every revocation were durable before the commit was
    # attempted, and nothing claims the rotation was recorded.
    assert [(row['event'], row['resource'], row['digest'])
            for row in rotations[0]][1:] == [
        ('identity_revoke_intent',
         {'subject': 'vm-original', 'epoch': original['epoch']},
         original['certificate_sha256'])]
