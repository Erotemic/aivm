"""P4a offline host enrollment: no real VM or provider is contacted."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.certificates import create_csr, inspect_csr
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


def test_public_client_returns_only_active_certificate_material(tmp_path):
    import base64
    authority, key, csr, fingerprint = make(tmp_path)
    entry = enroll(authority, csr, fingerprint)
    material = authority.public_client('vm-alpha')
    assert material['subject'] == 'vm-alpha'
    assert material['certificate_sha256'] == entry['certificate_sha256']
    assert base64.b64decode(material['certificate_pem_b64']) == \
        Path(entry['certificate']).read_bytes()
    assert base64.b64decode(material['ca_pem_b64']) == \
        authority.tls_paths()[2].read_bytes()
    serialized = json.dumps(material)
    assert 'PRIVATE KEY' not in serialized
    assert 'issuer.aes256' not in serialized
    authority.revoke('vm-alpha')
    with pytest.raises(SecretsError) as exc:
        authority.public_client('vm-alpha')
    assert exc.value.code == 'revoked'


def files_under(root: Path) -> dict[str, bytes]:
    return {str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob('*')) if path.is_file()}


def audit_records(root: Path) -> list[list[dict]]:
    from aivm_secrets.host.audit import verify
    found = []
    for path in sorted((root / 'audit').glob('*.jsonl')):
        verify(path)
        found.append([json.loads(row) for row in path.read_text().splitlines()])
    return found


def test_a_cloned_key_cannot_gain_a_second_active_subject(tmp_path: Path) -> None:
    authority, _, csr, fingerprint = make(tmp_path)
    first = enroll(authority, csr, fingerprint)
    assert authority.status()['subjects']['vm-alpha']['key_sha256'] == fingerprint
    before = files_under(authority.root)
    with pytest.raises(SecretsError) as exc:
        enroll(authority, csr, fingerprint, subject='vm-clone')
    assert exc.value.code == 'denied'
    assert files_under(authority.root) == before
    # Once the original subject is revoked the key is no longer held by an
    # active subject, so the operator may deliberately move it.
    authority.revoke('vm-alpha')
    moved = enroll(authority, csr, fingerprint, subject='vm-clone')
    assert moved['epoch'] == 0
    assert moved['certificate_sha256'] != first['certificate_sha256']


def test_replace_with_cas_refuses_a_stale_snapshot(tmp_path: Path) -> None:
    authority, _, csr, fingerprint = make(tmp_path)
    old = enroll(authority, csr, fingerprint)
    newer = enroll(authority, csr, fingerprint, replace=True)
    before = files_under(authority.root)
    with pytest.raises(SecretsError) as exc:
        enroll(authority, csr, fingerprint, replace=True,
               expected_epoch=old['epoch'],
               expected_thumbprint=old['certificate_sha256'])
    assert exc.value.code == 'revoked'
    for partial in ({'expected_epoch': newer['epoch']},
                    {'expected_thumbprint': newer['certificate_sha256']},
                    {'expected_epoch': newer['epoch'],
                     'expected_thumbprint': newer['certificate_sha256'],
                     'replace': False}):
        with pytest.raises(SecretsError) as exc:
            enroll(authority, csr, fingerprint, **{'replace': True, **partial})
        assert exc.value.code == 'invalid_capability'
    assert files_under(authority.root) == before
    current = enroll(authority, csr, fingerprint, replace=True,
                     expected_epoch=newer['epoch'],
                     expected_thumbprint=newer['certificate_sha256'])
    assert current['epoch'] == newer['epoch'] + 1
    # A CAS also names an inactive row, which is what follows rotate-ca.
    authority.revoke('vm-alpha')
    row = authority.status()['subjects']['vm-alpha']
    again = enroll(authority, csr, fingerprint, replace=True,
                   expected_epoch=row['epoch'],
                   expected_thumbprint=row['certificate_sha256'])
    assert again['epoch'] == row['epoch'] + 1


def test_revoking_at_the_maximum_epoch_still_deactivates(tmp_path: Path) -> None:
    """B10: the row is hand-edited to the edge no transition can reach."""
    import time
    authority, _, csr, fingerprint = make(tmp_path)
    entry = enroll(authority, csr, fingerprint)
    path = authority.root / 'enrollments.json'
    data = json.loads(path.read_text())
    data['subjects']['vm-alpha']['epoch'] = 2**31 - 1
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    now = int(time.time())
    peer = der_of(entry['certificate'])
    assert authority.expectation_for_peer(peer, now).epoch == 2**31 - 1
    assert authority.revoke('vm-alpha') == {
        'subject': 'vm-alpha', 'epoch': 2**31 - 1, 'active': False}
    with pytest.raises(SecretsError) as exc:
        authority.expectation_for_peer(peer, now)
    assert exc.value.code == 'invalid_capability'
    with pytest.raises(SecretsError) as exc:
        enroll(authority, csr, fingerprint)
    assert exc.value.code == 'exhausted'


def test_prune_frees_every_expired_revoked_slot(tmp_path: Path) -> None:
    """B9: 128 enroll+revoke cycles used to exhaust the registry for good."""
    from aivm_secrets.identity.enrollment import CLIENT_DAYS, MAX_SUBJECTS
    start = 1_700_000_000
    authority = IdentityAuthority.initialize(
        tmp_path / 'authority', issuer='aivm.test',
        audience='aivm-secrets.identity', now=start)
    key, csr = tmp_path / 'k.pem', tmp_path / 'k.csr'
    fingerprint = create_csr(private_key=key, request_file=csr)
    for n in range(MAX_SUBJECTS):
        authority.enroll(subject=f'vm-{n}', csr=csr.read_bytes(),
                         approve_fingerprint=fingerprint, now=start)
        authority.revoke(f'vm-{n}', now=start)
    with pytest.raises(SecretsError) as exc:
        authority.enroll(subject='vm-new', csr=csr.read_bytes(),
                         approve_fingerprint=fingerprint, now=start)
    assert exc.value.code == 'exhausted'
    # Before the certificates expire there is nothing to forget or write.
    files = files_under(authority.root)
    assert authority.prune(now=start + 60) == {'forgotten': []}
    assert files_under(authority.root) == files
    later = start + CLIENT_DAYS * 86400 + 60
    result = authority.prune(now=later)
    assert [item['subject'] for item in result['forgotten']] == sorted(
        f'vm-{n}' for n in range(MAX_SUBJECTS))
    assert all(item['epoch'] == 1 for item in result['forgotten'])
    assert authority.status()['subjects'] == {}
    fresh = authority.enroll(subject='vm-new', csr=csr.read_bytes(),
                             approve_fingerprint=fingerprint, now=later)
    assert fresh['epoch'] == 0
    assert set(authority.status()['subjects']) == {'vm-new'}
    pruned = [records for records in audit_records(authority.root)
              if records[0]['event'] == 'identity_prune_intent']
    assert len(pruned) == 1
    assert [row['event'] for row in pruned[0]] == (
        ['identity_prune_intent'] + ['identity_forget_intent'] * MAX_SUBJECTS
        + ['identity_recorded'])
    assert pruned[0][1]['resource'] == {'subject': 'vm-0', 'epoch': 1}


def test_forget_only_an_inactive_expired_row(tmp_path: Path) -> None:
    from aivm_secrets.identity.enrollment import CLIENT_DAYS
    start = 1_700_000_000
    authority = IdentityAuthority.initialize(
        tmp_path / 'authority', issuer='aivm.test',
        audience='aivm-secrets.identity', now=start)
    key, csr = tmp_path / 'k.pem', tmp_path / 'k.csr'
    fingerprint = create_csr(private_key=key, request_file=csr)
    entry = authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                             approve_fingerprint=fingerprint, now=start)
    expired = entry['not_after']
    before = files_under(authority.root)
    for subject in ('vm-alpha', 'vm-missing'):   # active; unknown
        with pytest.raises(SecretsError) as exc:
            authority.forget(subject, now=expired + 1)
        assert exc.value.code == 'denied'
    assert files_under(authority.root) == before
    authority.revoke('vm-alpha', now=start)
    revoked = files_under(authority.root)
    with pytest.raises(SecretsError) as exc:
        authority.forget('vm-alpha', now=expired - 1)   # not yet expired
    assert exc.value.code == 'denied'
    assert files_under(authority.root) == revoked
    assert authority.forget('vm-alpha', now=expired) == {'forgotten': [{
        'subject': 'vm-alpha', 'epoch': 1,
        'certificate_sha256': entry['certificate_sha256']}]}
    assert authority.status()['subjects'] == {}
    # The public certificate is kept; only the registry row is gone.
    assert Path(entry['certificate']).is_file()
    forgot = [records for records in audit_records(authority.root)
              if records[0]['event'] == 'identity_forget_intent']
    assert [row['event'] for row in forgot[0]] == [
        'identity_forget_intent', 'identity_recorded']
    assert forgot[0][0]['digest'] == entry['certificate_sha256']
    # The subject restarts at epoch 0 with no retired keys: harmless, because
    # the forgotten certificate (and every token bound to it) has expired.
    again = authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                             approve_fingerprint=fingerprint,
                             now=expired + CLIENT_DAYS)
    assert again['epoch'] == 0


def test_prune_audits_each_forgotten_row_before_the_registry_commit(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fault injection at the registry commit, as a crash there would be."""
    from aivm_secrets.identity.enrollment import CLIENT_DAYS
    start = 1_700_000_000
    authority = IdentityAuthority.initialize(
        tmp_path / 'authority', issuer='aivm.test',
        audience='aivm-secrets.identity', now=start)
    key, csr = tmp_path / 'k.pem', tmp_path / 'k.csr'
    fingerprint = create_csr(private_key=key, request_file=csr)
    entry = authority.enroll(subject='vm-alpha', csr=csr.read_bytes(),
                             approve_fingerprint=fingerprint, now=start)
    authority.revoke('vm-alpha', now=start)
    registry = (authority.root / 'enrollments.json').read_bytes()

    def crash(state: object) -> None:
        raise SecretsError('audit_failed')
    monkeypatch.setattr(authority, '_update', crash)
    with pytest.raises(SecretsError) as exc:
        authority.prune(now=start + CLIENT_DAYS * 86400 + 60)
    assert exc.value.code == 'audit_failed'
    assert (authority.root / 'enrollments.json').read_bytes() == registry
    pruned = [records for records in audit_records(authority.root)
              if records[0]['event'] == 'identity_prune_intent']
    assert len(pruned) == 1
    # Each forgotten row was durable before the commit was attempted, and
    # nothing claims the prune was recorded.
    assert [(row['event'], row['resource'], row['digest'])
            for row in pruned[0]][1:] == [
        ('identity_forget_intent', {'subject': 'vm-alpha', 'epoch': 1},
         entry['certificate_sha256'])]


def test_custody_refusals_name_the_rule_but_not_the_other_subject(
        tmp_path: Path) -> None:
    authority, _, csr, fingerprint = make(tmp_path)
    first = enroll(authority, csr, fingerprint)
    with pytest.raises(SecretsError) as exc:
        enroll(authority, csr, fingerprint, subject='vm-renamed')
    assert (exc.value.code, exc.value.detail) == (
        'denied', 'key is certified for another active subject')
    assert 'vm-alpha' not in exc.value.for_operator()
    second_key, second_csr = tmp_path / 'second.key', tmp_path / 'second.csr'
    second = create_csr(private_key=second_key, request_file=second_csr)
    authority.rotate_client_key(
        subject='vm-alpha', csr=second_csr.read_bytes(),
        approve_fingerprint=second, expected_epoch=first['epoch'],
        expected_thumbprint=first['certificate_sha256'])
    with pytest.raises(SecretsError) as exc:
        enroll(authority, csr, fingerprint, replace=True)
    assert (exc.value.code, exc.value.detail) == (
        'denied', 'key is retired for this subject')


def test_forgetting_a_row_discards_its_retired_key_custody(
        tmp_path: Path) -> None:
    """The documented limit of REG-02, pinned so the docs stay true.

    A VM that still exists keeps its subject. Once its revoked, expired row
    is forgotten, a key it rotated away from is no longer retired for it.
    """
    from aivm_secrets.identity.enrollment import CLIENT_DAYS
    start = 1_700_000_000
    authority = IdentityAuthority.initialize(
        tmp_path / 'authority', issuer='aivm.test',
        audience='aivm-secrets.identity', now=start)
    old_key, old_csr = tmp_path / 'old.key', tmp_path / 'old.csr'
    old = create_csr(private_key=old_key, request_file=old_csr)
    new_key, new_csr = tmp_path / 'new.key', tmp_path / 'new.csr'
    new = create_csr(private_key=new_key, request_file=new_csr)
    first = authority.enroll(subject='vm-alpha', csr=old_csr.read_bytes(),
                             approve_fingerprint=old, now=start)
    authority.rotate_client_key(
        subject='vm-alpha', csr=new_csr.read_bytes(), approve_fingerprint=new,
        expected_epoch=first['epoch'],
        expected_thumbprint=first['certificate_sha256'], now=start)
    authority.revoke('vm-alpha', now=start)
    with pytest.raises(SecretsError) as exc:
        authority.enroll(subject='vm-alpha', csr=old_csr.read_bytes(),
                         approve_fingerprint=old, now=start)
    assert exc.value.code == 'denied'
    later = start + CLIENT_DAYS * 86400 + 60
    assert [item['subject'] for item in authority.prune(now=later)['forgotten']
            ] == ['vm-alpha']
    again = authority.enroll(subject='vm-alpha', csr=old_csr.read_bytes(),
                             approve_fingerprint=old, now=later)
    assert again['epoch'] == 0
    assert authority.status()['subjects']['vm-alpha']['key_sha256'] == old
