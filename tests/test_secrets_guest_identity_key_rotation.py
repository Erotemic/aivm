"""A forced bootstrap rekey never runs an untrusted shell or writes as root."""
from __future__ import annotations

from types import SimpleNamespace
import json

import pytest

from aivm.rc.guest import guestctl as guest


def req():
    return guest.GuestIdentityCSRRequest(
        'identity-key-rotate-csr', 'lab-agent', 1234, 'b' * 32)


def test_request_is_closed_and_names_are_fixed():
    assert guest.GuestIdentityCSRRequest.from_json(req().to_json()) == req()
    for value in (
        dict(operation='identity-key-rotate-csr', guest_user='lab-agent',
             uid=1234, nonce='b'*32, key_path='/tmp/escape'),
        dict(operation='identity-key-rotate-csr', guest_user='lab-agent',
             uid=0, nonce='b'*32),
        dict(operation='identity-key-rotate-csr', guest_user='lab-agent',
             uid=1234, nonce='bad'),
    ):
        with pytest.raises(guest.GuestEnrollmentError):
            guest.GuestIdentityCSRRequest.from_json(json.dumps(value))


def test_staging_requires_active_key_and_certificate_and_never_overwrites(monkeypatch):
    monkeypatch.setattr(guest.pwd, 'getpwnam', lambda _: SimpleNamespace(
        pw_uid=1234, pw_dir='/home/lab-agent'))
    calls = []
    exists = {'client.key', 'client.pem'}
    def run(argv, **kw):
        calls.append(tuple(argv))
        assert argv[:4] == ['/usr/sbin/runuser','-u','lab-agent','--']
        assert kw['env'] == {'PATH':'/usr/sbin:/usr/bin:/bin','LC_ALL':'C'}
        if argv[4:6] == ['/usr/bin/test', '-f']:
            return SimpleNamespace(returncode=int(argv[-1].split('/')[-1] not in exists),stdout=b'')
        if argv[4] == '/usr/bin/cat':
            return SimpleNamespace(returncode=0,stdout=b'-----BEGIN CERTIFICATE REQUEST-----\nTEST\n')
        return SimpleNamespace(returncode=0,stdout=b'')
    monkeypatch.setattr(guest.subprocess, 'run', run)
    response = guest.prepare_guest_identity_csr(req())
    assert response['operation'] == 'identity-key-rotate-csr'
    assert any('/usr/bin/openssl' in row for row in calls)
    assert any('client.rotate.key' in ' '.join(row) for row in calls)
    assert not any('/bin/sh' in row or '/bin/bash' in row for row in calls)
    calls.clear(); exists.add('client.rotate.key')
    with pytest.raises(guest.GuestEnrollmentError):
        guest.prepare_guest_identity_csr(req())
    assert not any('/usr/bin/openssl' in row for row in calls)
    calls.clear(); exists.discard('client.key')
    with pytest.raises(guest.GuestEnrollmentError):
        guest.prepare_guest_identity_csr(req())
    assert not any('/usr/bin/openssl' in row for row in calls)
