"""Bounded forced-bootstrap CSR operation; no broad bootstrap shell."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm.rc.guest import guestctl as program


def request():
    return program.GuestIdentityCSRRequest('identity-csr', 'lab-agent', 1234,
                                           'a' * 32)


def test_closed_guest_csr_request():
    assert program.GuestIdentityCSRRequest.from_json(request().to_json()) == request()
    for mutation in ({'operation': 'identity-csr', 'guest_user': 'lab-agent',
                      'uid': 0, 'nonce': 'a' * 32},
                     {'operation': 'identity-csr', 'guest_user': 'lab-agent',
                      'uid': 1234, 'nonce': 'bad'},
                     {'operation': 'identity-csr', 'guest_user': 'lab-agent',
                      'uid': 1234, 'nonce': 'a' * 32, 'command': 'cat /etc/shadow'}):
        import json
        with pytest.raises(program.GuestEnrollmentError):
            program.GuestIdentityCSRRequest.from_json(json.dumps(mutation))


def test_guest_executes_only_fixed_programs_as_its_user(monkeypatch):
    monkeypatch.setattr(program.pwd, 'getpwnam', lambda _: SimpleNamespace(
        pw_uid=1234, pw_dir='/home/lab-agent'))
    calls = []
    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs['env'] == {'PATH': '/usr/sbin:/usr/bin:/bin', 'LC_ALL': 'C'}
        assert argv[:5] == ['/usr/sbin/runuser', '-u', 'lab-agent', '--', argv[4]]
        if argv[4:6] == ['/usr/bin/test', '-f']:
            return SimpleNamespace(returncode=1, stdout=b'')
        if argv[4] == '/usr/bin/cat':
            return SimpleNamespace(returncode=0,
                stdout=b'-----BEGIN CERTIFICATE REQUEST-----\nsynthetic\n')
        return SimpleNamespace(returncode=0, stdout=b'')
    monkeypatch.setattr(program.subprocess, 'run', fake_run)
    response = program.prepare_guest_identity_csr(request())
    assert response['nonce'] == 'a' * 32
    assert response['uid'] == 1234
    assert all('/usr/sbin/runuser' == row[0] for row in calls)
    assert any('/usr/bin/openssl' in row for row in calls)
    assert all('sh' not in row and 'bash' not in row for row in calls)


def test_wrong_uid_refused_before_execution(monkeypatch):
    monkeypatch.setattr(program.pwd, 'getpwnam', lambda _: SimpleNamespace(
        pw_uid=5678, pw_dir='/home/lab-agent'))
    monkeypatch.setattr(program.subprocess, 'run', lambda *a, **k: pytest.fail(
        'no external subprocess may execute'))
    with pytest.raises(program.GuestEnrollmentError):
        program.prepare_guest_identity_csr(request())
