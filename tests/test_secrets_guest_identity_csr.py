"""Bounded forced-bootstrap CSR operation; no broad bootstrap shell."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Literal

import pytest

from aivm.rc.guest import guestctl as program
from aivm_secrets.identity.certificates import create_csr, inspect_csr


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


# ---------------------------------------------------------------------------
# The helper's exact argv against the real openssl
# ---------------------------------------------------------------------------

needs_openssl = pytest.mark.skipif(
    not Path('/usr/bin/openssl').exists() or os.getuid() == 0,
    reason='needs /usr/bin/openssl and a non-root test user')


def _spki(data: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_private_key,
    )
    if b'PRIVATE KEY' in data:
        key: Any = load_pem_private_key(data, None).public_key()
    else:
        key = x509.load_pem_x509_csr(data).public_key()
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _real_guest(monkeypatch: pytest.MonkeyPatch, home: Path,
                before: Callable[[list[str]], None] | None = None) -> list[list[str]]:
    """Run the helper's commands for real, as this test user.

    ``runuser`` is the guest-root boundary: the test cannot switch users, so
    the prefix is dropped and the exact remaining argv runs with the
    helper's own environment. ``before`` may act just before one runs.
    """
    real_run = subprocess.run
    ran: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        assert argv[:4] == ['/usr/sbin/runuser', '-u', 'lab-agent', '--'], argv
        ran.append(argv[4:])
        if before is not None:
            before(argv[4:])
        return real_run(argv[4:], **kwargs)

    monkeypatch.setattr(program.pwd, 'getpwnam', lambda _: SimpleNamespace(
        pw_uid=os.getuid(), pw_dir=str(home)))
    monkeypatch.setattr(program.subprocess, 'run', run)
    return ran


def _ask(operation: Literal['identity-csr', 'identity-key-rotate-csr'] = 'identity-csr',
         nonce: str = 'a' * 32) -> bytes:
    request = program.GuestIdentityCSRRequest(operation, 'lab-agent', os.getuid(),
                                              nonce)
    return str(program.prepare_guest_identity_csr(request)['csr']).encode('ascii')


@needs_openssl
def test_helper_openssl_argv_yields_csrs_the_authority_accepts(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OpenSSL 3 accepts the helper's argv (``-noenc``) and the CSR enrolls."""
    from aivm_secrets.identity.enrollment import IdentityAuthority

    home = tmp_path / 'home'
    home.mkdir()
    directory = home / '.config' / 'aivm' / 'identity'
    _real_guest(monkeypatch, home)
    first = _ask(nonce='1' * 32)
    key = (directory / 'client.key').read_bytes()
    assert _spki(first) == _spki(key) == _spki((directory / 'client.csr').read_bytes())
    authority = IdentityAuthority.initialize(
        tmp_path / 'authority', issuer='aivm.test', audience='aivm-secrets.identity')
    enrolled = authority.enroll(subject='vm-a', csr=first,
                                approve_fingerprint=inspect_csr(first))
    assert enrolled['epoch'] == 0

    # A cached CSR for some other key (an older rotation, a snapshot) is
    # never handed out again: the reply is re-signed by the installed key.
    create_csr(private_key=tmp_path / 'stale.key', request_file=tmp_path / 'stale.csr')
    (directory / 'client.csr').write_bytes((tmp_path / 'stale.csr').read_bytes())
    second = _ask(nonce='2' * 32)
    assert (directory / 'client.key').read_bytes() == key
    assert _spki(second) == _spki(key) == _spki((directory / 'client.csr').read_bytes())
    renewed = authority.renew_client(
        subject='vm-a', csr=second, approve_fingerprint=inspect_csr(second),
        expected_epoch=0, expected_thumbprint=enrolled['certificate_sha256'])
    assert renewed['epoch'] == 1

    (directory / 'client.pem').write_bytes(b'installed certificate')
    staged = _ask('identity-key-rotate-csr', nonce='3' * 32)
    assert _spki(staged) == _spki((directory / 'client.rotate.key').read_bytes())
    assert _spki(staged) == _spki((directory / 'client.rotate.csr').read_bytes())
    assert _spki(staged) != _spki(key)
    assert authority.rotate_client_key(
        subject='vm-a', csr=staged, approve_fingerprint=inspect_csr(staged),
        expected_epoch=1, expected_thumbprint=renewed['certificate_sha256'],
    )['epoch'] == 2
    assert sorted(path.name for path in directory.iterdir()) == [
        'client.csr', 'client.key', 'client.pem', 'client.rotate.csr',
        'client.rotate.key']


@needs_openssl
def test_losing_the_first_key_race_signs_with_the_winners_key(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / 'home'
    home.mkdir()
    directory = home / '.config' / 'aivm' / 'identity'

    published: list[bytes] = []

    def concurrent_winner(argv: list[str]) -> None:
        # Another identity-csr request publishes its key first. Remember
        # that key as published, so overwriting it is noticed below.
        if argv[0] == '/usr/bin/ln' and not (directory / 'client.key').exists():
            create_csr(private_key=directory / 'client.key',
                       request_file=directory / 'client.csr')
            published.append((directory / 'client.key').read_bytes())

    ran = _real_guest(monkeypatch, home, before=concurrent_winner)
    reply = _ask()
    (winner,) = published
    assert any(argv[0] == '/usr/bin/ln' for argv in ran)
    assert (directory / 'client.key').read_bytes() == winner
    assert _spki(reply) == _spki(winner)
    assert _spki((directory / 'client.csr').read_bytes()) == _spki(winner)
    assert sorted(path.name for path in directory.iterdir()) == [
        'client.csr', 'client.key']


@needs_openssl
def test_losing_a_rotation_race_refuses_and_keeps_the_winners_staging(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / 'home'
    directory = home / '.config' / 'aivm' / 'identity'
    directory.mkdir(parents=True)
    create_csr(private_key=directory / 'client.key',
               request_file=directory / 'client.csr')
    (directory / 'client.pem').write_bytes(b'installed certificate')

    staged: list[bytes] = []

    def concurrent_rotation(argv: list[str]) -> None:
        if (argv[0] == '/usr/bin/ln' and
                not (directory / 'client.rotate.key').exists()):
            create_csr(private_key=directory / 'client.rotate.key',
                       request_file=directory / 'client.rotate.csr')
            staged.append((directory / 'client.rotate.key').read_bytes())

    _real_guest(monkeypatch, home, before=concurrent_rotation)
    with pytest.raises(program.GuestEnrollmentError, match='pending key rotation'):
        _ask('identity-key-rotate-csr')
    (winner,) = staged
    assert (directory / 'client.rotate.key').read_bytes() == winner
    assert _spki((directory / 'client.rotate.csr').read_bytes()) == _spki(winner)
    assert sorted(path.name for path in directory.iterdir()) == [
        'client.csr', 'client.key', 'client.pem', 'client.rotate.csr',
        'client.rotate.key']
