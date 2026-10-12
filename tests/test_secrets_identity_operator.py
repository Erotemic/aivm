"""P4a host operator commands and bounded guest client: entirely offline."""
from __future__ import annotations

import json
import os
import stat
import threading
import subprocess
import sys
from pathlib import Path

import pytest

from aivm_secrets.cli import main
from aivm_secrets.errors import SecretsError
from aivm_secrets.host.server import LocalServer
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.service import UnixIdentityService
from tests.secrets_helpers import Harness, REPO


def cli(capsys, *args):
    words = [str(item) for item in args]
    if words[0] in ('request', 'inspect-csr', 'call'):
        code = main(['identity', *words])
        captured = capsys.readouterr()
        output, error = captured.out, captured.err
    else:
        command = [sys.executable, '-I', '-m', 'aivm_secrets', 'identity', *words]
        done = subprocess.run(command, capture_output=True, text=True, timeout=15)
        code, output, error = done.returncode, done.stdout, done.stderr
    return code, json.loads(output) if output else {}, error


def test_host_cli_init_request_inspect_enroll_issue_revoke(tmp_path, capsys):
    root, key, csr = tmp_path / 'authority', tmp_path / 'guest.key', tmp_path / 'guest.csr'
    code, data, err = cli(capsys, 'init', '--root', root,
                          '--issuer', 'aivm.test', '--audience', 'aivm-secrets.identity')
    assert code == 0 and data['subjects'] == {}
    code, req, err = cli(capsys, 'request', '--key', key, '--csr', csr)
    assert code == 0 and len(req['key_fingerprint']) == 64
    code, observed, err = cli(capsys, 'inspect-csr', '--csr', csr)
    assert observed['key_fingerprint'] == req['key_fingerprint']
    # Enrollment needs the exact approved key hash. A mismatched claim fails.
    code, _, err = cli(capsys, 'enroll', '--root', root, '--subject', 'vm-a',
                       '--csr', csr, '--approve-key-fingerprint', '0' * 64)
    assert code == 1
    code, result, err = cli(capsys, 'enroll', '--root', root, '--subject', 'vm-a',
                            '--csr', csr, '--approve-key-fingerprint', req['key_fingerprint'])
    assert code == 0 and Path(result['certificate']).exists()
    assert stat.S_IMODE(Path(result['certificate']).stat().st_mode) == 0o600
    code, status, err = cli(capsys, 'status', '--root', root)
    assert status['subjects']['vm-a']['active'] is True
    harness = Harness(tmp_path)
    try:
        capfile, tokenfile = tmp_path / 'raw-broker.cap', tmp_path / 'bound.jwt'
        capfile.write_text(harness.capability)
        capfile.chmod(0o600)
        code, issue, err = cli(capsys, 'issue', '--root', root, '--subject', 'vm-a',
                               '--capability-file', capfile, '--output', tokenfile)
        assert code == 0 and tokenfile.is_file()
        assert harness.capability not in tokenfile.read_text()
        # Host cannot accidentally overwrite an existing token file.
        code, _, err = cli(capsys, 'issue', '--root', root, '--subject', 'vm-a',
                           '--capability-file', capfile, '--output', tokenfile)
        assert code == 1
        code, revoked, err = cli(capsys, 'revoke', '--root', root, '--subject', 'vm-a')
        assert code == 0 and revoked['active'] is False
    finally:
        harness.broker.close()


def test_guest_client_cli_real_tls_to_host_broker(tmp_path, capsys):
    root, key, csr = tmp_path / 'authority', tmp_path / 'guest.key', tmp_path / 'guest.csr'
    assert cli(capsys, 'init', '--root', root, '--issuer', 'aivm.test')[0] == 0
    _, request, _ = cli(capsys, 'request', '--key', key, '--csr', csr)
    _, enrolled, _ = cli(capsys, 'enroll', '--root', root, '--subject', 'vm-a',
                          '--csr', csr, '--approve-key-fingerprint',
                          request['key_fingerprint'])
    harness = Harness(tmp_path)
    try:
        capfile, tokenfile = tmp_path / 'broker.cap', tmp_path / 'bound.jwt'
        capfile.write_text(harness.capability)
        capfile.chmod(0o600)
        assert cli(capsys, 'issue', '--root', root, '--subject', 'vm-a',
                   '--capability-file', capfile, '--output', tokenfile)[0] == 0
        authority = IdentityAuthority(root)
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            listen = tmp_path / 'bridge' / 'identity.sock'
            with UnixIdentityService(authority=authority,
                                     broker_socket=broker.socket_path,
                                     listen=listen, max_connections=1) as bridge:
                thread = threading.Thread(target=bridge.serve)
                thread.start()
                code, result, err = cli(
                    capsys, 'call', '--socket', listen,
                    '--ca', root / 'ca.pem',
                    '--certificate', enrolled['certificate'],
                    '--key', key, '--jwt-file', tokenfile,
                    '--request', json.dumps({'operation': 'pr.view',
                        'arguments': {'repository': REPO, 'pr': 13861}}))
                assert code == 0 and result['ok'] is True
                assert result['result']['number'] == 13861
                thread.join(timeout=10)
                assert not thread.is_alive()
    finally:
        harness.broker.close()


def test_no_implicit_vm_actions_or_broker_start(tmp_path, capsys):
    root = tmp_path / 'authority'
    cli(capsys, 'init', '--root', root)
    assert not (root / 'broker.sock').exists()
    assert not (root / 'session.sock').exists()
    assert not list(root.glob('*.jwt'))


def test_host_operator_commands_require_isolated_interpreter(tmp_path, capsys):
    unsafe = tmp_path / 'not-created'
    code = main(['identity', 'init', '--root', str(unsafe)])
    assert code == 1
    assert not unsafe.exists()
    assert 'Host file ownership' in capsys.readouterr().err
