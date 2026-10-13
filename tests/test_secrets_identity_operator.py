"""P4a host operator commands and bounded guest client: entirely offline."""
from __future__ import annotations

import argparse
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
                    '--ca', IdentityAuthority(root).tls_paths()[2],
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


ISSUER_API = (Path(__file__).resolve().parent.parent / 'docs' / 'planning' /
              'aivm-secrets-garrett-issuer-api.md')
VERB_CLASSES = {'read-only', 'automation-safe', 'operator-only', 'guest-side'}
# verb -> (every option string it accepts, the option strings it requires)
VerbFlags = dict[str, tuple[frozenset[str], frozenset[str]]]


def _issuer_api_rows() -> list[tuple[str, str, str]]:
    """(command, class, status) for each row of the policy's verb table."""
    rows = []
    inside = False
    for line in ISSUER_API.read_text(encoding='utf-8').splitlines():
        if line.startswith('## '):
            inside = line == '## Verb classification'
        elif inside and line.startswith('| `'):
            cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
            rows.append((cells[0].strip('`'), cells[1], cells[2]))
    return rows


def _identity_verbs(parser: argparse.ArgumentParser) -> VerbFlags:
    """Read the flags of every ``identity`` verb from a real argument parser."""

    def subcommands(
        parent: argparse.ArgumentParser,
    ) -> dict[str, argparse.ArgumentParser]:
        for action in parent._actions:
            if isinstance(action, argparse._SubParsersAction):
                return dict(action.choices)
        raise AssertionError(f'{parent.prog} has no subcommands')

    verbs: VerbFlags = {}
    for verb, sub in subcommands(subcommands(parser)['identity']).items():
        options = [action for action in sub._actions if action.option_strings]
        verbs[verb] = (
            frozenset(flag for action in options
                      for flag in action.option_strings),
            frozenset(flag for action in options if action.required
                      for flag in action.option_strings),
        )
    return verbs


def _verb_table_problems(
    rows: list[tuple[str, str, str]], verbs: VerbFlags,
) -> list[str]:
    """Every way the verb table disagrees with the parser, as messages.

    A row names a verb plus the optional flags that select one of its forms;
    flags the verb always requires are implied, not listed. So a flag that
    any row lists as a form must stay optional: once the parser requires it,
    the rows that omit it name an invocation that no longer parses.
    """
    problems = []
    commands = [command for command, _, _ in rows]
    if len(commands) != len(set(commands)):
        problems.append('duplicate rows')
    form_flags: dict[str, set[str]] = {}
    for command in commands:
        verb, *flags = command.split()
        form_flags.setdefault(verb, set()).update(flags)
    classified = set()
    for command, verb_class, status in rows:
        verb, *flags = command.split()
        if verb_class not in VERB_CLASSES:
            problems.append(f'{command!r}: unknown class {verb_class!r}')
        if status not in {'implemented', 'planned'}:
            problems.append(f'{command!r}: unknown status {status!r}')
        if not all(flag.startswith('--') for flag in flags):
            problems.append(f'{command!r}: a form lists only --flags')
        accepted, required = verbs.get(verb, (frozenset(), frozenset()))
        shipped = verb in verbs and set(flags) <= accepted
        if status == 'implemented':
            classified.add(verb)
            missing = sorted((required & form_flags[verb]) - set(flags))
            if not shipped:
                problems.append(
                    f'{command!r} is marked implemented in {ISSUER_API.name}, '
                    'but the identity CLI does not accept it')
            elif missing:
                problems.append(
                    f'{command!r} is marked implemented in {ISSUER_API.name}, '
                    f'but the identity CLI now requires {missing}: remove or '
                    'reword that row')
        elif shipped:
            problems.append(
                f'{command!r} has shipped: change its Status to implemented '
                f'in {ISSUER_API.name}, and update its "AIVM caller today" '
                'and "Why" cells')
    unclassified = sorted(set(verbs) - classified)
    if unclassified:
        problems.append(
            f'identity verbs missing from {ISSUER_API.name}: {unclassified}')
    return problems


def test_every_identity_verb_has_an_issuer_api_class() -> None:
    """The issuer API policy classifies exactly what the identity CLI accepts.

    This reads the real argument parser, not a copy of its verb list. A verb
    cannot ship unclassified, a row marked ``planned`` cannot stay that way
    once its verb and flags exist, and a row marked ``implemented`` cannot
    outlive the invocation it names: the document must say what is true of
    the code now, and mark only the rest as planned.
    """
    from aivm_secrets.cli import _parser

    assert _verb_table_problems(_issuer_api_rows(),
                                _identity_verbs(_parser())) == []


def _rotate_ca_parser(*, cas_required: bool) -> argparse.ArgumentParser:
    """The smallest parser shaped like ``aivm-secrets identity rotate-ca``."""
    parser = argparse.ArgumentParser(prog='toy')
    identity = parser.add_subparsers(dest='command').add_parser('identity')
    verbs = identity.add_subparsers(dest='identity_action')
    rotate = verbs.add_parser('rotate-ca')
    rotate.add_argument('--root')
    rotate.add_argument('--expected-ca-sha256', required=cas_required)
    return parser


BARE_ROW = ('rotate-ca', 'operator-only', 'implemented')
CAS_ROW = ('rotate-ca --expected-ca-sha256', 'operator-only', 'implemented')
CAS_PLANNED_ROW = ('rotate-ca --expected-ca-sha256', 'operator-only', 'planned')


@pytest.mark.parametrize(('rows', 'cas_required', 'expected'), [
    pytest.param([BARE_ROW, CAS_ROW], False, [], id='both_forms_parse'),
    pytest.param([BARE_ROW, CAS_ROW], True,
                 ["'rotate-ca' is marked", "['--expected-ca-sha256']"],
                 id='bare_row_outlives_a_flag_that_became_required'),
    pytest.param([BARE_ROW, CAS_PLANNED_ROW], False, ['has shipped'],
                 id='planned_row_that_shipped'),
    pytest.param([], False, ['missing from', "['rotate-ca']"],
                 id='unclassified_verb'),
])
def test_the_verb_table_check_reports_each_disagreement(
    rows: list[tuple[str, str, str]], cas_required: bool, expected: list[str],
) -> None:
    """The table check itself, against a parser this test controls.

    The real parser does not yet require any flag a row lists as a form, so
    this pins that the check reports it -- and each other disagreement --
    once one does.
    """
    problems = _verb_table_problems(
        rows, _identity_verbs(_rotate_ca_parser(cas_required=cas_required)))
    if not expected:
        assert problems == []
    else:
        assert len(problems) == 1, problems
        assert all(fragment in problems[0] for fragment in expected), problems
