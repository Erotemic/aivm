"""Mutation gate: removing a security check must turn the suite red.

The assurance plan asks for evidence that the tests are not vacuous: delete a
resource constraint, drop the channel comparison, refund a failed
reservation, allow a redirect, accept a duplicate JSON key -- and the
associated gate must fail. Each ``Mutant`` below is one such deletion, tied
to the theorem it attacks and the test files that are supposed to notice.

For every mutant the package is copied, the one edit is applied, and those
test files are run against the copy. A mutant *survives* if they still pass;
any survivor fails this test. The unmutated copy is run first, so "all
killed" cannot be explained by a broken harness.

Killing these mutants is supporting evidence about the tests. It is not a
completeness argument for the specification, and it is not a proof.
"""

from __future__ import annotations

import py_compile
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

MACHINE = (
    'test_secrets_machine.py',
    'test_secrets_trace.py',
    'test_secrets_vectors.py',
)
BROKER = ('test_secrets_broker.py',)
CHECKS = (
    'test_secrets_https.py',
    'test_secrets_presets.py',
    'test_secrets_vectors.py',
)


@dataclass(frozen=True)
class Mutant:
    theorem: str
    what: str
    path: str
    old: str
    new: str
    tests: tuple[str, ...]


MUTANTS = [
    # -- BIND-01 ------------------------------------------------------------
    Mutant('BIND-01', 'capability binding is not compared with the channel',
           'kernel/machine.py', 'claims.binding != binding\n', 'False\n', MACHINE),
    Mutant('BIND-01', 'channel is not compared with the session',
           'kernel/machine.py', 'or binding != state.binding\n', 'or False\n', MACHINE),
    Mutant('BIND-01', 'policy digest is not compared',
           'kernel/machine.py',
           'or claims.policy_digest != state.policy_digest\n', 'or False\n', MACHINE),
    Mutant('BIND-01', 'the guest socket skips the kernel peer-UID check',
           'host/server.py',
           'if peer_uid(self.request) != server.owner_uid:', 'if False:',
           ('test_secrets_server.py',)),
    # -- REVOKE-01 ----------------------------------------------------------
    Mutant('REVOKE-01', 'a revoked grant is still live',
           'kernel/machine.py',
           "        if not grant.active:\n            raise SecretsError('revoked')",
           '        if False:\n            pass', MACHINE),
    Mutant('REVOKE-01', 'a revoked session still emits effects',
           'kernel/machine.py',
           "    if not state.active:\n        raise SecretsError('revoked')\n    for grant in chain:",
           '    for grant in chain:', MACHINE),
    Mutant('REVOKE-01', 'a revoked session still authenticates',
           'kernel/machine.py',
           "    if not state.active:\n        raise SecretsError('revoked')\n    if (",
           '    if (', MACHINE),
    Mutant('REVOKE-01', 'revoking a grant does not deactivate it',
           'kernel/machine.py',
           'replace(grant, active=False)', 'replace(grant, active=True)', MACHINE),
    # -- TIME-01 ------------------------------------------------------------
    Mutant('TIME-01', 'validity interval is closed at expiry',
           'kernel/machine.py',
           'clock.wall < grant.expires_at:', 'clock.wall <= grant.expires_at:', MACHINE),
    Mutant('TIME-01', 'a grant is valid before it was issued',
           'kernel/machine.py',
           'if not grant.issued_at <= clock.wall < grant.expires_at:',
           'if not clock.wall < grant.expires_at:', MACHINE),
    Mutant('TIME-01', 'the monotonic deadline is ignored',
           'kernel/machine.py', 'if clock.mono >= grant.deadline:', 'if False:', MACHINE),
    Mutant('TIME-01', 'liveness is not re-sampled at the final emission',
           'kernel/machine.py',
           "    _require_live(state, chain, clock)\n    state = replace(state, ticket=replace(ticket, phase='final'))",
           "    state = replace(state, ticket=replace(ticket, phase='final'))", MACHINE),
    # -- BUDGET-01 ----------------------------------------------------------
    Mutant('BUDGET-01', 'one request beyond the budget is admitted',
           'kernel/machine.py',
           'if grant.used >= grant.max_requests:', 'if grant.used > grant.max_requests:',
           MACHINE),
    Mutant('BUDGET-01', 'an admission is not debited',
           'kernel/machine.py',
           'replace(grant, used=grant.used + 1)', 'replace(grant, used=grant.used)', MACHINE),
    Mutant('BUDGET-01', 'children do not debit their ancestors',
           'kernel/machine.py',
           'if grant.grant_id in debited', 'if grant.grant_id == leaf.grant_id', MACHINE),
    Mutant('BUDGET-01', 'the invalid-attempt cap is not enforced',
           'kernel/machine.py', 'if state.attempts >= state.max_attempts:', 'if False:',
           MACHINE + BROKER),
    # -- AUTH-01 ------------------------------------------------------------
    Mutant('AUTH-01', 'arguments are not checked against the grant',
           'kernel/machine.py',
           'if scope.check_arguments(operation, request) > grant.max_body_bytes:',
           'if False:', MACHINE),
    Mutant('AUTH-01', 'writes ignore the host deny mode',
           'kernel/machine.py',
           "        if state.write_mode == 'deny':\n            raise SecretsError('denied')",
           "        if state.write_mode == 'deny':\n            pass", MACHINE + BROKER),
    Mutant('AUTH-01', 'unknown request arguments are accepted',
           'kernel/scope.py',
           "        if name not in parameters and name not in fields:\n            raise SecretsError('invalid_request')",
           '        if False:\n            pass',
           ('test_secrets_scope.py', 'test_secrets_trace.py', 'test_secrets_vectors.py')),
    Mutant('AUTH-01', 'a body field may exceed its byte cap',
           'kernel/scope.py', 'if size > item.max_bytes:', 'if False:',
           ('test_secrets_scope.py', 'test_secrets_trace.py', 'test_secrets_vectors.py')),
    Mutant('AUTH-01', 'a stated fact is not required to hold',
           'kernel/https.py',
           "            if not item.holds(facts, request):\n                raise SecretsError('resource_mismatch')",
           '            if False:\n                pass', CHECKS + BROKER),
    Mutant('AUTH-01', 'a fact of another type can satisfy a requirement',
           'kernel/https.py',
           '        if type(found) is not type(expected):\n            return False\n',
           '', CHECKS),
    Mutant('AUTH-01', 'facts are compared case-insensitively without being told to',
           'kernel/https.py',
           'if self.fold and type(found) is str:', 'if type(found) is str:', CHECKS),
    Mutant('AUTH-01', 'the built-in GitHub manifest does not check the PR author',
           'kernel/presets.py',
           "                    {\n                        'at': ['user', 'login'],\n"
           "                        'equals': login(value['author']),\n"
           "                        'fold': True,\n                    },\n",
           '', ('test_secrets_presets.py', 'test_secrets_vectors.py') + BROKER),
    Mutant('AUTH-01', 'the built-in GitHub manifest does not check the head repository',
           'kernel/presets.py',
           "                    {\n                        'at': ['head', 'repo', 'full_name'],\n"
           "                        'equals': repository(value['head_repository']),\n"
           "                        'fold': True,\n                    },\n",
           '', ('test_secrets_presets.py', 'test_secrets_vectors.py') + BROKER),
    Mutant('AUTH-01', 'a write is classified by its method, not its declaration',
           'kernel/https.py',
           'self.name, self.write, self.parameters, self.body_fields',
           "self.name, self.method != 'GET', self.parameters, self.body_fields",
           CHECKS + MACHINE + BROKER),
    Mutant('AUTH-01', 'non-GraphQL POST/PATCH may be declared read-only',
           'kernel/https.py',
           "            if method != 'GET' and not write and 'graphql' not in value:\n",
           '            if False:\n', CHECKS),
    # -- EFFECT-01 / ROUTE-01 / COMP-01 --------------------------------------
    Mutant('EFFECT-01', 'a ticket can be spent on a different request',
           'kernel/machine.py',
           'or request.digest != ticket.request_digest', 'or False', MACHINE),
    Mutant('EFFECT-01', 'a preflight may be a write',
           'kernel/machine.py',
           "    if effect.is_write:\n        raise SecretsError('denied')",
           '    if effect.is_write:\n        pass', MACHINE),
    Mutant('EFFECT-01', 'a read ticket may emit a write',
           'kernel/machine.py', 'if effect.is_write and not ticket.write:', 'if False:',
           MACHINE),
    Mutant('EFFECT-01', 'a write ticket may end without any effect',
           'kernel/machine.py',
           "        if ticket.write:\n            raise SecretsError('denied')",
           '        if ticket.write:\n            pass', MACHINE),
    Mutant('EFFECT-01', 'a declared write is authorized as if it were a read',
           'kernel/machine.py',
           '        True,\n        ticket.write,\n        effect,',
           '        True,\n        False,\n        effect,', MACHINE),
    Mutant('COMP-01', 'a bound commit hash is not validated before entering a path',
           'kernel/https.py',
           'return grammar.hex_string(folded, len(folded), code=code)', 'return folded',
           CHECKS),
    Mutant('COMP-01', 'a bound segment is not validated before entering a path',
           'kernel/https.py',
           '        return grammar.segment(found, code=code)', '        return found',
           CHECKS),
    Mutant('ROUTE-01', 'dot segments are allowed in a path',
           'kernel/grammar.py', "    if value in ('.', '..'):", '    if False:',
           ('test_secrets_grammar.py', 'test_secrets_model.py', 'test_secrets_https.py')),
    Mutant('ROUTE-01', 'a GET may carry a body',
           'kernel/model.py',
           "if (effect.method == 'GET') != (effect.body is None):", 'if False:',
           ('test_secrets_model.py',)),
    Mutant('ROUTE-01', 'a path placeholder needs no allowlist',
           'kernel/https.py',
           '        if not placed <= declared | captured:', '        if False:', CHECKS),
    Mutant('ROUTE-01', 'an allowlist nothing uses is accepted',
           'kernel/https.py', '        if used != declared:', '        if False:', CHECKS),
    Mutant('ROUTE-01', 'a multi-segment string may be placed in a query',
           'kernel/https.py',
           '_parameter(spec, in_query=key in in_query)', '_parameter(spec, in_query=False)',
           CHECKS),
    Mutant('ROUTE-01', 'a redirect status is treated as success',
           'host/egress.py',
           'if not 200 <= status < 300:', 'if not 200 <= status < 400:',
           ('test_secrets_egress.py',)),
    Mutant('ROUTE-01', 'the executor does not recheck the effect grammar',
           'host/egress.py',
           'effect = check_effect(authorized.effect)', 'effect = authorized.effect',
           ('test_secrets_egress.py',)),
    # -- ATTEN-01 -----------------------------------------------------------
    Mutant('ATTEN-01', 'a delegated scope is not checked to be a subset',
           'kernel/scope.py', '    if not is_subset(child, parent):', '    if False:',
           MACHINE + ('test_secrets_scope.py',)),
    Mutant('ATTEN-01', 'interval subset checks only the lower bound',
           'kernel/scope.py',
           'return parent.low <= child.low and child.high <= parent.high',
           'return parent.low <= child.low', ('test_secrets_scope.py',)),
    Mutant('ATTEN-01', 'a child may claim a larger request budget',
           'kernel/machine.py', 'max_requests > parent.max_requests', 'False', MACHINE),
    Mutant('ATTEN-01', 'a child may outlive its parent',
           'kernel/machine.py',
           'expires_at = min(expires_at, clock.wall + narrowing.lifetime_seconds)',
           'expires_at = clock.wall + narrowing.lifetime_seconds', MACHINE),
    # -- APPROVAL-01 --------------------------------------------------------
    Mutant('APPROVAL-01', 'an approval is not consumed',
           'kernel/machine.py', '            approvals = kept', '            pass', MACHINE),
    Mutant('APPROVAL-01', 'any approval authorizes any write',
           'kernel/machine.py',
           'if item.digest == wanted and clock.wall < item.expires_at',
           'if clock.wall < item.expires_at', MACHINE),
    Mutant('APPROVAL-01', 'approvals never expire',
           'kernel/machine.py',
           'if item.digest == wanted and clock.wall < item.expires_at',
           'if item.digest == wanted', MACHINE),
    # -- CODEC-01 -----------------------------------------------------------
    Mutant('CODEC-01', 'duplicate JSON keys are accepted',
           'kernel/codec.py',
           "        if key in result:\n            raise ValueError('duplicate key')",
           '        if False:\n            pass',
           ('test_secrets_codec.py', 'test_secrets_vectors.py')),
    Mutant('CODEC-01', 'NaN and Infinity are accepted',
           'kernel/codec.py',
           "def _constant(value: str) -> None:\n    raise ValueError('non-finite number')",
           "def _constant(value: str) -> None:\n    return None",
           ('test_secrets_codec.py', 'test_secrets_vectors.py')),
    # -- CONF-01 / AUDIT-01 --------------------------------------------------
    Mutant('CONF-01', 'a reflected credential reaches the guest',
           'host/broker.py',
           'if len(encoded) >= wire.MAX_REPLY or needle in encoded:',
           'if len(encoded) >= wire.MAX_REPLY:', BROKER),
    Mutant('CONF-01', 'a credential resolver inherits the whole environment',
           'host/sources.py',
           "key: os.environ[key] for key in ('HOME', 'PATH') if key in os.environ",
           'key: os.environ[key] for key in os.environ',
           ('test_secrets_sources.py',)),
    Mutant('AUDIT-01', 'dispatch intent is not recorded before dispatch',
           'host/broker.py',
           "            self._record('dispatch', request_id, trace)\n", '            pass\n',
           BROKER),
    Mutant('AUDIT-01', 'an audit failure does not end the session',
           'host/broker.py',
           "        if error.code == 'audit_failed':\n            self._kill()\n        # Once",
           "        if error.code == 'audit_failed':\n            pass\n        # Once",
           BROKER),
    Mutant('AUDIT-01', 'a failed write is reported as a definite error',
           'host/broker.py',
           "if trace.wrote and error.code != 'unreachable':",
           "if False and error.code != 'unreachable':", BROKER),
    Mutant('AUDIT-01', 'the broker classifies a dispatched write by its method',
           'host/broker.py',
           'trace.wrote = final.write', 'trace.wrote = final.effect.is_write', BROKER),
    Mutant('AUDIT-01', 'a write answered 4xx is reported as definitely not applied',
           'host/egress.py', '            if write and sent:', '            if False:',
           ('test_secrets_egress.py',)),
    Mutant('AUDIT-01', 'the executor judges a failure by method, not declaration',
           'host/egress.py',
           '        write = authorized.write\n', '        write = effect.is_write\n',
           ('test_secrets_egress.py',)),
    Mutant('AUDIT-01', 'the audit chain is not checked',
           'host/audit.py', "or row['prev'] != head", 'or False',
           ('test_secrets_audit.py',)),
    # -- host file safety ----------------------------------------------------
    Mutant('FILES', 'a world-writable ancestor directory is trusted',
           'host/files.py',
           "    if info.st_mode & stat.S_IWOTH:\n        raise _unsafe(shown, 'directory is world-writable')",
           '    if False:\n        pass', ('test_secrets_files.py',)),
    Mutant('FILES', 'a group-readable credential file is accepted',
           'host/files.py', '        if info.st_mode & 0o077:', '        if False:',
           ('test_secrets_files.py',)),
    Mutant('FILES', 'a path through a guest-owned link is judged by where it leads',
           'host/files.py',
           '            _refuse_under(candidate, forms, what)\n            info = os.stat(',
           '            info = os.stat(', ('test_secrets_files.py',)),
    Mutant('FILES', 'a directory is created through a guest-owned link before refusal',
           'host/files.py',
           "    outside(path, untrusted, what='directory')\n", '    pass\n',
           ('test_secrets_files.py',)),
    Mutant('FILES', 'an account sharing the primary group goes unnoticed',
           'host/files.py',
           'entry.pw_gid == gid and entry.pw_uid != me.pw_uid', 'False',
           ('test_secrets_files.py',)),
    Mutant('FILES', 'a group is called private without seeing every account',
           'host/files.py',
           'if gid != me.pw_gid or not _accounts_enumerable():', 'if gid != me.pw_gid:',
           ('test_secrets_files.py',)),
    Mutant('FILES', 'a group-writable trusted file is accepted for any group',
           'host/files.py',
           '        if info.st_mode & stat.S_IWGRP and not _private_group(info.st_gid):\n            raise _unsafe(',
           '        if False:\n            raise _unsafe(', ('test_secrets_files.py',)),
    Mutant('FILES', 'a verified resolver is looked up by name again when run',
           'host/sources.py', 'executable=str(program),', 'executable=name,',
           ('test_secrets_sources.py',)),
    # -- the broker's own code ----------------------------------------------
    Mutant('LAUNCH', 'a module search path inside the workspace is accepted',
           'host/hardening.py', '    for entry in sys.path:', '    for entry in ():',
           ('test_secrets_hardening.py',)),
    Mutant('LAUNCH', 'a module already loaded from the workspace is accepted',
           'host/hardening.py',
           '    for name, module in list(sys.modules.items()):',
           '    for name, module in ():', ('test_secrets_hardening.py',)),
]  # fmt: skip

SUPPORT = ('__init__.py', 'secrets_helpers.py')


def build(directory: Path, mutant: Mutant | None) -> None:
    """Copy the package and the tests it needs; apply at most one edit."""
    shutil.copytree(
        ROOT / 'aivm_secrets',
        directory / 'aivm_secrets',
        ignore=shutil.ignore_patterns('__pycache__'),
    )
    tests = directory / 'tests'
    tests.mkdir()
    names = set(SUPPORT) | {name for item in MUTANTS for name in item.tests}
    for name in names:
        shutil.copy(ROOT / 'tests' / name, tests / name)
    shutil.copytree(
        ROOT / 'tests' / 'secrets_vectors', tests / 'secrets_vectors'
    )
    # The shipped manifests are test inputs too.
    shutil.copytree(ROOT / 'docs' / 'examples', directory / 'docs' / 'examples')
    if mutant is None:
        return
    target = directory / 'aivm_secrets' / mutant.path
    source = target.read_text(encoding='utf-8')
    assert source.count(mutant.old) == 1, (
        f'mutant "{mutant.what}" no longer matches {mutant.path} exactly once; '
        'update its snippet so the check it removes is still the one named'
    )
    target.write_text(source.replace(mutant.old, mutant.new), encoding='utf-8')
    # A mutant that does not even compile proves nothing about the tests.
    py_compile.compile(str(target), doraise=True)


def run_tests(
    directory: Path, names: tuple[str, ...]
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            '-P',
            '-m',
            'pytest',
            '-o',
            'addopts=',
            '-q',
            '-x',
            '-p',
            'no:cacheprovider',
            '--no-header',
            *(f'tests/{name}' for name in names),
        ],  # fmt: skip
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=600,
    )


def survives(mutant: Mutant | None) -> tuple[Any, int, str]:
    with tempfile.TemporaryDirectory(prefix='aivm-mutant-') as scratch:
        directory = Path(scratch)
        build(directory, mutant)
        names = (
            mutant.tests
            if mutant
            else tuple(
                sorted({name for item in MUTANTS for name in item.tests})
            )
        )
        # Proof that pytest imported the copy and not the installed package:
        # only the copy leaves this marker behind when it is imported.
        marker = directory / 'imported-the-copy'
        init = directory / 'aivm_secrets' / '__init__.py'
        with init.open('a', encoding='utf-8') as stream:
            stream.write(f'\nopen({str(marker)!r}, "w").close()\n')
        done = run_tests(directory, names)
        assert marker.exists(), (
            'the tests did not run against the copied package'
        )
        return (
            mutant,
            done.returncode,
            done.stdout[-2000:] + done.stderr[-2000:],
        )


def test_removing_a_check_fails_its_gate():
    _, code, output = survives(None)
    assert code == 0, 'the unmutated copy must pass:\n' + output
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(survives, MUTANTS))
    survivors = [
        f'{mutant.theorem}: {mutant.what} ({mutant.path})'
        for mutant, code, _ in results
        if code == 0
    ]
    assert not survivors, 'tests did not notice:\n  ' + '\n  '.join(survivors)
    # Exit status 1 is "tests ran and some failed". Anything else means the
    # mutant broke collection or the run itself, which is not a kill.
    broken = [
        f'{mutant.what}: pytest exited {code}\n{output}'
        for mutant, code, output in results
        if code != 1
    ]
    assert not broken, '\n'.join(broken)


def test_every_named_theorem_has_a_mutant():
    theorems = {mutant.theorem for mutant in MUTANTS}
    assert {
        'AUTH-01', 'EFFECT-01', 'BIND-01', 'TIME-01', 'REVOKE-01', 'BUDGET-01',
        'ATTEN-01', 'APPROVAL-01', 'CODEC-01', 'CONF-01', 'AUDIT-01', 'ROUTE-01',
        'COMP-01', 'FILES', 'LAUNCH',
    } <= theorems  # fmt: skip
    assert len({(m.path, m.old, m.new) for m in MUTANTS}) == len(MUTANTS)
