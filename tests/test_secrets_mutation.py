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
IDENTITY_BRIDGE = ('test_secrets_identity_service.py',)
# The OAuth token client's request, between its "sent" mark and the reply.
_TOKEN_REQUEST = (
    "            conn.request('POST', target, data, {\n"
    "                'Host': host, 'Accept': 'application/json',\n"
    "                'Content-Type': 'application/x-www-form-urlencoded',\n"
    "                'Cache-Control': 'no-store',\n"
    '            })\n'
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
    # -- CA-01/CA-04: single active trust root -----------------------------
    Mutant('CA-01', 'CA generation can be reused rather than advanced',
           'identity/garrett/authority.py',
           "grammar.integer(ca_generation, current['ca']['generation'] + 1,",
           "grammar.integer(ca_generation, 1,",
           ('test_secrets_authority_parity.py',)),
    Mutant('CA-01', 'CA key fingerprint need not change on rollover',
           'identity/garrett/authority.py',
           "if ca_sha256 == current['ca']['sha256']:",
           'if False:', ('test_secrets_authority_parity.py',)),
    Mutant('CA-04', 'old bound bridges ignore a changed root manifest',
           'identity/enrollment.py',
           '        self._assert_current_ca()\n        thumb = certificate_thumbprint(der)',
           '        thumb = certificate_thumbprint(der)',
           ('test_secrets_ca_rotation.py',)),

    # -- independent primitive and Garrett protocol contracts ---------------
    Mutant('PRIM-BIND-01', 'certificate binding equality is ignored',
           'primitives/binding.py', 'or actual != expected):',
           'or False):', ('test_secrets_garrett_modularity.py',)),
    Mutant('PRIM-TIME-01', 'identity expiry becomes inclusive',
           'primitives/validity.py', 'not not_before <= now < expires_at):',
           'not not_before <= now <= expires_at):',
           ('test_secrets_garrett_modularity.py',)),
    Mutant('PRIM-EPOCH-01', 'an exhausted enrollment epoch wraps or advances',
           'primitives/epochs.py', '    if current == maximum:',
           '    if False:', ('test_secrets_garrett_modularity.py',)),
    Mutant('GARRETT-ISSUE-01', 'issuance ignores enrollment revocation',
           'identity/garrett/protocol.py',
           "if record is None or not record['active'] or now >= record['not_after']:",
           "if record is None or now >= record['not_after']:",
           ('test_secrets_garrett_modularity.py',)),
    Mutant('PRIM-EPOCH-01', 'an epoch maximum no i64 holds is accepted',
           'primitives/epochs.py',
           '            or not 0 <= maximum <= MAX_VALUE\n',
           '            or maximum < 0\n', ('test_secrets_primitives_parity.py',)),
    Mutant('PRIM-EPOCH-01', 'an epoch no i64 holds is compared',
           'primitives/epochs.py',
           'or not 0 <= actual <= MAX_VALUE or actual != expected):',
           'or actual < 0 or actual != expected):',
           ('test_secrets_primitives_parity.py',)),
    Mutant('PRIM-TIME-01', 'an identity claim may expire at 2**63, past any i64',
           'identity/garrett/claims.py',
           "grammar.integer(data['iat'], 0, MAX_ISSUED_AT,",
           "grammar.integer(data['iat'], 0, MAX_ISSUED_AT + 1,",
           ('test_secrets_identity_parity.py',)),
    # -- Garrett OAuth: refresh outcome, callback and contract parity ---------
    Mutant('GARRETT-OAUTH-REFRESH-01', 'an in-doubt refresh token is presented again',
           'identity/oauth_vault.py',
           "    if state == 'in_doubt':\n        raise SecretsError('credential_source', detail=REFRESH_IN_DOUBT)",
           "    if False:\n        raise SecretsError('credential_source', detail=REFRESH_IN_DOUBT)",
           ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'the in-doubt marker is not durable before the request',
           'identity/oauth_vault.py',
           "            self._write(provider, subject, {**row, 'refresh_state': 'in_doubt'})\n",
           '            pass\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'an unsent retry forgets the earlier unknown outcome',
           'identity/oauth_vault.py',
           "REFRESH_NOT_SENT: (prior, 'oauth_refresh_not_sent')",
           "REFRESH_NOT_SENT: ('none', 'oauth_refresh_not_sent')",
           ('test_secrets_garrett_oauth_https.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'any invalid_grant counts as a definite rejection',
           'identity/garrett/oauth_contract.py',
           "    if status == 400 and oauth_error == 'invalid_grant':",
           "    if oauth_error == 'invalid_grant':",
           ('test_secrets_garrett_oauth_parity.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'a request whose reply was lost counts as never sent',
           'identity/oauth_transport.py',
           "            sent = True\n" + _TOKEN_REQUEST + "            resp = conn.getresponse()\n",
           _TOKEN_REQUEST + "            resp = conn.getresponse()\n            sent = True\n",
           ('test_secrets_garrett_oauth_https.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'a definitely rejected grant stays usable',
           'identity/oauth_vault.py',
           "REFRESH_REJECTED: ('reauth_required', 'oauth_refresh_rejected')",
           "REFRESH_REJECTED: (prior, 'oauth_refresh_rejected')",
           ('test_secrets_garrett_oauth_https.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'a record that needs reauthorization is used',
           'identity/oauth_vault.py', "    if state == 'reauth_required':",
           '    if False:', ('test_secrets_garrett_oauth_https.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'an unstorable successor is an unexplained, unaudited failure',
           'identity/oauth_vault.py', '                raise self._in_doubt(note, 0) from None\n',
           '                raise\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'an unstorable settled outcome is an unexplained, unaudited failure',
           'identity/oauth_vault.py',
           '            except Exception:\n                return self._in_doubt(note, status)\n',
           '            except Exception:\n                raise\n',
           ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-REFRESH-01', 'the last generation spends its refresh token on an unacceptable reply',
           'identity/oauth_transport.py', '    if previous.generation >= MAX_GENERATION:\n',
           '    if False:\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-LOGIN-01', 'a login runs the browser flow for a subject the vault refuses',
           'identity/cli.py',
           '    vault.can_enroll(provider, args.subject, replace=args.replace)\n', '',
           ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-LOGIN-01', 'the authorization expires at 180 s whatever --timeout says',
           'identity/cli.py', '    pending = new_pending(provider, ttl=args.timeout)\n',
           '    pending = new_pending(provider)\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-LOGIN-01', 'an exchange that may have minted a grant is not reported as orphaned',
           'identity/cli.py', '        if error.detail == EXCHANGE_IN_DOUBT:',
           '        if False:', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-LOGIN-01', 'an unusable 200 exchange reply carries no reason',
           'identity/oauth_transport.py',
           "    except SecretsError:\n        raise SecretsError('credential_source',\n"
           "                           detail=EXCHANGE_IN_DOUBT) from None",
           '    except SecretsError:\n        raise',
           ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-REVOKE-01', 'revocation at the maximum epoch fails open',
           'identity/oauth_vault.py',
           '                if epoch < MAX_EPOCH:\n                    epoch += 1\n',
           '                epoch += 1\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-CALLBACK-01', 'an error callback for another authorization ends the login',
           'identity/garrett/oauth_contract.py',
           "    if parameters['state'] != pending.state:",
           "    if outcome == 'code' and parameters['state'] != pending.state:",
           ('test_secrets_garrett_oauth_parity.py',)),
    Mutant('GARRETT-OAUTH-CALLBACK-01', 'a provider denial waits out the timeout',
           'identity/oauth_transport.py', '            if self.denied:',
           '            if False:', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-CALLBACK-01', 'an idle local connection holds the callback open',
           'identity/oauth_transport.py', '                self._watchdog.start()\n',
           '                pass\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-CALLBACK-01', 'a full RFC 9207 error response is refused as malformed',
           'identity/oauth_transport.py', 'strict_parsing=True, max_num_fields=5)',
           'strict_parsing=True, max_num_fields=4)', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-PARITY-01', 'scopes split on Python whitespace',
           'identity/garrett/oauth_contract.py', '        if char in SCOPE_SEPARATORS:',
           "        if char.isspace() or char == ',':",
           ('test_secrets_garrett_oauth_parity.py',)),
    Mutant('GARRETT-OAUTH-PARITY-01', 'a PKCE verifier or state may be shorter than RFC 7636 allows',
           'identity/garrett/oauth_contract.py',
           'not MIN_PKCE <= len(value) <= MAX_PKCE',
           'not 1 <= len(value) <= MAX_PKCE',
           ('test_secrets_garrett_oauth_parity.py', 'test_secrets_garrett_oauth.py')),
    # The runner's own list and string checks on allowed_scopes and
    # expected_issuer have no mutant: the contract makes the same refusal
    # with the same code, so deleting either copy alone is an equivalent
    # mutant. The contract's copies below are the ones a port transcribes.
    Mutant('GARRETT-OAUTH-PARITY-01', 'a falsy non-string issuer reads as "no issuer expected"',
           'identity/garrett/oauth_contract.py', '    if type(expected_issuer) is not str:\n',
           '    if False:\n', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-PARITY-01', 'a string allowed_scopes is read as one-letter scopes',
           'identity/garrett/oauth_contract.py', '    if type(raw) is not list or len(raw) > 32:',
           '    if len(raw) > 32:', ('test_secrets_garrett_oauth.py',)),
    Mutant('GARRETT-OAUTH-PARITY-01', 'the runner reads a boolean expiry as an integer',
           'identity/oauth_runner.py',
           "            expires = grammar.integer(val['expires_at'], 0, MAX_TIME,\n"
           "                                      code='credential_source')",
           "            expires = val['expires_at']",
           ('test_secrets_garrett_oauth_parity.py',)),
    Mutant('GARRETT-OAUTH-PARITY-01', 'provider error text is measured in characters, not UTF-8 bytes',
           'identity/garrett/oauth_contract.py',
           '            grammar.text(parameters[name], MAX_ERROR_TEXT,\n'
           "                         code='credential_source')",
           '            if len(parameters[name]) > MAX_ERROR_TEXT:\n'
           "                raise SecretsError('credential_source')",
           ('test_secrets_garrett_oauth_parity.py',)),
    Mutant('GARRETT-OAUTH-PARITY-01', 'a classified error value may hold any character',
           'identity/garrett/oauth_contract.py',
           """        if not ' ' <= char <= '~' or char == '"' or char == '\\\\':""",
           '        if False:', ('test_secrets_garrett_oauth_parity.py',)),
    Mutant('GARRETT-OAUTH-TLS-01', 'the token client trusts SSL_CERT_FILE / SSL_CERT_DIR',
           'identity/oauth_transport.py',
           '    context.load_verify_locations(cafile=cafile, capath=capath)',
           '    context.load_default_certs(ssl.Purpose.SERVER_AUTH)',
           ('test_secrets_garrett_oauth_https.py',)),
    Mutant('GARRETT-OAUTH-TLS-01', 'the token client trusts SSL_CERT_FILE',
           'identity/oauth_transport.py',
           '    cafile = paths.openssl_cafile if os.path.isfile(paths.openssl_cafile) else None\n',
           '    cafile = paths.cafile\n', ('test_secrets_garrett_oauth_https.py',)),
    Mutant('GARRETT-OAUTH-TLS-01', 'the token client trusts a hashed SSL_CERT_DIR',
           'identity/oauth_transport.py',
           '    capath = paths.openssl_capath if os.path.isdir(paths.openssl_capath) else None\n',
           '    capath = paths.capath\n', ('test_secrets_garrett_oauth_https.py',)),
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
           'primitives/grammar.py', "    if value in ('.', '..'):", '    if False:',
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
           'primitives/codec.py',
           "        if key in result:\n            raise ValueError('duplicate key')",
           '        if False:\n            pass',
           ('test_secrets_codec.py', 'test_secrets_vectors.py')),
    Mutant('CODEC-01', 'NaN and Infinity are accepted',
           'primitives/codec.py',
           "def _constant(value: str) -> None:\n    raise ValueError('non-finite number')",
           "def _constant(value: str) -> None:\n    return None",
           ('test_secrets_codec.py', 'test_secrets_vectors.py')),
    Mutant('CODEC-01', 'a lone surrogate escape is accepted',
           'primitives/codec.py',
           '        _check_text(value)\n        return value',
           '        return value',
           ('test_secrets_codec.py', 'test_secrets_vectors.py')),
    Mutant('CODEC-01', 'a float is digested',
           'primitives/codec.py',
           '        elif item is not None and kind is not bool:\n',
           '        elif False:\n',
           ('test_secrets_codec.py', 'test_secrets_primitives_parity.py')),
    Mutant('CODEC-01', 'an integer no i64 holds is digested',
           'primitives/codec.py',
           '            if not MIN_INTEGER <= item <= MAX_INTEGER:',
           '            if False:',
           ('test_secrets_codec.py', 'test_secrets_primitives_parity.py')),
    # No runner input reaches these three: loads refuses a lone surrogate and
    # decodes only string keys first. Only the unit tests can kill them.
    Mutant('CODEC-01', 'a non-string object key is digested',
           'primitives/codec.py',
           "                if type(key) is not str:\n"
           "                    raise TypeError('object key is not a string')\n"
           "                _scalar_text(key)\n",
           "                if type(key) is str:\n"
           "                    _scalar_text(key)\n",
           ('test_secrets_codec.py',)),
    Mutant('CODEC-01', 'a lone surrogate in a digested string is digested',
           'primitives/codec.py',
           '        if kind is str:\n            _scalar_text(item)\n',
           '        if kind is str:\n            pass\n',
           ('test_secrets_codec.py',)),
    Mutant('CODEC-01', 'a lone surrogate in a digested key is digested',
           'primitives/codec.py',
           "                    raise TypeError('object key is not a string')\n"
           "                _scalar_text(key)\n",
           "                    raise TypeError('object key is not a string')\n",
           ('test_secrets_codec.py',)),
    Mutant('CODEC-01', 'a capability is bounded in code points, not UTF-8 bytes',
           'primitives/wire.py',
           'return grammar.byte_length(capability) <= MAX_CAPABILITY',
           'return len(capability) <= MAX_CAPABILITY',
           ('test_secrets_wire.py', 'test_secrets_primitives_parity.py')),
    Mutant('CODEC-01', 'a capability with no UTF-8 encoding is accepted',
           'primitives/wire.py',
           '    except UnicodeError:\n        return False',
           '    except UnicodeError:\n        return True',
           ('test_secrets_wire.py',)),
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
    Mutant('AUDIT-01', 'the identity bridge calls an unanswered dispatch malformed',
           'identity/service.py',
           "            except Exception:\n"
           "                raise SecretsError('outcome_unknown') from None\n"
           "        if type(result) is not dict:\n"
           "            raise SecretsError('outcome_unknown')",
           "            except Exception:\n"
           "                raise SecretsError('invalid_request') from None\n"
           "        if type(result) is not dict:\n"
           "            raise SecretsError('invalid_request')",
           IDENTITY_BRIDGE),
    # -- the identity bridge's wiring ----------------------------------------
    Mutant('BIND-01', 'a bridge pinned to one subject serves any enrolled one',
           'identity/mtls.py',
           '        if self._subject is not None and (\n'
           '                expected is None or expected.subject != self._subject):',
           '        if False:', IDENTITY_BRIDGE),
    Mutant('BRIDGE', 'the bridge may forward to a socket not named broker.sock',
           'identity/service.py',
           "        if self.path.name != GUEST_SOCKET:\n            raise SecretsError('unsafe_file')",
           "        if False:\n            raise SecretsError('unsafe_file')",
           IDENTITY_BRIDGE),
    Mutant('BRIDGE', 'the broker socket is judged only when the bridge starts',
           'identity/service.py',
           '        # for a link or loosened since the bridge started.\n'
           '        self._validate()\n',
           '        # for a link or loosened since the bridge started.\n',
           IDENTITY_BRIDGE),
    Mutant('AUDIT-01', 'bound_call calls a refused certificate an unknown outcome',
           'identity/client.py',
           '            if not data and _refused_handshake(ex):\n'
           "                raise SecretsError('unreachable') from None\n",
           '', IDENTITY_BRIDGE),
    # -- the identity bridge's lifetime --------------------------------------
    Mutant('BRIDGE', 'a bridge exits without letting the answers in flight out',
           'identity/service.py',
           '        self._drain(workers, should_stop, stopping)\n', '',
           IDENTITY_BRIDGE),
    Mutant('BRIDGE', 'a bridge whose lease closed keeps listening while it drains',
           'identity/service.py',
           '        self._close_listener()\n'
           '        self._drain(workers, should_stop, stopping)\n',
           '        self._drain(workers, should_stop, stopping)\n',
           IDENTITY_BRIDGE),
    Mutant('BRIDGE', 'a bridge whose lease closed waits out a slow provider',
           'identity/service.py',
           '            self.stop_drain if stopping else DRAIN_SECONDS)',
           '            DRAIN_SECONDS)', IDENTITY_BRIDGE),
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
    # -- REN-07: renewal re-certifies only the enrolled key ------------------
    Mutant('REN-07', 'renewal accepts a different key',
           'identity/garrett/key_rotation.py',
           "    if enrolled_key_fingerprint != candidate_key_fingerprint:\n        raise SecretsError('denied')",
           "    if False:\n        raise SecretsError('denied')",
           ('test_secrets_identity_key_rotation_parity.py',
            'test_secrets_identity_lifecycle.py')),
    Mutant('REN-07', 'the host renews without the same-key rule',
           'identity/enrollment.py',
           '                authorize_key_reuse(enrolled_key_fingerprint=enrolled,\n'
           '                                    candidate_key_fingerprint=fp)',
           '                pass', ('test_secrets_identity_lifecycle.py',)),
    Mutant('REN-07', 'the enrolled key is not checked against the registry',
           'identity/enrollment.py',
           "            if enrolled != row['key_sha256']:",
           '            if False:', ('test_secrets_identity_lifecycle.py',)),
    # -- REN-08: key fingerprint custody ---------------------------------------
    Mutant('REN-08', 'a key retired for a subject is certified for it again',
           'identity/garrett/registry.py',
           "    if prior is not None and key_sha256 in prior['retired_keys']:\n",
           '    if False:\n',
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_lifecycle.py')),
    Mutant('REN-08', "another active subject's key is certified for a second subject",
           'identity/garrett/registry.py',
           "        if name != subject and row['active'] and row['key_sha256'] == key_sha256:",
           '        if False:',
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_enrollment.py')),
    Mutant('REN-08', 'a replaced key is not retired',
           'identity/garrett/registry.py',
           "    if prior['key_sha256'] != key_sha256:\n        kept.append(prior['key_sha256'])",
           "    if False:\n        kept.append(prior['key_sha256'])",
           ('test_secrets_identity_registry_parity.py',)),
    Mutant('REN-08', 'the retired-key list is not bounded',
           'identity/garrett/registry.py',
           '    if len(kept) > MAX_RETIRED_KEYS:', '    if False:',
           ('test_secrets_identity_registry_parity.py',)),
    Mutant('REN-08', 'a registry with one key on two active rows is accepted',
           'identity/garrett/registry.py',
           "            if current in active_keys:\n                raise SecretsError('invalid_capability')",
           "            if False:\n                raise SecretsError('invalid_capability')",
           ('test_secrets_identity_registry_parity.py',)),
    Mutant('REN-08', 'enroll --replace ignores its compare-and-swap',
           'identity/garrett/registry.py',
           "    if (prior is None or prior['epoch'] != expected_epoch or\n"
           "            prior['certificate_sha256'] != expected_thumbprint):",
           '    if prior is None:',
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_enrollment.py')),
    Mutant('REN-08', 'a partial enroll CAS becomes an unconditional replace',
           'identity/enrollment.py',
           '        if type(replace) is not bool or (cas and (\n'
           '                not replace or type(expected_epoch) is not int or\n'
           '                type(expected_thumbprint) is not str)):',
           '        if type(replace) is not bool:',
           ('test_secrets_identity_enrollment.py',)),
    Mutant('REN-08', 'a registry with an unbounded retired-key list is accepted',
           'identity/garrett/registry.py',
           '        if type(retired) is not list or len(retired) > MAX_RETIRED_KEYS:',
           '        if type(retired) is not list:',
           ('test_secrets_identity_registry_parity.py',)),
    Mutant('REN-08', "a registry that retires a row's current key is accepted",
           'identity/garrett/registry.py',
           '            if _key(item) == current or item in seen:',
           "            if _key(item) == '' or item in seen:",
           ('test_secrets_identity_registry_parity.py',)),
    Mutant('REN-08', 'a registry with a duplicate retired key is accepted',
           'identity/garrett/registry.py',
           '            if _key(item) == current or item in seen:',
           '            if _key(item) == current:',
           ('test_secrets_identity_registry_parity.py',)),
    # -- REG-01/REG-02: fail-safe revocation and a reusable registry ----------
    Mutant('REG-01', 'revoking at the maximum epoch leaves the row active',
           'identity/garrett/registry.py',
           "    if row['epoch'] != MAX_EPOCH:\n"
           "        result['epoch'] = epochs.advance(row['epoch'], maximum=MAX_EPOCH)\n",
           "    result['epoch'] = epochs.advance(row['epoch'], maximum=MAX_EPOCH)\n",
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_enrollment.py')),
    Mutant('REG-01', 'a saturated row is re-enrolled instead of exhausted',
           'identity/garrett/registry.py',
           "    if prior is not None and prior['epoch'] == MAX_EPOCH:\n"
           "        raise SecretsError('exhausted')",
           "    if False:\n        raise SecretsError('exhausted')",
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_enrollment.py')),
    Mutant('REN-02', 'renewing a saturated enrollment is not revoked',
           'identity/garrett/registry.py',
           "    if prior['epoch'] == MAX_EPOCH:\n"
           '        # An enrollment that cannot advance cannot be renewed: it is over.\n',
           '    if False:\n',
           ('test_secrets_identity_renewal_parity.py',)),
    Mutant('REG-02', 'prune commits before auditing each forgotten row',
           'identity/enrollment.py',
           "                    for item in forgotten:\n"
           "                        log.record('identity_forget_intent', timestamp=stamp,\n"
           "                                   resource={'subject': item['subject'],\n"
           "                                             'epoch': item['epoch']},\n"
           "                                   digest=item['certificate_sha256'])\n"
           "                    self._update(updated)\n",
           "                    self._update(updated)\n"
           "                    for item in forgotten:\n"
           "                        log.record('identity_forget_intent', timestamp=stamp,\n"
           "                                   resource={'subject': item['subject'],\n"
           "                                             'epoch': item['epoch']},\n"
           "                                   digest=item['certificate_sha256'])\n",
           ('test_secrets_identity_enrollment.py',)),
    Mutant('REG-02', 'an active row can be forgotten',
           'identity/garrett/registry.py',
           "    return not row['active'] and now >= row['not_after']",
           "    return now >= row['not_after']",
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_enrollment.py')),
    Mutant('REG-02', 'a row can be forgotten before its certificate expires',
           'identity/garrett/registry.py',
           "    return not row['active'] and now >= row['not_after']",
           "    return not row['active']",
           ('test_secrets_identity_registry_parity.py',
            'test_secrets_identity_enrollment.py')),
    # -- CA-04/CA-05: revoke-all on rotation, guarded by the active root ------
    Mutant('CA-04', 'CA rotation leaves enrollments active',
           'identity/garrett/registry.py',
           "        if row['active']:\n            result['subjects'][subject] = _deactivated(row)",
           "        if False:\n            result['subjects'][subject] = _deactivated(row)",
           ('test_secrets_identity_registry_parity.py', 'test_secrets_ca_rotation.py')),
    Mutant('CA-04', 'CA rotation erases the registry and restarts epochs',
           'identity/enrollment.py', '                self._update(revoked_registry)',
           "                self._update({'schema': registry_model.SCHEMA, 'subjects': {}})",
           ('test_secrets_ca_rotation.py',)),
    Mutant('CA-04', 'CA rotation commits before auditing each revocation',
           'identity/enrollment.py',
           "                for item in revoked:\n"
           "                    log.record('identity_revoke_intent', timestamp=stamp,\n"
           "                               resource={'subject': item['subject'],\n"
           "                                         'epoch': item['epoch']},\n"
           "                               digest=item['certificate_sha256'])\n"
           "                self._update(revoked_registry)\n"
           "                self._write_selected_manifest(selection)\n",
           "                self._update(revoked_registry)\n"
           "                self._write_selected_manifest(selection)\n"
           "                for item in revoked:\n"
           "                    log.record('identity_revoke_intent', timestamp=stamp,\n"
           "                               resource={'subject': item['subject'],\n"
           "                                         'epoch': item['epoch']},\n"
           "                               digest=item['certificate_sha256'])\n",
           ('test_secrets_ca_rotation.py',)),
    Mutant('CA-05', 'the root compare-and-swap accepts any expected root',
           'identity/garrett/authority.py',
           "    if current['ca']['sha256'] != expected_sha256:\n        raise SecretsError('revoked')",
           "    if False:\n        raise SecretsError('revoked')",
           ('test_secrets_authority_parity.py',)),
    Mutant('CA-05', 'rotate-ca runs without its compare-and-swap',
           'identity/enrollment.py',
           '            authority_model.require_ca(current, expected_sha256=expected_ca_sha256)\n',
           '', ('test_secrets_ca_rotation.py',)),
    Mutant('CA-03', 'a server leaf from an older CA generation is selectable',
           'identity/garrett/authority.py',
           "    if server['ca_generation'] != ca['generation']:\n        raise SecretsError('invalid_capability')",
           "    if False:\n        raise SecretsError('invalid_capability')",
           ('test_secrets_authority_parity.py',)),
    Mutant('RUNNER-01', 'an unhashable action ends the trust-generation stream',
           'identity/authority_runner.py',
           '        if type(action) is not str or action not in fields:',
           '        if action not in fields:', ('test_secrets_authority_parity.py',)),
    Mutant('RUNNER-01', 'an unhashable action ends the registry stream',
           'identity/registry_runner.py',
           '        if type(action) is not str or action not in ACTIONS:',
           '        if action not in ACTIONS:',
           ('test_secrets_identity_registry_parity.py',)),
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
