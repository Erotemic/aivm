"""Provider-neutral Garrett OAuth issuance, refresh and protected storage.

The token endpoint is faked at its network boundary: a ``transport`` object
whose ``post`` is the one call that would put bytes on the wire. The loopback
callback, the vault, its audit log and the CLI verbs are the real code; the
real-TLS transport is exercised in ``test_secrets_garrett_oauth_https.py``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import threading
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from aivm_secrets.errors import MESSAGES, SecretsError
from aivm_secrets.host.audit import verify
from aivm_secrets.identity import oauth_transport
from aivm_secrets.identity.cli import oauth_command
from aivm_secrets.identity.garrett.oauth_contract import (
    MAX_GENERATION,
    AccessGrant,
    PendingAuthorization,
    accept_callback,
    assess_token_response,
    callback_outcome,
    record_grant,
)
from aivm_secrets.identity.oauth_provider import OAuthProvider, load_provider
from aivm_secrets.identity.oauth_transport import (
    HostCallback,
    PinnedOAuthHTTP,
    authorization_url,
    exchange_code,
    new_pending,
    refresh_token,
)
from aivm_secrets.identity.oauth_vault import MAX_EPOCH, OAuthVault
from tests.secrets_helpers import write_private

STATE = 'STATE-synthetic-loopback-state-0123456789ab'
VERIFIER = 'VERIFIER-synthetic-pkce-code-verifier-012345'
PROFILE = {
    'schema': 1, 'name': 'synthetic', 'client_id': 'client-id',
    'authorization_url': 'https://login.example.org/authorize',
    'token_url': 'https://login.example.org/token',
    'resource_host': 'api.example.org', 'callback_port': 18765,
    'scopes': ['read'],
}


def provider(**overrides: Any) -> OAuthProvider:
    return OAuthProvider.parse({**PROFILE, **overrides})


def reply(access: str = 'ACCESS_SECRET', refresh: str = 'REFRESH_SECRET',
          ttl: int = 7200) -> dict:
    return {'access_token': access, 'refresh_token': refresh,
            'token_type': 'Bearer', 'expires_in': ttl, 'scope': 'read'}


def grant(access: str = 'ACCESS_SECRET', refresh: str = 'REFRESH_SECRET',
          *, ttl: int = 7200, now: int = 100) -> AccessGrant:
    return assess_token_response(reply(access, refresh, ttl), now=now,
                                 allowed_scopes=['read'])


class FakeOAuth:
    """A token endpoint that answers each request with the next response."""

    def __init__(self, responses: list[dict]) -> None:
        self.responses = list(responses)
        self.seen: list[dict[str, str]] = []

    def post(self, profile: OAuthProvider, form: dict[str, str],
             **kwargs: Any) -> dict:
        self.seen.append(dict(form))
        return self.responses.pop(0)


class LostReply(FakeOAuth):
    """The request reached the provider; its answer never came back."""

    def __init__(self) -> None:
        super().__init__([])

    def post(self, profile: OAuthProvider, form: dict[str, str],
             **kwargs: Any) -> dict:
        self.seen.append(dict(form))
        raise TimeoutError('the reply was lost after the request was sent')


class Crash(BaseException):
    """The host process dies mid-request (not an error anyone handles)."""


def audit_events(vault_root: Path) -> Counter:
    """The vault's audit events; every record's code is a closed error code."""
    events: Counter = Counter()
    for path in (vault_root / 'audit').glob('*.jsonl'):
        verify(path)
        for line in path.read_text().splitlines():
            record = json.loads(line)
            assert record['code'] in ('', *MESSAGES), record
            events[record['event']] += 1
    return events


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def test_provider_rejects_hostile_urls_and_insecure_refresh_modes() -> None:
    for url in ('http://login.example.org/token', 'https://a@b.example.org/x',
                'https://login.example.org:8443/x',
                'https://login.example.org/x?token=1',
                'https://127.0.0.1/t', 'https://localhost/t',
                'https://login.example.org/x#z'):
        with pytest.raises(SecretsError):
            provider(token_url=url)
    with pytest.raises(SecretsError):
        provider(refresh_rotation=False)
    assert provider(refresh_rotation=False,
                    client_secret_file='/var/tmp/test-secret').refresh_rotation is False


def test_pkce_state_and_callback_contract() -> None:
    p = provider()
    pending = PendingAuthorization.create(STATE, VERIFIER, p.redirect_uri,
                                          now=200, ttl=100)
    url = authorization_url(p, pending)
    query = parse_qs(urlsplit(url).query)
    assert query['code_challenge'] == [base64.urlsafe_b64encode(
        hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b'=').decode()]
    assert query['code_challenge_method'] == ['S256']
    assert query['response_type'] == ['code']
    assert VERIFIER not in url
    assert accept_callback(pending, {'code': 'CODE', 'state': STATE}, now=200) == 'CODE'
    for params, now in (
        ({'code': 'CODE', 'state': 'BAD'}, 200),
        ({'code': 'CODE', 'state': STATE}, 300),
        ({'code': 'CODE', 'state': STATE, 'extra': 'x'}, 200),
        ({'code': 'CODE', 'state': STATE, 'iss': 'https://bad.example'}, 200),
        ({'code': '', 'state': STATE}, 200),
    ):
        with pytest.raises(SecretsError):
            accept_callback(pending, params, now=now)


@pytest.mark.parametrize('field', ['state', 'verifier'])
@pytest.mark.parametrize('value, accepted', [
    pytest.param('a' * 42, False, id='42-chars'),
    pytest.param('a' * 43, True, id='43-chars'),
    pytest.param('a' * 128, True, id='128-chars'),
    pytest.param('a' * 129, False, id='129-chars'),
    pytest.param('a.b~c-d_' + 'e' * 35, True, id='unreserved'),
    pytest.param('a+b' + 'c' * 40, False, id='reserved'),
])
def test_pkce_values_are_43_to_128_unreserved_characters(
        field: str, value: str, accepted: bool) -> None:
    values = {'state': STATE, 'verifier': VERIFIER, field: value}
    if accepted:
        PendingAuthorization.create(values['state'], values['verifier'],
                                    provider().redirect_uri, now=1)
    else:
        with pytest.raises(SecretsError):
            PendingAuthorization.create(values['state'], values['verifier'],
                                        provider().redirect_uri, now=1)


def test_new_pending_lives_for_the_requested_timeout() -> None:
    pending = new_pending(provider(), now=1000, ttl=600)
    assert pending.expires_at - pending.issued_at == 600
    assert 43 <= len(pending.state) and 43 <= len(pending.verifier)


def test_exchange_refresh_rotation_and_scope_attenuation() -> None:
    p = provider()
    pending = PendingAuthorization.create(STATE, VERIFIER, p.redirect_uri,
                                          now=100, ttl=100)
    transport = FakeOAuth([reply('ACCESS1', 'REFRESH1'),
                           reply('ACCESS2', 'REFRESH2')])
    first = exchange_code(p, pending, {'code': 'CODE', 'state': STATE},
                          now=120, transport=transport)
    assert first.access_token == 'ACCESS1'
    assert first.generation == 0
    assert transport.seen[0]['code_verifier'] == VERIFIER
    second = refresh_token(p, first, now=200, transport=transport)
    assert second.access_token == 'ACCESS2' and second.refresh_token == 'REFRESH2'
    assert second.generation == 1
    assert transport.seen[1]['refresh_token'] == 'REFRESH1'
    for data in (reply('X', 'REFRESH1'),
                 {**reply('X','REFRESH3'), 'scope': 'admin'},
                 {**reply('X','REFRESH3'), 'token_type': 'MAC'},
                 {**reply('X','REFRESH3'), 'expires_in': -1},
                 {**reply('X','REFRESH3'), 'expires_in': True}):
        with pytest.raises(SecretsError):
            assess_token_response(data, now=200, allowed_scopes=['read'],
                                  previous=first)


def test_allowed_scopes_must_be_a_list_not_a_string() -> None:
    # tuple('repo') would be four one-letter scopes that each pass the grammar.
    wrong: list[Any] = ['repo', ('repo',)]
    for allowed in wrong:
        with pytest.raises(SecretsError):
            assess_token_response({'access_token': 'A', 'token_type': 'Bearer'},
                                  now=1, allowed_scopes=allowed)


@pytest.mark.parametrize('issuer', [
    pytest.param(None, id='null'),
    pytest.param(0, id='zero'),
    pytest.param(False, id='false'),
    pytest.param(b'', id='bytes'),
    pytest.param(['https://login.example.org'], id='list'),
])
def test_the_contract_itself_refuses_a_non_string_issuer(issuer: Any) -> None:
    # The JSON runner refuses these before calling the contract, so only a
    # direct call shows the contract's own check -- the copy a port
    # transcribes. A falsy issuer must never read as "no issuer expected".
    pending = PendingAuthorization.create(STATE, VERIFIER, provider().redirect_uri,
                                          now=200, ttl=100)
    for params in ({'code': 'CODE', 'state': STATE},
                   {'code': 'CODE', 'state': STATE,
                    'iss': 'https://login.example.org'},
                   {'error': 'access_denied', 'state': STATE}):
        with pytest.raises(SecretsError) as refused:
            callback_outcome(pending, params, now=200, expected_issuer=issuer)
        assert refused.value.detail == ''
        with pytest.raises(SecretsError) as refused:
            accept_callback(pending, params, now=200, expected_issuer=issuer)
        assert refused.value.detail == ''
    # Control: the empty string is how "no issuer expected" is said.
    assert accept_callback(pending, {'code': 'CODE', 'state': STATE}, now=200,
                           expected_issuer='') == 'CODE'


def test_vault_never_persists_plain_credentials_and_denies_rollback_to_other_profile(
        tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    token = grant()
    assert vault.enroll(p, 'vm-1', token)['epoch'] == 0
    stored = next((tmp_path / 'vault').glob('*.json'))
    content = stored.read_bytes()
    assert b'ACCESS_SECRET' not in content and b'REFRESH_SECRET' not in content
    assert vault.credential_for_session(p, 'vm-1', resource_host='api.example.org', now=101) == 'ACCESS_SECRET'
    with pytest.raises(SecretsError):
        vault.credential_for_session(p, 'vm-1', resource_host='evil.example.org', now=101)
    with pytest.raises(SecretsError):
        vault.enroll(p, 'vm-1', token)
    assert vault.revoke(p, 'vm-1')['epoch'] == 1
    with pytest.raises(SecretsError):
        vault.credential_for_session(p, 'vm-1', resource_host='api.example.org', now=101)
    assert vault.enroll(p, 'vm-1', token, replace=True)['epoch'] == 2
    # A policy/manifest update cannot silently inherit an old token.
    other = replace(p, resource_host='other.example.org')
    with pytest.raises(SecretsError) as refused:
        vault.session_snapshot(other, 'vm-1', resource_host='other.example.org',
                               now=101)
    assert refused.value.detail == 'profile_changed'
    assert vault.status(other, 'vm-1')['profile_current'] is False
    content = stored.read_bytes()
    stored.write_bytes(content.replace(b'0', b'1', 1))
    with pytest.raises(SecretsError):
        vault.status(p, 'vm-1')


def test_expired_grant_is_refreshed_once_and_persisted_atomically(tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant('FIRST', 'REFRESH1', ttl=120))
    upstream = FakeOAuth([reply('SECOND', 'REFRESH2', 120)])
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=180, transport=upstream) == 'SECOND'
    assert len(upstream.seen) == 1
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=181, transport=upstream) == 'SECOND'
    assert len(upstream.seen) == 1
    status = vault.status(p, 'vm-1')
    assert (status['expires_at'], status['generation'], status['refresh_state'],
            status['has_refresh']) == (300, 1, 'none', True)
    # A reply that reuses the presented refresh token is unusable -- and the
    # provider did receive REFRESH2, so it may have rotated it: in doubt.
    unusable = FakeOAuth([reply('FAIL', 'REFRESH2')])
    with pytest.raises(SecretsError) as failed:
        vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                     now=200, force_refresh=True,
                                     transport=unusable)
    assert failed.value.detail == 'refresh_in_doubt'
    # The durable grant was not replaced, and it is not used either.
    assert vault.status(p, 'vm-1')['generation'] == 1
    with pytest.raises(SecretsError) as refused:
        vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                     now=181)
    assert refused.value.detail == 'refresh_in_doubt'


def test_no_expired_bearer_without_refresh(tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    first = assess_token_response({
        'access_token': 'TOKEN1', 'token_type': 'bearer',
        'expires_in': 50,
    }, now=100, allowed_scopes=list(p.scopes))
    vault.enroll(p, 'vm-1', first)
    with pytest.raises(SecretsError) as e:
        vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host, now=105)
    assert e.value.code == 'expired'
    assert vault.status(p, 'vm-1')['has_refresh'] is False


# -- refresh outcome state ----------------------------------------------------


def test_a_lost_refresh_reply_is_never_replayed_automatically(tmp_path: Path) -> None:
    p = provider()
    root = tmp_path / 'vault'
    vault = OAuthVault.initialize(root)
    vault.enroll(p, 'vm-1', grant('FIRST', 'REFRESH1', ttl=120))
    lease = vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                                   now=101)
    lost = LostReply()
    with pytest.raises(SecretsError) as failed:
        vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                               now=180, transport=lost)
    assert (failed.value.code, failed.value.detail) == (
        'credential_source', 'refresh_in_doubt')
    assert [form['refresh_token'] for form in lost.seen] == ['REFRESH1']
    status = vault.status(p, 'vm-1')
    assert (status['refresh_state'], status['generation'], status['has_refresh'],
            status['active']) == ('in_doubt', 0, True, True)
    assert audit_events(root)['oauth_refresh_in_doubt'] == 1
    # Neither the next session start, nor a still-valid access token, nor a
    # running session's lease, nor an ordinary explicit refresh presents
    # the possibly consumed refresh token again.
    attempts: list[dict[str, Any]] = [
        {'now': 181}, {'now': 101}, {'now': 101, 'force_refresh': True}]
    for attempt in attempts:
        with pytest.raises(SecretsError) as refused:
            vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                                   transport=lost, **attempt)
        assert refused.value.detail == 'refresh_in_doubt'
    with pytest.raises(SecretsError) as refused:
        with vault.active_lease(p, 'vm-1', lease):
            pass
    assert refused.value.detail == 'refresh_in_doubt'
    with pytest.raises(SecretsError) as refused:
        vault.refresh(p, 'vm-1', now=190, transport=lost)
    assert refused.value.detail == 'refresh_in_doubt'
    assert len(lost.seen) == 1
    # One deliberate retry presents it exactly once and settles the record.
    retry = FakeOAuth([reply('SECOND', 'REFRESH2', 120)])
    after = vault.refresh(p, 'vm-1', now=190, transport=retry,
                          retry_in_doubt=True)
    assert [form['refresh_token'] for form in retry.seen] == ['REFRESH1']
    assert (after['refresh_state'], after['generation']) == ('none', 1)
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=191) == 'SECOND'


def test_the_in_doubt_marker_is_on_disk_before_the_request_is_sent(
        tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant('FIRST', 'REFRESH1', ttl=120))
    record = next((tmp_path / 'vault').glob('*.json'))

    class Witness(FakeOAuth):
        """Copies the record off disk at the instant the request leaves."""

        def post(self, profile: OAuthProvider, form: dict[str, str],
                 **kwargs: Any) -> dict:
            self.on_disk = record.read_bytes()
            return super().post(profile, form, **kwargs)

    witness = Witness([reply('SECOND', 'REFRESH2', 120)])
    vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host, now=180,
                           transport=witness)
    assert vault.status(p, 'vm-1')['refresh_state'] == 'none'
    # A host crash right after sending leaves exactly that disk state behind.
    record.write_bytes(witness.on_disk)
    assert vault.status(p, 'vm-1')['refresh_state'] == 'in_doubt'


def test_a_crash_during_the_request_leaves_the_record_in_doubt(tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant('FIRST', 'REFRESH1', ttl=120))

    class Dies(FakeOAuth):
        def post(self, profile: OAuthProvider, form: dict[str, str],
                 **kwargs: Any) -> dict:
            super().post(profile, form, **kwargs)
            raise Crash()

    with pytest.raises(Crash):
        vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                               now=180, transport=Dies([{}]))
    assert vault.status(p, 'vm-1')['refresh_state'] == 'in_doubt'


def test_reauthorizing_clears_an_in_doubt_record(tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant('FIRST', 'REFRESH1', ttl=120))
    with pytest.raises(SecretsError):
        vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                               now=180, transport=LostReply())
    # A login without --replace still refuses: the in-doubt grant is active.
    with pytest.raises(SecretsError) as refused:
        vault.can_enroll(p, 'vm-1')
    assert refused.value.code == 'denied'
    answer = vault.enroll(p, 'vm-1', grant('FRESH', 'FRESH_REFRESH', now=180),
                          replace=True)
    assert answer['epoch'] == 1
    assert vault.status(p, 'vm-1')['refresh_state'] == 'none'
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=181) == 'FRESH'


# -- edited provider profiles ---------------------------------------------------


def test_an_edited_profile_can_inspect_revoke_and_reuse_its_record(
        tmp_path: Path) -> None:
    p = provider()
    edited = provider(scopes=['read', 'write'])  # same name: same record file
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant())
    with pytest.raises(SecretsError) as refused:
        vault.session_snapshot(edited, 'vm-1', resource_host=edited.resource_host,
                               now=101)
    assert refused.value.detail == 'profile_changed'
    seen = vault.status(edited, 'vm-1')
    assert (seen['active'], seen['profile_current'], seen['epoch']) == (True, False, 0)
    assert vault.revoke(edited, 'vm-1') == {
        'provider': 'synthetic', 'subject': 'vm-1', 'active': False,
        'epoch': 1, 'previous_digest': p.digest[:16]}
    after = vault.status(edited, 'vm-1')
    assert (after['active'], after['profile_current'], after['previous_digest'],
            after['epoch']) == (False, True, p.digest[:16], 1)
    # The record now belongs to the edited profile; the old one is stale.
    with pytest.raises(SecretsError):
        vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host, now=101)
    vault.enroll(edited, 'vm-1', grant('EDITED', 'EDITED_REFRESH'))
    assert vault.credential_for_session(edited, 'vm-1',
                                        resource_host=edited.resource_host,
                                        now=101) == 'EDITED'


def test_an_edited_profile_can_replace_an_active_record(tmp_path: Path) -> None:
    p = provider()
    edited = provider(callback_port=18766)
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant())
    with pytest.raises(SecretsError) as refused:
        vault.enroll(edited, 'vm-1', grant('NEW', 'NEW_REFRESH'))
    assert refused.value.code == 'denied'
    answer = vault.enroll(edited, 'vm-1', grant('NEW', 'NEW_REFRESH'), replace=True)
    assert (answer['epoch'], answer['previous_digest']) == (1, p.digest[:16])
    status = vault.status(edited, 'vm-1')
    assert status['profile_current'] and status['active']
    assert vault.credential_for_session(edited, 'vm-1',
                                        resource_host=edited.resource_host,
                                        now=101) == 'NEW'


def test_revocation_at_the_maximum_epoch_still_deactivates(tmp_path: Path) -> None:
    p = provider()
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(p, 'vm-1', grant())
    # Hand-edited or corrupted-but-authentic state can only be produced with
    # the vault key; _write is the sealing primitive that holds it.
    vault._write(p, 'vm-1', {'active': True, 'epoch': MAX_EPOCH,
                             'grant': record_grant(grant()),
                             'refresh_state': 'none', 'previous_digest': ''})
    assert vault.revoke(p, 'vm-1')['epoch'] == MAX_EPOCH
    status = vault.status(p, 'vm-1')
    assert (status['active'], status['epoch']) == (False, MAX_EPOCH)
    with pytest.raises(SecretsError) as refused:
        vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host, now=101)
    assert refused.value.code == 'revoked'
    with pytest.raises(SecretsError) as exhausted:
        vault.enroll(p, 'vm-1', grant(), replace=True)
    assert exhausted.value.code == 'exhausted'


def test_a_refresh_at_the_last_generation_is_refused_before_sending(
        tmp_path: Path) -> None:
    # No successor of this grant could be accepted, so presenting its
    # rotating refresh token would spend it for nothing.
    p = provider()
    root = tmp_path / 'vault'
    vault = OAuthVault.initialize(root)
    vault.enroll(p, 'vm-1', replace(grant('FIRST', 'REFRESH1', ttl=120),
                                    generation=MAX_GENERATION))
    upstream = FakeOAuth([reply('SECOND', 'REFRESH2', 120)])
    attempts: list[dict[str, Any]] = [{'now': 180},
                                      {'now': 101, 'force_refresh': True}]
    for attempt in attempts:
        with pytest.raises(SecretsError) as refused:
            vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                                   transport=upstream, **attempt)
        assert (refused.value.code, refused.value.detail) == (
            'exhausted', 'refresh_exhausted')
    with pytest.raises(SecretsError) as refused:
        vault.refresh(p, 'vm-1', now=180, transport=upstream,
                      retry_in_doubt=True)
    assert refused.value.code == 'exhausted'
    assert upstream.seen == []
    status = vault.status(p, 'vm-1')
    assert (status['refresh_state'], status['generation']) == (
        'none', MAX_GENERATION)
    assert audit_events(root)['oauth_refresh_intent'] == 0
    # The access token itself stays usable until it nears its expiry.
    assert vault.credential_for_session(p, 'vm-1', resource_host=p.resource_host,
                                        now=101) == 'FIRST'


class RefusingDisk(FakeOAuth):
    """The provider answers; then the vault directory refuses new files.

    The disk is the boundary here: the vault directory becomes read-only the
    moment the request is answered, as a full disk would refuse the write.
    """

    def __init__(self, root: Path, answer: Any) -> None:
        super().__init__([])
        self.root = root
        self.answer = answer

    def post(self, profile: OAuthProvider, form: dict[str, str],
             **kwargs: Any) -> dict:
        self.seen.append(dict(form))
        self.root.chmod(0o500)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.mark.skipif(os.geteuid() == 0, reason='root ignores directory modes')
@pytest.mark.parametrize('answer', [
    pytest.param(reply('SECOND', 'REFRESH2', 120), id='successor'),
    pytest.param(SecretsError('credential_source', detail='refresh_not_sent'),
                 id='not-sent'),
    pytest.param(SecretsError('credential_source', status=400,
                              detail='refresh_rejected'), id='rejected'),
])
def test_an_outcome_the_vault_cannot_store_stays_in_doubt_and_is_audited(
        tmp_path: Path, answer: Any) -> None:
    p = provider()
    root = tmp_path / 'vault'
    vault = OAuthVault.initialize(root)
    vault.enroll(p, 'vm-1', grant('FIRST', 'REFRESH1', ttl=120))
    disk = RefusingDisk(root, answer)
    try:
        with pytest.raises(SecretsError) as failed:
            vault.session_snapshot(p, 'vm-1', resource_host=p.resource_host,
                                   now=180, transport=disk)
    finally:
        root.chmod(0o700)
    # Not an unrelated "audit failed": what the operator must know is that
    # the refresh token may be spent and the record says so.
    assert (failed.value.code, failed.value.detail) == (
        'credential_source', 'refresh_in_doubt')
    assert len(disk.seen) == 1
    assert vault.status(p, 'vm-1')['refresh_state'] == 'in_doubt'
    events = audit_events(root)
    assert (events['oauth_refresh_intent'], events['oauth_refresh_in_doubt'],
            events['oauth_recorded'], events['oauth_refresh_not_sent'],
            events['oauth_refresh_rejected']) == (1, 1, 1, 0, 0)


# -- the loopback callback -------------------------------------------------------


def waited(listener: HostCallback, *, timeout: float,
           limit: float) -> tuple[Any, float]:
    """Run ``listener.wait`` in a thread; return its outcome and duration."""
    outcome: list[Any] = []

    def run() -> None:
        start = time.monotonic()
        try:
            outcome.append(listener.wait(timeout=timeout))
        except BaseException as exc:
            outcome.append(exc)
        outcome.append(time.monotonic() - start)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(limit)
    assert not worker.is_alive(), 'wait() did not return within its deadline'
    return outcome[0], outcome[1]


def visit(port: int, target: str) -> list[tuple[int, bytes]]:
    """A browser request to the callback, from a thread; replies collected."""
    replies: list[tuple[int, bytes]] = []

    def go() -> None:
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            conn.request('GET', target)
            response = conn.getresponse()
            replies.append((response.status, response.read()))
        finally:
            conn.close()

    threading.Thread(target=go, daemon=True).start()
    return replies


def test_host_callback_accepts_only_authorized_one_shot() -> None:
    port = free_port()
    p = provider(callback_port=port)
    pending = new_pending(p)
    with HostCallback(p, pending) as listener:
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        conn.request('GET', '/oauth/callback?code=x&state=wrong')
        # Call handle_request since listener does not start a background thread.
        listener._httpd.handle_request()
        response = conn.getresponse()
        assert response.status == 400
        response.read()
        conn.close()
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        conn.request('GET', f'/oauth/callback?code=good&state={pending.state}')
        listener._httpd.handle_request()
        response = conn.getresponse()
        assert response.status == 200
        response.read()
        conn.close()
        assert listener.parameters == {'code': 'good', 'state': pending.state}


def test_an_idle_local_connection_cannot_hold_the_login_open() -> None:
    p = provider(callback_port=free_port())
    with HostCallback(p, new_pending(p)) as listener:
        idle = socket.create_connection(('127.0.0.1', p.callback_port))
        try:
            outcome, elapsed = waited(listener, timeout=1.0, limit=6)
        finally:
            idle.close()
    assert isinstance(outcome, SecretsError) and outcome.code == 'expired'
    assert elapsed < 2.0


def test_a_trickling_connection_is_cut_at_its_request_deadline(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # Shortened from 5 s so the test is quick; the deadline is a constant.
    monkeypatch.setattr(oauth_transport, 'CALLBACK_SECONDS', 0.5)
    p = provider(callback_port=free_port())
    pending = new_pending(p)
    stop = threading.Event()
    with HostCallback(p, pending) as listener:
        # Queued first, so it is the request the listener reads first.
        drip = socket.create_connection(('127.0.0.1', p.callback_port))

        def trickle() -> None:
            # One byte per interval never trips a per-read timeout by itself.
            for char in b'GET /oauth/callback?' + b'x' * 400:
                if stop.wait(0.1):
                    return
                try:
                    drip.send(bytes([char]))
                except OSError:
                    return

        threading.Thread(target=trickle, daemon=True).start()
        try:
            replies = visit(p.callback_port,
                            f'/oauth/callback?code=good&state={pending.state}')
            outcome, elapsed = waited(listener, timeout=20, limit=10)
        finally:
            stop.set()
            drip.close()
    assert outcome == {'code': 'good', 'state': pending.state}
    assert elapsed < 4.0
    deadline = time.monotonic() + 3
    while not replies and time.monotonic() < deadline:
        time.sleep(0.01)
    assert replies and replies[0][0] == 200


def test_a_provider_denial_ends_the_login_at_once_without_echo() -> None:
    p = provider(callback_port=free_port())
    pending = new_pending(p)
    with HostCallback(p, pending) as listener:
        replies = visit(p.callback_port, (
            '/oauth/callback?error=access_denied&state=' + pending.state +
            '&error_description=PROVIDER%20SECRET%20TEXT'
            '&error_uri=https%3A%2F%2Flogin.example.org%2Fwhy'))
        outcome, elapsed = waited(listener, timeout=30, limit=5)
    assert isinstance(outcome, SecretsError)
    assert (outcome.code, outcome.detail) == ('credential_source',
                                              'authorization_denied')
    assert elapsed < 1.0
    assert 'PROVIDER' not in outcome.for_operator()
    deadline = time.monotonic() + 3
    while not replies and time.monotonic() < deadline:
        time.sleep(0.01)
    assert replies and b'PROVIDER' not in replies[0][1]


def test_a_full_rfc_9207_denial_ends_the_login_at_once() -> None:
    # All five parameters an RFC 6749 4.1.2.1 + RFC 9207 error may carry.
    issuer = 'https://login.example.org/oauth'
    p = provider(callback_port=free_port(), issuer_response=issuer)
    pending = new_pending(p)
    with HostCallback(p, pending) as listener:
        replies = visit(p.callback_port, '/oauth/callback?' + urlencode({
            'error': 'access_denied', 'state': pending.state,
            'error_description': 'PROVIDER TEXT', 'error_uri': issuer + '/why',
            'iss': issuer}))
        outcome, elapsed = waited(listener, timeout=30, limit=5)
    assert isinstance(outcome, SecretsError)
    assert (outcome.code, outcome.detail) == ('credential_source',
                                              'authorization_denied')
    assert elapsed < 1.0
    deadline = time.monotonic() + 3
    while not replies and time.monotonic() < deadline:
        time.sleep(0.01)
    assert replies and replies[0][0] == 200


def test_a_denial_for_another_authorization_does_not_end_the_login() -> None:
    p = provider(callback_port=free_port())
    pending = new_pending(p)
    with HostCallback(p, pending) as listener:
        other = visit(p.callback_port,
                      '/oauth/callback?error=access_denied&state=' + 'x' * 43)
        outcome, _ = waited(listener, timeout=1.0, limit=6)
        assert isinstance(outcome, SecretsError) and outcome.code == 'expired'
        assert other and other[0][0] == 400 and not listener.denied


def test_a_busy_callback_port_is_a_secrets_error_not_a_traceback() -> None:
    with socket.socket() as holder:
        holder.bind(('127.0.0.1', 0))
        holder.listen(1)
        p = provider(callback_port=holder.getsockname()[1])
        with pytest.raises(SecretsError) as refused:
            HostCallback(p, new_pending(p))
    assert (refused.value.code, refused.value.detail) == (
        'credential_source', 'callback_port_unavailable')


def test_pinned_https_does_not_follow_redirect_or_accept_oversized(
        monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status = 302
        def getheader(self, name: str, default: str = '') -> str:
            return default
        def read(self, count: int) -> bytes:
            return b''
        def close(self) -> None:
            pass
    class Connection:
        def __init__(self, host: str, port: int, *, timeout: float,
                     context: Any) -> None:
            assert host == 'login.example.org' and port == 443
            assert context.keylog_filename is None
        def connect(self) -> None:
            pass
        def request(self, method: str, target: str, data: bytes,
                    headers: dict) -> None:
            assert method == 'POST' and target == '/token'
            assert 'Authorization' not in headers
        def getresponse(self) -> Response:
            return Response()
        def close(self) -> None:
            pass
    monkeypatch.setattr(http.client, 'HTTPSConnection', Connection)
    with pytest.raises(SecretsError) as refused:
        PinnedOAuthHTTP().post(provider(), {'grant_type': 'authorization_code', 'code': 'a'})
    # A redirect answers a request that was sent: what it did is unknown.
    assert (refused.value.detail, refused.value.status) == ('exchange_in_doubt', 302)


def test_refresh_with_omitted_scope_preserves_attenuated_grant() -> None:
    # OAuth refresh can omit `scope`; this must *not* silently widen an
    # already-downscoped grant back to the provider's configured scope set.
    allowed = ['read', 'read:private']
    old = assess_token_response({
        'token_type': 'Bearer', 'access_token': 'OLD',
        'refresh_token': 'REFRESH1', 'expires_in': 500, 'scope': 'read',
    }, now=100, allowed_scopes=allowed)
    updated = assess_token_response({
        'token_type': 'Bearer', 'access_token': 'NEW',
        'refresh_token': 'REFRESH2', 'expires_in': 500,
    }, now=120, allowed_scopes=allowed, previous=old)
    assert updated.scopes == ('read',) and updated.generation == 1


# -- the identity oauth-* verbs ----------------------------------------------------


def oauth_args(*argv: str) -> argparse.Namespace:
    from aivm_secrets.cli import _parser
    return _parser().parse_args(['identity', *argv])


class Operator:
    """A vault, a provider profile file and the arguments that name them."""

    def __init__(self, tmp_path: Path, **profile: Any) -> None:
        self.profile_path = write_private(
            tmp_path / 'profile.json',
            json.dumps({**PROFILE, **profile}).encode(), 0o644)
        self.vault_root = tmp_path / 'vault'
        oauth_command(oauth_args('oauth-init', '--vault', str(self.vault_root)), ())
        self.provider = load_provider(self.profile_path)
        self.vault = OAuthVault(self.vault_root)

    def run(self, verb: str, *extra: str, **kwargs: Any) -> dict:
        return oauth_command(oauth_args(
            verb, '--vault', str(self.vault_root),
            '--provider-config', str(self.profile_path),
            '--subject', 'vm-1', *extra), (), **kwargs)


class Browser:
    """The operator's browser: follows the printed URL back to the callback."""

    def __init__(self, port: int, *,
                 before: Callable[[], Any] | None = None) -> None:
        self.port = port
        self.before = before
        self.opened: list[str] = []

    def __call__(self, url: str) -> None:
        self.opened.append(url)
        query = parse_qs(urlsplit(url).query)
        assert query['redirect_uri'] == [f'http://127.0.0.1:{self.port}/oauth/callback']
        if self.before is not None:
            self.before()
        visit(self.port, '/oauth/callback?code=synthetic-code&state='
              + query['state'][0])


def test_oauth_login_round_trip_through_the_loopback_callback(
        tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    port = free_port()
    operator = Operator(tmp_path, callback_port=port)
    endpoint = FakeOAuth([reply('LOGIN_ACCESS', 'LOGIN_REFRESH')])
    answer = operator.run('oauth-login', '--timeout', '30', transport=endpoint,
                          browser=Browser(port))
    assert answer['epoch'] == 0 and answer['scopes'] == ['read']
    assert [(form['grant_type'], form['code']) for form in endpoint.seen] == [
        ('authorization_code', 'synthetic-code')]
    status = operator.run('oauth-status')
    assert (status['refresh_state'], status['generation'], status['has_refresh'],
            status['active']) == ('none', 0, True, True)
    out = capsys.readouterr().out
    assert 'Open this URL' in out and 'LOGIN_' not in out


def test_oauth_login_refuses_an_occupied_subject_before_any_browser_flow(
        tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    with socket.socket() as busy:
        # Were the callback bound first, this would fail as a busy port.
        busy.bind(('127.0.0.1', 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        operator = Operator(tmp_path, callback_port=port)
        operator.vault.enroll(operator.provider, 'vm-1', grant())
        endpoint = FakeOAuth([])
        browser = Browser(port)
        with pytest.raises(SecretsError) as refused:
            operator.run('oauth-login', transport=endpoint, browser=browser)
    assert refused.value.code == 'denied'
    assert endpoint.seen == [] and browser.opened == []
    assert 'Open this URL' not in capsys.readouterr().out


def test_oauth_login_reports_a_grant_it_could_not_store(tmp_path: Path) -> None:
    port = free_port()
    operator = Operator(tmp_path, callback_port=port)

    def concurrent_login() -> None:
        # Another login for the same subject lands mid-flow.
        OAuthVault(operator.vault_root).enroll(
            operator.provider, 'vm-1', grant('RACER', 'RACER_REFRESH'))

    endpoint = FakeOAuth([reply('ORPHAN', 'ORPHAN_REFRESH')])
    with pytest.raises(SecretsError) as refused:
        operator.run('oauth-login', '--timeout', '30', transport=endpoint,
                     browser=Browser(port, before=concurrent_login))
    assert refused.value.code == 'denied'
    assert refused.value.detail.startswith('grant orphaned upstream')
    assert [form['grant_type'] for form in endpoint.seen] == ['authorization_code']
    assert operator.vault.credential_for_session(
        operator.provider, 'vm-1', resource_host='api.example.org',
        now=101) == 'RACER'


def test_oauth_login_waits_as_long_as_its_timeout_allows(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    port = free_port()
    operator = Operator(tmp_path, callback_port=port)
    # The wall clock is the boundary: the operator spends 200 s in the
    # browser, longer than the 180 s an authorization used to live.
    offset = [0.0]
    wall = time.time

    def clock() -> float:
        return wall() + offset[0]

    def linger() -> None:
        offset[0] = 200.0

    monkeypatch.setattr(time, 'time', clock)
    endpoint = FakeOAuth([reply('LOGIN_ACCESS', 'LOGIN_REFRESH')])
    answer = operator.run('oauth-login', '--timeout', '600', transport=endpoint,
                          browser=Browser(port, before=linger))
    assert answer['epoch'] == 0
    assert [form['grant_type'] for form in endpoint.seen] == ['authorization_code']


class Exchange(FakeOAuth):
    """A token endpoint whose one answer may be a transport failure.

    A failure is what ``PinnedOAuthHTTP.post`` raises for that outcome.
    """

    def post(self, profile: OAuthProvider, form: dict[str, str],
             **kwargs: Any) -> dict:
        answer = super().post(profile, form, **kwargs)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.mark.parametrize('answer, orphaned', [
    pytest.param({**reply('BROAD', 'BROAD_REFRESH'), 'scope': 'read write'},
                 True, id='200-broader-scope'),
    pytest.param({**reply('MAC', 'MAC_REFRESH'), 'token_type': 'MAC'},
                 True, id='200-not-bearer'),
    pytest.param(SecretsError('credential_source', detail='exchange_in_doubt'),
                 True, id='reply-lost'),
    pytest.param(SecretsError('credential_source', status=400,
                              detail='exchange_rejected'),
                 False, id='code-rejected'),
    pytest.param(SecretsError('credential_source', detail='exchange_not_sent'),
                 False, id='not-sent'),
])
def test_oauth_login_reports_a_grant_its_exchange_may_have_left_upstream(
        tmp_path: Path, answer: Any, orphaned: bool) -> None:
    port = free_port()
    operator = Operator(tmp_path, callback_port=port)
    endpoint = Exchange([answer])
    with pytest.raises(SecretsError) as failed:
        operator.run('oauth-login', '--timeout', '30', transport=endpoint,
                     browser=Browser(port))
    assert failed.value.code == 'credential_source'
    assert failed.value.detail.startswith('grant orphaned upstream') is orphaned
    if orphaned:
        assert failed.value.detail.endswith('(exchange_in_doubt)')
    assert 'REFRESH' not in failed.value.for_operator()
    assert [form['grant_type'] for form in endpoint.seen] == ['authorization_code']
    assert list(operator.vault_root.glob('*.json')) == []


def test_oauth_refresh_retries_an_in_doubt_grant_only_when_asked(
        tmp_path: Path) -> None:
    operator = Operator(tmp_path)
    operator.vault.enroll(operator.provider, 'vm-1',
                          grant(now=int(time.time())))
    lost = LostReply()
    with pytest.raises(SecretsError):
        operator.run('oauth-refresh', transport=lost)
    status = operator.run('oauth-status')
    assert (status['refresh_state'], status['generation'],
            status['has_refresh']) == ('in_doubt', 0, True)
    with pytest.raises(SecretsError) as refused:
        operator.run('oauth-refresh', transport=lost)
    assert refused.value.detail == 'refresh_in_doubt'
    assert len(lost.seen) == 1
    retry = FakeOAuth([reply('SECOND', 'REFRESH2')])
    answer = operator.run('oauth-refresh', '--retry-in-doubt', transport=retry)
    assert [form['refresh_token'] for form in retry.seen] == ['REFRESH_SECRET']
    assert (answer['refresh_state'], answer['generation']) == ('none', 1)
