"""The one credentialed egress path, against a real TLS server on loopback.

Nothing here is mocked below the socket: the executor performs a genuine
verified TLS handshake with ``TLSService``. What these tests establish is
what the trusted interpreter does with an authorized effect -- and what it
refuses to do whatever a provider answers (ROUTE-01, COMP-01).
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import replace

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host import egress as egress_module
from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.kernel.machine import AuthorizedEffect
from aivm_secrets.kernel.model import Effect, Egress
from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.kernel.wire import MAX_RESPONSE
from tests.secrets_helpers import (
    REPO,
    SERVICE_TOKEN,
    TLS_HOST,
    TLSService,
    github_policy,
    make_certificates,
    metadata,
    must,
)

READ = Effect('GET', '/v1/issues/23', (('page', '2'),))
WRITE = Effect('POST', '/v1/issues/23/comments', body=(('body', 'héllo "x"'),))


# A provider whose GET changes state; the manifest declared it a write.
TOGGLE = Effect('GET', '/v1/issues/23/close')


def authorized(
    effect: Effect, *, final: bool = True, write: bool | None = None
) -> AuthorizedEffect:
    """What the kernel would mint. ``write`` is the *declared* effect."""
    declared = effect.is_write if write is None else write
    return AuthorizedEffect(0, 'a' * 32, 'd' * 64, final, declared, effect)


@pytest.fixture
def service(tmp_path):
    with TLSService(tmp_path) as running:
        yield running


def executor(service: TLSService, **changes) -> HTTPSExecutor:
    pins = service.egress()
    destination = Egress(
        service.host, pins['port'], pins['address'], pins['ca_file'], 'bearer'
    )
    return HTTPSExecutor(replace(destination, **changes))


def failed(call, *args) -> SecretsError:
    with pytest.raises(SecretsError) as caught:
        call(*args)
    return caught.value


def respond(status, body=b'{}', **headers):
    return lambda seen: (status, headers, body)


def test_https_provider_pins_host_credentials_and_tls(service, monkeypatch):
    for variable in ('HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'HTTP_PROXY'):
        monkeypatch.setenv(variable, 'http://attacker.invalid:3128')
    service.routes[('GET', '/v1/issues/23?page=2')] = {'id': 23}
    result = executor(service).execute(authorized(READ), SERVICE_TOKEN)
    assert result == {'id': 23}
    (seen,) = service.requests
    assert (seen['method'], seen['target']) == ('GET', '/v1/issues/23?page=2')
    headers = seen['headers']
    assert headers['authorization'] == 'Bearer ' + SERVICE_TOKEN
    assert headers['host'] == f'{TLS_HOST}:{service.port}'
    assert headers['accept'] == 'application/json'
    assert headers['accept-encoding'] == 'identity'
    assert headers['user-agent'] == egress_module.USER_AGENT
    assert 'x-api-key' not in headers and 'content-type' not in headers
    assert 'cookie' not in headers and 'proxy-authorization' not in headers


def test_api_key_scheme_static_headers_and_canonical_body(service):
    service.routes[('POST', '/v1/issues/23/comments')] = {'created': True}
    pinned = executor(
        service,
        authentication='x-api-key',
        headers=(('X-Api-Version', '2026-03-10'),),
    )
    assert pinned.execute(authorized(WRITE), SERVICE_TOKEN) == {'created': True}
    (seen,) = service.requests
    assert seen['headers']['x-api-key'] == SERVICE_TOKEN
    assert 'authorization' not in seen['headers']
    assert seen['headers']['x-api-version'] == '2026-03-10'
    assert seen['headers']['content-type'] == 'application/json'
    # Exactly the projected fields, canonically encoded; nothing else.
    assert seen['body'] == '{"body":"h\\u00e9llo \\"x\\""}'


def test_text_responses_and_custom_accept(service):
    diff = b'diff --git a/x b/x\n+caf\xc3\xa9\n'
    service.routes[('GET', '/v1/raw')] = respond(200, diff)
    effect = Effect(
        'GET', '/v1/raw', accept='application/vnd.github.diff', response='text'
    )
    assert (
        executor(service).execute(authorized(effect), SERVICE_TOKEN)
        == diff.decode()
    )
    assert (
        service.requests[0]['headers']['accept']
        == 'application/vnd.github.diff'
    )
    service.routes[('GET', '/v1/raw')] = respond(200, b'\xff\xfe')
    assert failed(
        executor(service).execute, authorized(effect), SERVICE_TOKEN
    ).code == ('upstream_response')


def test_the_github_preset_reaches_only_its_constructed_routes(service):
    """The built-in manifest through the same executor, on a stand-in host."""
    spec = parse_policy(github_policy())
    request = spec.parse_request(
        {
            'operation': 'pr.checks',
            'arguments': {'repository': REPO, 'pr': 13861},
        }
    )
    base = '/repos/taucetiproject/tauceti'
    service.routes[('GET', f'{base}/pulls/13861')] = metadata()
    checks = f'{base}/commits/{"a" * 40}/check-runs?page=1&per_page=100'
    service.routes[('GET', checks)] = {'check_runs': []}
    runner = executor(service, headers=spec.egress.headers)
    facts = runner.execute(
        authorized(must(spec.preflight(request)), final=False), SERVICE_TOKEN
    )
    result = runner.execute(
        authorized(must(spec.final(request, facts))), SERVICE_TOKEN
    )
    assert result == {'check_runs': []}
    assert [seen['target'] for seen in service.requests] == [
        f'{base}/pulls/13861',
        checks,
    ]
    for seen in service.requests:
        assert seen['headers']['x-github-api-version'] == '2026-03-10'
        assert seen['headers']['accept'] == 'application/vnd.github+json'


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_https_provider_never_redirects_or_retries(service, status):
    elsewhere = respond(status, b'', Location='https://attacker.invalid/steal')
    service.routes[('GET', '/v1/issues/23?page=2')] = elsewhere
    service.routes[('GET', '/steal')] = {'followed': True}
    error = failed(executor(service).execute, authorized(READ), SERVICE_TOKEN)
    assert (error.code, error.status) == ('upstream_error', status)
    assert (
        len(service.requests) == 1
    )  # one request; the Location was not chased


STATUSES_4XX = [400, 401, 403, 404, 409, 422, 429]


@pytest.mark.parametrize('status', STATUSES_4XX)
def test_a_refused_read_is_definite(service, status):
    """4xx to a read: the service answered, and there was nothing to apply."""
    provider_text = b'{"message":"token ghp_PROVIDERTEXT is invalid"}'
    service.routes[('GET', '/v1/issues/23?page=2')] = respond(
        status, provider_text
    )
    error = failed(executor(service).execute, authorized(READ), SERVICE_TOKEN)
    assert (error.code, error.status) == ('upstream_rejected', status)
    # No provider text is carried by the error, only the bounded status.
    assert 'PROVIDERTEXT' not in str(error) + error.detail
    assert len(service.requests) == 1  # never retried, 429 included


@pytest.mark.parametrize('status', STATUSES_4XX)
def test_a_write_answered_4xx_may_still_have_been_applied(service, status):
    """No HTTP status proves a sent write did nothing.

    This provider *applies* the comment and then answers 4xx -- a conflict
    detected after the fact, a validation error from a later stage. Calling
    that "rejected" would invite the very retry that duplicates it.
    """
    applied = []

    def apply_then_refuse(seen):
        applied.append(seen['body'])
        return status, {}, b'{"message":"ghp_PROVIDERTEXT conflict"}'

    service.routes[('POST', '/v1/issues/23/comments')] = apply_then_refuse
    error = failed(executor(service).execute, authorized(WRITE), SERVICE_TOKEN)
    assert (error.code, error.status) == ('outcome_unknown', status)
    assert 'PROVIDERTEXT' not in str(error) + error.detail
    assert len(applied) == 1 and len(service.requests) == 1


@pytest.mark.parametrize('status', [404, 409, 500, 302])
def test_a_declared_write_is_a_write_whatever_its_method(service, status):
    """The verdict follows the manifest's ``effect``, not ``GET`` vs ``POST``."""
    service.routes[('GET', '/v1/issues/23/close')] = respond(status)
    declared = authorized(TOGGLE, write=True)
    error = failed(executor(service).execute, declared, SERVICE_TOKEN)
    assert (error.code, error.status) == ('outcome_unknown', status)
    # The very same request, declared a read, is an ordinary read failure.
    plain = failed(executor(service).execute, authorized(TOGGLE), SERVICE_TOKEN)
    assert plain.code in ('upstream_rejected', 'upstream_error')
    assert len(service.requests) == 2


def test_a_declared_write_that_succeeds_is_just_a_result(service):
    service.routes[('GET', '/v1/issues/23/close')] = {'closed': True}
    declared = authorized(TOGGLE, write=True)
    assert executor(service).execute(declared, SERVICE_TOKEN) == {
        'closed': True
    }


@pytest.mark.parametrize('status', [500, 502, 503, 504])
def test_a_server_error_leaves_a_write_unknown(service, status):
    service.routes[('GET', '/v1/issues/23?page=2')] = respond(status)
    service.routes[('POST', '/v1/issues/23/comments')] = respond(status)
    read = failed(executor(service).execute, authorized(READ), SERVICE_TOKEN)
    assert (read.code, read.status) == ('upstream_error', status)
    write = failed(executor(service).execute, authorized(WRITE), SERVICE_TOKEN)
    assert (write.code, write.status) == ('outcome_unknown', status)
    assert len(service.requests) == 2


@pytest.mark.parametrize(
    'body,headers',
    [
        (b'x' * (MAX_RESPONSE + 1), {}),
        (b'{"secret":NaN}', {}),
        (b'{"a":1,"a":2}', {}),
        (b'broken-json', {}),
        (b'{}', {'Content-Encoding': 'gzip'}),
        (b'{}', {'Content-Encoding': 'br'}),
    ],
    ids=['oversized', 'nan', 'duplicate-key', 'not-json', 'gzip', 'brotli'],
)
def test_egress_rejects_unbounded_or_ambiguous_payloads(service, body, headers):
    service.routes[('GET', '/v1/issues/23?page=2')] = respond(
        200, body, **headers
    )
    service.routes[('POST', '/v1/issues/23/comments')] = respond(
        200, body, **headers
    )
    read = failed(executor(service).execute, authorized(READ), SERVICE_TOKEN)
    assert read.code == 'upstream_response'
    # The same unusable answer to a write means it may well have happened.
    write = failed(executor(service).execute, authorized(WRITE), SERVICE_TOKEN)
    assert write.code == 'outcome_unknown'


def test_a_response_exactly_at_the_limit_is_accepted(service):
    body = b'"' + b'x' * (MAX_RESPONSE - 2) + b'"'
    service.routes[('GET', '/v1/issues/23?page=2')] = respond(200, body)
    assert (
        len(executor(service).execute(authorized(READ), SERVICE_TOKEN))
        == MAX_RESPONSE - 2
    )


def test_tls_identity_is_the_policy_host_whatever_address_is_pinned(
    service, tmp_path
):
    service.routes[('GET', '/v1/issues/23?page=2')] = {'ok': True}
    # Right address, wrong name: the certificate is not for this host.
    wrong_name = failed(
        executor(service, host='other.secrets-test.example').execute,
        authorized(READ), SERVICE_TOKEN,
    )  # fmt: skip
    assert wrong_name.code == 'unreachable'
    # Right name, but a CA the operator did not pin.
    (tmp_path / 'other').mkdir()
    stranger = make_certificates(tmp_path / 'other')['ca']
    untrusted = failed(
        executor(service, ca_file=str(stranger)).execute,
        authorized(READ),
        SERVICE_TOKEN,
    )
    assert untrusted.code == 'unreachable'
    # ...and the public roots do not vouch for it either.
    public = failed(
        executor(service, ca_file='').execute, authorized(READ), SERVICE_TOKEN
    )
    assert public.code == 'unreachable'
    assert service.requests == []  # no request, and no credential, was sent


def test_connection_failure_is_definite_even_for_a_write(service):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        closed_port = probe.getsockname()[1]
    for effect in (READ, WRITE):
        error = failed(
            executor(service, port=closed_port).execute,
            authorized(effect),
            SERVICE_TOKEN,
        )
        assert error.code == 'unreachable'


class RawTLSPeer:
    """A TLS endpoint that misbehaves after the handshake, as scripted."""

    def __init__(self, directory, behave):
        import ssl

        self.files = make_certificates(directory)
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(self.files['cert'], self.files['key'])
        self._listener = socket.socket()
        self._listener.bind(('127.0.0.1', 0))
        self._listener.listen(4)
        self._behave = behave
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while True:
            try:
                raw, _ = self._listener.accept()
            except OSError:
                return
            try:
                with self._context.wrap_socket(raw, server_side=True) as peer:
                    peer.recv(65536)
                    self._behave(peer)
            except OSError:
                pass

    def __enter__(self):
        self._thread.start()
        return HTTPSExecutor(
            Egress(
                TLS_HOST,
                self._listener.getsockname()[1],
                '127.0.0.1',
                str(self.files['ca']),
            )
        )

    def __exit__(self, *exc):
        # shutdown() wakes the blocked accept(); close() alone would not.
        self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        self._thread.join(5)


def test_a_dropped_connection_after_sending_leaves_a_write_unknown(tmp_path):
    """Bytes went out, nothing came back: only reads may call that an error."""
    with RawTLSPeer(tmp_path, lambda peer: None) as runner:
        read = failed(runner.execute, authorized(READ), SERVICE_TOKEN)
        write = failed(runner.execute, authorized(WRITE), SERVICE_TOKEN)
        toggle = failed(
            runner.execute, authorized(TOGGLE, write=True), SERVICE_TOKEN
        )
    assert (read.code, write.code) == ('upstream_error', 'outcome_unknown')
    assert toggle.code == 'outcome_unknown'


def test_a_trickling_peer_cannot_outlive_the_total_deadline(
    tmp_path, monkeypatch
):
    """Per-read socket timeouts alone would let this run for minutes.

    The peer sends headers promising a megabyte, then one byte every 0.2s:
    every individual read succeeds well inside the socket timeout.
    """
    monkeypatch.setattr(egress_module, 'TOTAL_DEADLINE', 1.0)

    def trickle(peer):
        peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n')
        for _ in range(100):
            peer.sendall(b' ')
            time.sleep(0.2)

    with RawTLSPeer(tmp_path, trickle) as runner:
        started = time.monotonic()
        read = failed(runner.execute, authorized(READ), SERVICE_TOKEN)
        elapsed = time.monotonic() - started
        assert read.code == 'upstream_error'
        assert 0.8 < elapsed < 5, elapsed
        write = failed(runner.execute, authorized(WRITE), SERVICE_TOKEN)
        assert write.code == 'outcome_unknown'


@pytest.mark.parametrize(
    'bad',
    [
        Effect('GET', '/v1/../admin'),
        Effect('GET', '//attacker.invalid/x'),
        Effect('GET', '/v1/x', (('q', 'a b'),)),
        Effect('GET', '/v1/x\r\nHost: attacker.invalid'),
        Effect('DELETE', '/v1/x'),
        Effect('GET', '/v1/x', accept='text/plain\r\nX-Injected: 1'),
        Effect('POST', '/v1/x'),
        Effect('GET', '/v1/x', body=(('b', 'x'),)),
    ],
)
def test_the_executor_rechecks_the_effect_grammar(service, bad):
    error = failed(executor(service).execute, authorized(bad), SERVICE_TOKEN)
    assert error.code == 'denied'
    assert service.requests == []


def test_only_a_kernel_authorization_is_executable(service):
    runner = executor(service)
    for forged in [READ, ('GET', '/v1/x'), {'effect': READ}, None]:
        assert failed(runner.execute, forged, SERVICE_TOKEN).code == 'denied'
    for inconsistent in (
        # A preflight is by definition read-only ...
        authorized(WRITE, final=False),
        authorized(TOGGLE, final=False, write=True),
        # ... and a request with a body is never a declared read.
        authorized(WRITE, write=False),
    ):
        assert (
            failed(runner.execute, inconsistent, SERVICE_TOKEN).code == 'denied'
        )
    assert service.requests == []


def test_an_unsafe_trust_anchor_stops_the_session_before_any_request(
    service, tmp_path
):
    anchor = service.files['ca']
    anchor.chmod(0o666)
    error = failed(executor, service)
    assert error.code == 'unsafe_file'
    anchor.chmod(0o644)
    garbage = tmp_path / 'garbage.pem'
    garbage.write_text('not a certificate')
    garbage.chmod(0o644)
    assert (
        failed(lambda: executor(service, ca_file=str(garbage))).code
        == 'unsafe_file'
    )
    assert failed(
        lambda: executor(service, ca_file=str(tmp_path / 'missing'))
    ).code == ('unsafe_file')


def test_tls_context_is_strict(service):
    import ssl

    context = egress_module.tls_context(Egress('api.example.org'))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    pinned = executor(service)._context
    assert pinned.check_hostname and pinned.verify_mode == ssl.CERT_REQUIRED
    # A pinned anchor replaces the system roots; it does not add to them.
    assert len(pinned.get_ca_certs()) == 1
