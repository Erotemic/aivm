"""Deterministic, offline fixtures for the secret-use broker.

Two fakes live here, one for each real boundary of the broker:

``FakeExecutor``  stands in for the provider *inside* the process, for tests
                  about orchestration. It only accepts what the kernel
                  authorized, like the real executor.
``TLSService``    is a real HTTPS server on loopback with a throwaway CA. The
                  real executor, a real ``aivm-secrets serve`` child and the
                  real-VM e2e suite all talk to it over genuine verified TLS.

No test in this suite uses a real credential or contacts a real provider.
"""

from __future__ import annotations

import copy
import datetime
import http.server
import json
import os
import ssl
import threading
from pathlib import Path
from typing import Any, Callable, TypeVar

from aivm_secrets.host.broker import Broker
from aivm_secrets.kernel import codec
from aivm_secrets.kernel.machine import AuthorizedEffect
from aivm_secrets.kernel.model import Binding
from aivm_secrets.kernel.service import parse_policy

T = TypeVar('T')

TOKEN = 'github_pat_TEST_ONLY_NOT_A_REAL_CREDENTIAL_123456789'
SERVICE_TOKEN = 'service_TOKEN_NOT_REAL_0123456789abcdef'
TLS_HOST = 'api.secrets-test.example'
REPO = 'TauCetiProject/TauCeti'


def must(value: T | None) -> T:
    """Narrow an optional the test expects to be present."""
    assert value is not None
    return value


def github_policy(**changes: Any) -> dict[str, Any]:
    data = {
        'schema': 1,
        'repository': REPO,
        'pr_numbers': [13861, 13862],
        'operations': [
            'pr.view',
            'pr.diff',
            'pr.comments',
            'pr.reviews',
            'pr.review-comments',
            'pr.checks',
            'pr.comment',
            'pr.edit',
        ],
        'author': 'Erotemic',
        'head_repository': 'Erotemic/TauCeti',
        'lifetime_seconds': 1800,
        'max_requests': 20,
        'max_body_bytes': 8192,
    }
    data.update(changes)
    return data


def https_policy(**changes: Any) -> dict[str, Any]:
    data = {
        'schema': 2,
        'adapter': 'https',
        'service': 'demo-service',
        'host': 'api.example.org',
        'authentication': 'x-api-key',
        'credential_source': {
            'kind': 'command',
            'argv': ['mytool', 'auth', 'print-token'],
            'inherit_env': ['XDG_CONFIG_HOME'],
        },
        'operations': [
            {
                'name': 'profile.read',
                'effect': 'read',
                'method': 'GET',
                'path': '/v1/account',
            },
            {
                'name': 'issue.view',
                'effect': 'read',
                'method': 'GET',
                'path': '/v1/issues/{issue}',
                'parameters': {'issue': [23, 24]},
            },
            {
                'name': 'issue.list',
                'effect': 'read',
                'method': 'GET',
                'path': '/v1/issues',
                'query': {'state': 'open', 'page': '{page}'},
                'parameters': {'page': {'min': 1, 'max': 50}},
            },
            {
                'name': 'issue.comment',
                'effect': 'write',
                'method': 'POST',
                'path': '/v1/issues/{issue}/comments',
                'parameters': {'issue': [23, 24]},
                'body_fields': {'body': 100},
            },
        ],
        'lifetime_seconds': 1800,
        'max_requests': 5,
        'max_body_bytes': 100,
    }
    data.update(changes)
    return data


PROJECT = 'acme/widgets'
REVISION = 'c0ffee' + '0' * 34


def tracker_policy(**changes: Any) -> dict[str, Any]:
    """A manifest using every general feature, for an invented provider.

    It has a fact check with literal, parameter and case-folded
    requirements and three bound facts; an operation whose answer is the
    check itself; a paged read built from bound facts; a write with an
    optional field; a state-changing ``GET`` declared as a write; and a
    command table. Nothing in it is specific to any real service.
    """
    target = {'project': [PROJECT], 'ticket': [7, 8]}
    data = https_policy(
        service='tracker',
        authentication='bearer',
        checks={
            'ticket': {
                'path': '/v1/projects/{project}/tickets/{ticket}',
                'require': [
                    {'at': ['id'], 'equals_parameter': 'ticket'},
                    {
                        'at': ['project', 'slug'],
                        'equals_parameter': 'project',
                        'fold': True,
                    },
                    {'at': ['state'], 'equals': 'open'},
                    {'at': ['owner', 'name'], 'equals': 'alice', 'fold': True},
                    {'at': ['version'], 'equals': 2},
                ],
                'bind': {
                    'revision': {'at': ['head', 'rev'], 'format': 'hex'},
                    'serial': {'at': ['serial'], 'format': 'integer'},
                    'branch': {'at': ['branch'], 'format': 'segment'},
                },
            }
        },
        operations=[
            {
                'name': 'ticket.view',
                'effect': 'read',
                'requires': 'ticket',
                'returns': 'check',
                'parameters': target,
                'fold': ['project'],
            },
            {
                'name': 'ticket.builds',
                'effect': 'read',
                'requires': 'ticket',
                'method': 'GET',
                'path': '/v1/projects/{project}/revisions/{revision}'
                '/builds/{serial}/{branch}',
                'query': {'page': '{page}', 'per_page': '50'},
                'parameters': dict(target, page={'min': 1, 'max': 9}),
                'defaults': {'page': 1},
                'fold': ['project'],
                'page': {'size': 50, 'at': ['builds'], 'parameter': 'page'},
            },
            {
                'name': 'ticket.note',
                'effect': 'write',
                'requires': 'ticket',
                'method': 'POST',
                'path': '/v1/projects/{project}/tickets/{ticket}/notes',
                'parameters': target,
                'fold': ['project'],
                'body_fields': {
                    'text': 100,
                    'title': {'max_bytes': 20, 'optional': True},
                },
            },
            {
                # A provider with a state-changing GET: the manifest says so.
                'name': 'ticket.close',
                'effect': 'write',
                'method': 'GET',
                'path': '/v1/projects/{project}/tickets/{ticket}/close',
                'parameters': target,
                'fold': ['project'],
            },
            {
                'name': 'ticket.log',
                'effect': 'read',
                'method': 'GET',
                'path': '/v1/tickets/{ticket}/log',
                'parameters': {'ticket': [7, 8]},
                'response': 'text',
            },
        ],
        cli={
            'tk': [
                {
                    'command': ['view'],
                    'operation': 'ticket.view',
                    'positional': ['ticket'],
                    'options': {'--project': 'project', '-p': 'project'},
                },
                {
                    'command': ['builds', 'list'],
                    'operation': 'ticket.builds',
                    'positional': ['ticket'],
                    'options': {'--project': 'project', '--page': 'page'},
                },
                {
                    'command': ['note'],
                    'operation': 'ticket.note',
                    'positional': ['project', 'ticket'],
                    'options': {
                        '--text': 'text',
                        '--text-file': '@text',
                        '--title': 'title',
                    },
                },
                {
                    'command': ['log'],
                    'operation': 'ticket.log',
                    'positional': ['ticket'],
                    'output': 'result',
                },
            ]
        },
        max_requests=20,
    )
    data.update(changes)
    return data


def tracker_facts() -> dict[str, Any]:
    """A provider answer that satisfies ``tracker_policy``'s check."""
    return {
        'id': 7,
        'project': {'slug': 'Acme/Widgets'},
        'state': 'open',
        'owner': {'name': 'Alice'},
        'version': 2,
        'head': {'rev': REVISION.upper()},
        'serial': 31,
        'branch': 'main',
    }


def write_private(path: Path, data: bytes, mode: int = 0o600) -> Path:
    """Create a file with an exact mode, irrespective of the caller's umask.

    A group-writable default umask (0002) must not turn a positive policy
    test into an ``unsafe_file`` failure.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
    return path


def write_policy_file(path: Path, data: dict[str, Any] | None = None) -> Path:
    return write_private(path, codec.dumps(data or github_policy()))


def metadata() -> dict[str, Any]:
    return {
        'number': 13861,
        'title': 'Proof repair',
        'body': 'Example',
        'base': {'repo': {'full_name': REPO}},
        'head': {'repo': {'full_name': 'Erotemic/TauCeti'}, 'sha': 'a' * 40},
        'user': {'login': 'Erotemic'},
    }


class FakeExecutor:
    """An in-process provider. Records ``(effect, credential)`` per call."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, str]] = []
        self.metadata = metadata()
        self.result: Any = []
        self.after_metadata: Callable[[], None] | None = None

    def execute(self, authorized: Any, credential: str) -> Any:
        # The real executor refuses anything the kernel did not mint.
        assert type(authorized) is AuthorizedEffect
        effect = authorized.effect
        self.calls.append((effect, credential))
        if not authorized.final:
            if self.after_metadata:
                self.after_metadata()
            return copy.deepcopy(self.metadata)
        if effect.response == 'text':
            return 'diff --git a/proof.lean b/proof.lean\n'
        if effect.path.endswith('/check-runs'):
            return {
                'total_count': 1,
                'check_runs': [{'name': 'lean', 'status': 'completed'}],
            }
        if '/builds/' in effect.path:
            return {'builds': copy.deepcopy(self.result)}
        if effect.path.startswith('/v1/'):
            body = dict(effect.body) if effect.body is not None else None
            return {'ok': True, 'path': effect.target, 'body': body}
        return copy.deepcopy(self.result)

    @property
    def methods(self) -> list[str]:
        return [effect.method for effect, _ in self.calls]


class Clock:
    wall = 1000
    monotonic = 100


class Harness:
    """One in-process broker with injected clocks and a fake provider."""

    def __init__(
        self,
        path: Path,
        *,
        policy: dict[str, Any] | None = None,
        writes: str = 'deny',
        executor: Any = None,
        token: str = TOKEN,
        **policy_changes: Any,
    ) -> None:
        self.executor = executor or FakeExecutor()
        self.clock = Clock()
        data = policy if policy is not None else github_policy()
        self.spec = parse_policy(dict(data, **policy_changes))
        self.binding = Binding(
            os.getuid(), 'principal-test', 'vm-test', 'b' * 32
        )
        self.audit = path / 'audit' / 'session.jsonl'
        self.token = token
        self.broker = Broker(
            self.spec,
            self.binding,
            token,
            self.audit,
            writes=writes,
            executor=self.executor,
            wall_clock=lambda: self.clock.wall,
            monotonic_clock=lambda: self.clock.monotonic,
        )
        self.capability = self.broker.capability

    def frame(
        self, verb: str, payload: Any, capability: str | None = None
    ) -> bytes:
        return codec.dumps(
            {
                'version': 1,
                'capability': capability or self.capability,
                verb: payload,
            }
        )

    def raw(self, operation: str = 'pr.view', **changes: Any) -> bytes:
        """A request frame for PR 13861 of the GitHub preset."""
        arguments = {'repository': REPO, 'pr': 13861}
        arguments.update(changes)
        payload = {'operation': operation, 'arguments': arguments}
        return self.frame('request', payload)

    def call(
        self, operation: str = 'pr.view', **changes: Any
    ) -> dict[str, Any]:
        return self.broker.handle(self.raw(operation, **changes))

    def invoke(
        self, operation: str, capability: str | None = None, **arguments: Any
    ) -> dict[str, Any]:
        """A generic ``{operation, arguments}`` request."""
        payload = {'operation': operation, 'arguments': arguments}
        return self.broker.handle(self.frame('request', payload, capability))

    def send(
        self, verb: str, payload: Any = True, capability: str | None = None
    ) -> dict[str, Any]:
        return self.broker.handle(self.frame(verb, payload, capability))

    def events(self) -> list[str]:
        return [row['event'] for row in self.rows()]

    def rows(self) -> list[dict[str, Any]]:
        return [
            json.loads(line) for line in self.audit.read_text().splitlines()
        ]


# ---------------------------------------------------------------------------
# A real HTTPS provider on loopback
# ---------------------------------------------------------------------------


def make_certificates(directory: Path, host: str = TLS_HOST) -> dict[str, Path]:
    """Mint a throwaway CA and one server certificate for ``host``."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def name(common: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

    def pem(key: Any) -> bytes:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name('aivm-secrets test CA'))
        .issuer_name(name('aivm-secrets test CA'))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name(host))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        # Python 3.13 verifies with VERIFY_X509_STRICT, which requires the
        # key identifiers real CAs always include.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    encoding = serialization.Encoding.PEM
    return {
        'ca': write_private(
            directory / 'ca.pem', ca.public_bytes(encoding), 0o644
        ),
        'cert': write_private(
            directory / 'server.pem', leaf.public_bytes(encoding), 0o644
        ),
        'key': write_private(directory / 'server.key', pem(key)),
    }


Route = Callable[[dict[str, Any]], tuple[int, dict[str, str], bytes]]


class TLSService:
    """A recording HTTPS service with operator-defined routes.

    ``routes`` maps ``(method, target)`` to a JSON-able value (served as 200)
    or to a callable returning ``(status, headers, body)``. Every request is
    appended to ``requests`` with its method, target, headers and body, so a
    test can assert on exactly what reached "the provider".
    """

    def __init__(self, directory: Path, host: str = TLS_HOST) -> None:
        self.host = host
        self.files = make_certificates(directory, host)
        self.routes: dict[tuple[str, str], Any] = {}
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def _serve(self) -> None:
                length = int(self.headers.get('Content-Length', '0') or 0)
                body = self.rfile.read(length) if length else b''
                seen = {
                    'method': self.command,
                    'target': self.path,
                    'headers': {k.lower(): v for k, v in self.headers.items()},
                    'body': body.decode('utf-8', 'replace'),
                }
                with service._lock:
                    service.requests.append(seen)
                route = service.routes.get((self.command, self.path))
                if route is None:
                    status, headers, data = 404, {}, b'{"message":"Not Found"}'
                elif callable(route):
                    status, headers, data = route(seen)
                else:
                    status, headers = 200, {}
                    data = json.dumps(route).encode()
                self.send_response(status)
                headers = {'Content-Type': 'application/json', **headers}
                headers.setdefault('Content-Length', str(len(data)))
                headers.setdefault('Connection', 'close')
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                try:
                    self.wfile.write(data)
                except OSError:
                    pass
                self.close_connection = True

            do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _serve

            def log_message(self, format: str, *args: Any) -> None:
                return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.files['cert'], self.files['key'])
        self._server = http.server.ThreadingHTTPServer(
            ('127.0.0.1', 0), Handler
        )
        self._server.daemon_threads = True
        self._server.socket = context.wrap_socket(
            self._server.socket, server_side=True
        )
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={'poll_interval': 0.05},
            daemon=True,
        )

    def __enter__(self) -> TLSService:
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def egress(self, **changes: Any) -> dict[str, Any]:
        """The policy ``egress`` pins that route ``host`` to this server."""
        pins = {
            'address': '127.0.0.1',
            'port': self.port,
            'ca_file': str(self.files['ca']),
        }
        pins.update(changes)
        return pins

    def policy(self, token_file: Path, **changes: Any) -> dict[str, Any]:
        """A schema-2 policy whose one destination is this server."""
        data = https_policy(
            service='e2e-service',
            host=self.host,
            authentication='bearer',
            egress=self.egress(),
            credential_source={'kind': 'file', 'path': str(token_file)},
        )
        data.update(changes)
        return data

    def seen(self, method: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [
                item
                for item in self.requests
                if method is None or item['method'] == method
            ]


# ---------------------------------------------------------------------------
# A real broker process
# ---------------------------------------------------------------------------


def poison(directory: Path) -> Path:
    """Fill ``directory`` with everything a hostile ``PYTHONPATH`` can hold.

    A shadow ``aivm_secrets`` package, a ``sitecustomize.py`` and a
    ``usercustomize.py``. Each appends the command line of the process that
    imported it to the returned marker file, so a test can tell *which*
    process ran guest-supplied code.
    """
    marker = directory / 'ran-guest-code'
    record = (
        'import os\n'
        f'with open({str(marker)!r}, "ab") as stream:\n'
        '    stream.write(open("/proc/self/cmdline", "rb").read() + b"\\n")\n'
    )
    shadow = directory / 'aivm_secrets'
    shadow.mkdir()
    (shadow / '__init__.py').write_text(record)
    (shadow / '__main__.py').write_text(
        'import json\n'
        'print(json.dumps({"channel": "SHADOW", "socket": "/tmp/shadow"}))\n'
    )
    (shadow / 'errors.py').write_text('class SecretsError(Exception): pass\n')
    (directory / 'sitecustomize.py').write_text(record)
    (directory / 'usercustomize.py').write_text(record)
    return marker


def ran_as_broker(marker: Path) -> list[bytes]:
    """The broker processes, if any, that imported something from ``poison``."""
    if not marker.exists():
        return []
    return [
        line
        for line in marker.read_bytes().split(b'\n')
        if b'\x00aivm_secrets\x00serve' in line
    ]


def cli_env(root: Path, **extra: str) -> dict[str, str]:
    """An environment whose runtime and state directories live under ``root``.

    ``root`` must be short: a session's socket path is derived from it.
    """
    runtime = root / 'run'
    runtime.mkdir(mode=0o700, exist_ok=True)
    env = dict(os.environ)
    env.update(
        XDG_RUNTIME_DIR=str(runtime),
        XDG_STATE_HOME=str(root / 'state'),
        **extra,
    )
    return env


def run_cli_process(
    argv: list[str], *, env: dict[str, str], input: str | None = None
) -> Any:
    """Run ``aivm-secrets`` as an installed program would run it."""
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, '-I', '-m', 'aivm_secrets', *argv],
        env=env,
        input=input,
        capture_output=True,
        text=True,
        cwd='/',
        timeout=60,
    )


class ServeProcess:
    """``aivm-secrets serve`` as a child, bound to this object's lifetime."""

    def __init__(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        flags: tuple[str, ...] = ('-I',),
    ) -> None:
        import subprocess
        import sys

        self.env = env
        self.process = subprocess.Popen(
            [
                sys.executable,
                *flags,
                '-m',
                'aivm_secrets',
                'serve',
                '--announce',
                'json',
                '--exit-on-stdin-eof',
                *argv,
            ],  # fmt: skip
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd='/',
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        self.announce: dict[str, Any] = json.loads(line) if line else {}

    @property
    def ready(self) -> bool:
        return 'socket' in self.announce

    @property
    def capability(self) -> str:
        return Path(self.announce['capability_file']).read_text()

    def exchange(
        self, payload: Any, verb: str = 'request', capability: str = ''
    ) -> Any:
        from aivm_secrets import guest

        return guest.exchange(
            self.announce['socket'],
            capability or self.capability,
            payload,
            verb,
        )

    def invoke(self, operation: str, **arguments: Any) -> Any:
        return self.exchange({'operation': operation, 'arguments': arguments})

    def cli(self, *argv: str, input: str | None = None) -> Any:
        return run_cli_process(list(argv), env=self.env, input=input)

    def stop(self) -> int:
        process = self.process
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        code = process.wait(timeout=30)
        self.stderr = process.stderr.read().decode() if process.stderr else ''
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        return code

    def __enter__(self) -> ServeProcess:
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.process.poll() is None:
            self.stop()
        else:
            for stream in (
                self.process.stdin,
                self.process.stdout,
                self.process.stderr,
            ):
                if stream is not None and not stream.closed:
                    stream.close()
