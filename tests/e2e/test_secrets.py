"""End-to-end secret-use sessions against a real KVM guest.

This suite creates a real VM and then opens real, interactive
``aivm ssh --secrets_policy`` sessions on a pseudo-terminal. Nothing between
the guest and the provider is faked:

* the guest is a libvirt/KVM domain booted from the pinned cloud image;
* the channel is OpenSSH with a real streamlocal (``-R``) forward;
* the broker is the real ``aivm-secrets serve`` child that ``aivm ssh``
  starts, resolving its own credential;
* the provider is ``TLSService``: a real HTTPS server on the host, reached
  over verified TLS with a private trust anchor pinned in the policy.

Only the provider's *identity* is synthetic (a throwaway CA and a made-up
token), so no real credential is used and no third party is contacted.

Each test is a shell script the guest runs. Results leave the guest as files
in the shared workspace -- the same folder attachment an agent would work in
-- and are compared with three host-side records: what the provider actually
received, the session's audit file, and what is left on both machines
afterwards.

Run with ``AIVM_E2E=1``. For iterating on one test, ``AIVM_E2E_SECRETS_VM``
may name a JSON file describing an already running VM
(``home``/``priv``/``cfg``/``ip``/``vm``/``user``); that VM is then reused
and left running.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

from tests.e2e._helpers import (
    REPO_ROOT,
    Terminal,
    _host_context_enabled,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
    apply_shared_image_cache,
    e2e_teardown,
    make_e2e_config,
    require_passwordless_sudo,
    save_e2e_store,
)

pytestmark = pytest.mark.e2e

TOKEN = 'e2e_TOKEN_NOT_REAL_7f3a9c2e5b8d4f61a0c3'
SESSION_TIMEOUT = 300
PREAMBLE = """\
set -u
cd "$PWD/{name}"
OUT="$PWD/out"
mkdir -p "$OUT"
# run NAME COMMAND...: keep stdout, stderr and the exit status as files.
run() {{
    name=$1; shift
    "$@" > "$OUT/$name.out" 2> "$OUT/$name.err"
    echo $? > "$OUT/$name.rc"
}}
"""


def operations() -> list[dict[str, Any]]:
    def read(name: str, path: str, **more: Any) -> dict[str, Any]:
        return dict(name=name, effect='read', method='GET', path=path, **more)

    return [
        read('profile.read', '/v1/account'),
        read(
            'issue.view', '/v1/issues/{issue}', parameters={'issue': [23, 24]}
        ),
        read(
            'issue.list',
            '/v1/issues',
            query={'state': 'open', 'page': '{page}'},
            parameters={'page': {'min': 1, 'max': 5}},
        ),
        {
            'name': 'issue.comment',
            'effect': 'write',
            'method': 'POST',
            'path': '/v1/issues/{issue}/comments',
            'parameters': {'issue': [23]},
            'body_fields': {'body': 200},
        },
        {
            # The provider applies this one and *then* answers 409.
            'name': 'issue.label',
            'effect': 'write',
            'method': 'POST',
            'path': '/v1/issues/{issue}/labels',
            'parameters': {'issue': [23]},
            'body_fields': {'label': 40},
        },
        {
            # A state-changing GET, declared as the write it is.
            'name': 'issue.close',
            'effect': 'write',
            'method': 'GET',
            'path': '/v1/issues/{issue}/close',
            'parameters': {'issue': [23]},
        },
        read('debug.echo', '/v1/secret-echo'),
        read('debug.redirect', '/v1/moved'),
        read('debug.forbidden', '/v1/forbidden'),
        read('debug.text', '/v1/raw', response='text'),
    ]


@dataclass
class Lab:
    env: dict[str, str]
    cfg_path: Path
    vm: str
    user: str
    ip: str
    identity: Path
    workspace: Path
    private: Path
    runtime: Path
    state: Path
    service: Any
    token_file: Path
    timings: dict[str, float] = field(default_factory=dict)

    def policy(self, **changes: Any) -> dict[str, Any]:
        data = self.service.policy(self.token_file, operations=operations())
        data.update(changes)
        return data

    def guest(self, *remote: str, input: str | None = None) -> Any:
        """One non-interactive command in the guest, outside any session."""
        command = [
            'ssh', '-i', str(self.identity), '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', f'{self.user}@{self.ip}', *remote,
        ]  # fmt: skip
        return subprocess.run(
            command,
            env=self.env,
            input=input,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def secrets(self, *argv: str) -> Any:
        """The operator's ``aivm-secrets`` in another host terminal."""
        return subprocess.run(
            [sys.executable, '-I', '-m', 'aivm_secrets', *argv],
            env=self.env, capture_output=True, text=True, cwd='/', timeout=60,
        )  # fmt: skip


@dataclass
class Result:
    name: str
    code: int
    transcript: str
    out: Path
    channel: str
    audit: list[dict[str, Any]]
    requests: list[dict[str, Any]]

    def rc(self, step: str) -> int:
        return int((self.out / f'{step}.rc').read_text().strip())

    def text(self, step: str) -> str:
        return (self.out / f'{step}.out').read_text()

    def err(self, step: str) -> str:
        return (self.out / f'{step}.err').read_text().strip()

    def json(self, step: str) -> Any:
        return json.loads(self.text(step))

    def events(self) -> list[str]:
        return [row['event'] for row in self.audit]

    def targets(self, method: str | None = None) -> list[str]:
        return [
            item['target']
            for item in self.requests
            if method is None or item['method'] == method
        ]


def brokers(policy: Path) -> list[int]:
    """PIDs of ``aivm-secrets serve`` processes started for ``policy``.

    Matched on exact process arguments, not on a substring of the command
    line: a shell, an editor or a developer's own unrelated session that
    merely mentions the words must not be mistaken for this test's broker.
    """
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / 'cmdline').read_bytes().decode(errors='replace')
        except OSError:
            continue
        words = argv.split('\0')
        if (
            'aivm_secrets' in words
            and 'serve' in words
            and str(policy) in words
        ):
            found.append(int(entry.name))
    return found


def wait_for(path: Path, *, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f'{path} never appeared')
        time.sleep(0.1)


def open_session(
    lab: Lab,
    name: str,
    script: str,
    *,
    policy: dict[str, Any] | None = None,
    policy_path: Path | None = None,
    writes: str = 'deny',
    during: Callable[[Terminal, Path], None] | None = None,
    expect_session: bool = True,
    extra: tuple[str, ...] = (),
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    python_flags: tuple[str, ...] = (),
) -> Result:
    """Open one real ``aivm ssh`` secret session and run ``script`` in it."""
    from aivm_secrets.kernel import codec

    work = lab.workspace / name
    work.mkdir()
    out = work / 'out'
    (work / 'script.sh').write_text(PREAMBLE.format(name=name) + script + '\n')
    if policy_path is None:
        policy_path = lab.private / f'{name}.json'
        fd = os.open(policy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(codec.dumps(policy or lab.policy()))
    before = len(lab.service.requests)
    started = time.monotonic()
    terminal = Terminal(
        [
            sys.executable,
            *python_flags,
            '-m',
            'aivm',
            'ssh',
            str(lab.workspace),
            '--yes',
            '--config',
            str(lab.cfg_path),
            '--secrets_policy',
            str(policy_path),
            '--secrets_writes',
            writes,
            *extra,
        ],  # fmt: skip
        env=env or lab.env,
        cwd=cwd or REPO_ROOT,
    )
    if not expect_session:
        code = terminal.wait(timeout=SESSION_TIMEOUT)
        return Result(name, code, terminal.output, out, '', [], [])
    terminal.expect('Guest client:', timeout=SESSION_TIMEOUT)
    terminal.ready(timeout=90)
    lab.timings.setdefault('session_open_seconds', time.monotonic() - started)
    terminal.send(f'sh {shlex.quote(name)}/script.sh; exit\n')
    if during is not None:
        during(terminal, out)
    code = terminal.wait(timeout=SESSION_TIMEOUT)
    match = re.search(r'Secret session ([0-9a-f]{12})', terminal.output)
    assert match, terminal.output[-2000:]
    channel = match.group(1)
    audits = list((lab.state / 'secrets-audit').glob(f'{channel}*.jsonl'))
    rows = (
        [json.loads(line) for line in audits[0].read_text().splitlines()]
        if audits
        else []
    )
    return Result(
        name,
        code,
        terminal.output,
        out,
        channel,
        rows,
        lab.service.requests[before:],
    )


E2E_BASE_DIR = Path('/var/lib/libvirt/aivm-e2e')


def remove_vm_leftovers(
    vm: str, cfg_path: Path, *, env: dict[str, str], timeout_s: int
) -> None:
    """Remove what the shared teardown leaves behind for this module's VM.

    ``vm delete`` keeps the VM's record, so the plain ``host net destroy``
    that follows refuses to remove a network it still considers referenced;
    and the per-VM storage directory keeps its copy of the base image.

    That directory is also where persistent attachments bind-mount *host
    folders*. It is removed only when no mount point remains beneath it, so
    a recursive delete can never reach through a bind into a real project.
    """
    _run_cli(
        ['host', 'net', 'destroy', '--force', '--yes', '--config', str(cfg_path)],
        cwd=REPO_ROOT, timeout_s=timeout_s, env=env, check=False,
    )  # fmt: skip
    target = E2E_BASE_DIR / vm
    if not vm.startswith('aivm-e2e-sec-') or target.parent != E2E_BASE_DIR:
        return
    mounted = [
        line.split()[1]
        for line in Path('/proc/self/mounts').read_text().splitlines()
        if len(line.split()) > 1
    ]
    if any(
        point == str(target) or point.startswith(f'{target}/')
        for point in mounted
    ):
        print(f'leaving {target}: mounts remain beneath it')
        return
    subprocess.run(
        ['sudo', '-n', 'rm', '-rf', '--one-file-system', '--', str(target)],
        check=False,
    )


@pytest.fixture(scope='module')
def lab(tmp_path_factory: pytest.TempPathFactory) -> Any:
    if not _host_context_enabled():
        pytest.skip('Set AIVM_E2E=1 to run host-context e2e tests.')
    pytest.importorskip('cryptography')
    from tests.secrets_helpers import TLSService, write_private

    require_passwordless_sudo()
    root = tmp_path_factory.mktemp('secrets-e2e')
    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '2400'))
    reuse = os.getenv('AIVM_E2E_SECRETS_VM', '')
    teardown = None
    if reuse:
        meta = json.loads(Path(reuse).read_text())
        home, priv = Path(meta['home']), Path(meta['priv'])
        cfg_path = Path(meta['cfg'])
        vm, user, ip = meta['vm'], meta['user'], meta['ip']
        state = cfg_path.parent / 'state'
        env = os.environ.copy()
        env['HOME'] = str(home)
    else:
        home, priv, pub = _make_temp_ssh_material(root)
        env = os.environ.copy()
        env['HOME'] = str(home)
        _require_e2e_host_dependencies(
            cwd=REPO_ROOT, timeout_s=timeout_s, env=env
        )
        cfg_path = root / 'e2e-secrets.toml'
        cfg = make_e2e_config(
            root, priv=priv, pub=pub, name_prefix='aivm-e2e-sec'
        )
        apply_shared_image_cache(cfg)
        save_e2e_store(cfg_path, cfg)
        teardown = e2e_teardown(cfg_path, env=env, timeout_s=timeout_s)
        teardown.__enter__()
        try:
            for argv in (['host', 'net', 'create'], ['vm', 'up']):
                _run_cli(
                    [*argv, '--yes', '--config', str(cfg_path)],
                    cwd=REPO_ROOT, timeout_s=timeout_s, env=env,
                )  # fmt: skip
            waited = _run_cli(
                ['vm', 'wait_ip', '--yes', '--config', str(cfg_path)],
                cwd=REPO_ROOT, timeout_s=timeout_s, env=env,
            )  # fmt: skip
        except BaseException:
            teardown.__exit__(None, None, None)
            raise
        vm, user = cfg.vm.name, cfg.vm.user
        ip = waited.stdout.strip().splitlines()[-1]
        state = Path(cfg.paths.state_dir)
    # Sockets need a short path; pytest's tmp tree is too deep for sun_path.
    runtime = Path(tempfile.mkdtemp(prefix='as-', dir='/tmp'))
    env['XDG_RUNTIME_DIR'] = str(runtime)
    env.pop('AIVM_SECRETS_SOCKET', None)
    workspace = root / 'workspace'
    workspace.mkdir()
    private = root / 'private'
    private.mkdir(mode=0o700)
    token_file = write_private(private / 'token', (TOKEN + '\n').encode())
    try:
        with TLSService(private) as service:
            service.routes.update(
                {
                    ('GET', '/v1/account'): {'login': 'e2e-operator'},
                    ('GET', '/v1/issues/23'): {'id': 23, 'title': 'First issue'},
                    ('GET', '/v1/issues/24'): {'id': 24, 'title': 'Second issue'},
                    ('GET', '/v1/issues?page=2&state=open'): [{'id': 31}, {'id': 32}],
                    ('POST', '/v1/issues/23/comments'): lambda seen: (
                        201, {}, b'{"created":true}'
                    ),
                    ('GET', '/v1/issues/23/close'): {'state': 'closed'},
                    # Applied, then refused: see ``conflicts``.
                    ('POST', '/v1/issues/23/labels'): lambda seen: (
                        409, {}, b'{"message":"label already present"}'
                    ),
                    # A provider that reflects the credential it was sent.
                    ('GET', '/v1/secret-echo'): lambda seen: (
                        200, {},
                        json.dumps({'you_sent': seen['headers']['authorization']}).encode(),
                    ),
                    ('GET', '/v1/moved'): lambda seen: (
                        302, {'Location': '/v1/account'}, b''
                    ),
                    ('GET', '/v1/forbidden'): lambda seen: (
                        403, {}, b'{"message":"provider says no, token was ' + b'x' * 8 + b'"}'
                    ),
                    ('GET', '/v1/raw'): lambda seen: (
                        200, {'Content-Type': 'text/plain'}, b'line one\nline two\n'
                    ),
                }
            )  # fmt: skip
            yield Lab(
                env, cfg_path, vm, user, ip, priv, workspace, private, runtime,
                state, service, token_file,
            )  # fmt: skip
    finally:
        shutil.rmtree(runtime, ignore_errors=True)
        if teardown is not None:
            teardown.__exit__(None, None, None)
            remove_vm_leftovers(vm, cfg_path, env=env, timeout_s=timeout_s)


# ---------------------------------------------------------------------------
# The core claim: the guest can use a credential it never holds
# ---------------------------------------------------------------------------


def test_reads_reach_the_provider_with_a_credential_the_guest_never_holds(
    lab: Lab,
) -> None:
    probes: dict[str, str] = {}

    def look_inside_the_guest(terminal: Terminal, out: Path) -> None:
        wait_for(out / 'hold')
        # While the session is live: search the guest's disk, every process
        # environment and every command line for the credential. The needle
        # travels on stdin so that it is not itself in a command line.
        search = (
            'needle=$(cat); '
            'sudo grep -rIlF -- "$needle" /tmp /home /root /run /var/tmp /dev/shm /etc '
            '2>/dev/null | head -5; echo FILES_DONE; '
            'for p in /proc/[0-9]*; do sudo cat "$p/environ" 2>/dev/null; done '
            '| tr "\\0" "\\n" | grep -cF -- "$needle"; echo ENV_DONE; '
            'sudo ls -la /tmp/aivm-secrets-*/'
        )
        probes['search'] = lab.guest(search, input=TOKEN).stdout
        (out / 'release').touch()

    script = """
run operations aivm-secrets operations
run account aivm-secrets invoke profile.read
run view "$AIVM_SECRETS_CLIENT" invoke issue.view --arguments '{"issue":23}'
run list aivm-secrets invoke issue.list --arguments '{"page":2}'
run text aivm-secrets invoke debug.text --result-only
run other aivm-secrets invoke issue.view --arguments '{"issue":99}'
run typed aivm-secrets invoke issue.view --arguments '{"issue":"23"}'
run extra aivm-secrets invoke issue.view --arguments '{"issue":23,"url":"https://evil.invalid"}'
run unknown aivm-secrets invoke admin.delete
run write aivm-secrets invoke issue.comment --arguments '{"issue":23,"body":"hi"}'
run fallback aivm-secrets api /user
env | grep '^AIVM_SECRETS' | sort > "$OUT/env"
cp "$AIVM_SECRETS_CAPABILITY_FILE" "$OUT/capability"
touch "$OUT/hold"
i=0; while [ ! -e "$OUT/release" ] && [ $i -lt 300 ]; do sleep 0.2; i=$((i+1)); done
"""
    result = open_session(lab, 'reads', script, during=look_inside_the_guest)
    assert result.code == 0

    # What the guest was told.
    assert result.json('account')['result'] == {'login': 'e2e-operator'}
    assert result.json('view')['result'] == {'id': 23, 'title': 'First issue'}
    assert result.json('list')['result'] == [{'id': 31}, {'id': 32}]
    assert result.text('text') == 'line one\nline two\n'
    grant = result.json('operations')['grant']
    assert grant['writes'] == 'deny' and len(grant['operations']) == len(
        operations()
    )
    assert [result.rc(s) for s in ('account', 'view', 'list', 'text')] == [
        0,
        0,
        0,
        0,
    ]
    for step, code in [('other', 'denied'), ('typed', 'denied'), ('extra', 'invalid_request'),
                       ('unknown', 'denied'), ('write', 'denied')]:  # fmt: skip
        assert (result.rc(step), result.err(step)) == (
            3,
            f'aivm-secrets: {code}',
        ), step
    assert result.rc('fallback') == 2  # no stock-CLI or raw-API fallback

    # What the provider actually received: exactly the four authorized
    # reads, each carrying the real credential.
    assert result.targets() == [
        '/v1/account', '/v1/issues/23', '/v1/issues?page=2&state=open', '/v1/raw',
    ]  # fmt: skip
    for seen in result.requests:
        assert seen['method'] == 'GET'
        assert seen['headers']['authorization'] == 'Bearer ' + TOKEN
        assert seen['headers']['host'].startswith(lab.service.host)

    # What the guest held: ciphertext and three paths. Never the credential.
    capability = (result.out / 'capability').read_text().strip()
    assert capability.startswith('aivs1.') and TOKEN not in capability
    env = (result.out / 'env').read_text()
    assert sorted(line.split('=')[0] for line in env.split()) == [
        'AIVM_SECRETS_CAPABILITY_FILE', 'AIVM_SECRETS_CLIENT', 'AIVM_SECRETS_SOCKET',
    ]  # fmt: skip
    search = probes['search']
    files, rest = search.split('FILES_DONE')
    assert files.strip() == '', f'credential found on guest disk: {files}'
    assert rest.split('ENV_DONE')[0].strip() == '0', (
        'credential in a guest environment'
    )
    listing = rest.split('ENV_DONE')[1]
    assert (
        'drwx------' in listing
        and 'srw-------' in listing
        and '-rw-------' in listing
    )
    for produced in result.out.iterdir():
        assert TOKEN not in produced.read_text(errors='replace'), produced.name
    assert (
        TOKEN not in result.transcript and capability not in result.transcript
    )

    # What the host recorded.
    assert (
        result.events()[0] == 'session_open'
        and result.events()[-1] == 'session_close'
    )
    assert result.events().count('completed') == 4
    assert result.events().count('rejected_or_failed') == 5
    text = json.dumps(result.audit)
    assert (
        TOKEN not in text
        and capability not in text
        and 'evil.invalid' not in text
    )
    assert result.audit[0]['channel'].startswith(result.channel)


def test_session_teardown_leaves_nothing_usable_behind(lab: Lab) -> None:
    result = open_session(
        lab, 'teardown', 'run account aivm-secrets invoke profile.read'
    )
    assert result.rc('account') == 0
    # Guest: the session directory, client, capability and socket are gone.
    leftover = lab.guest(
        f'ls -d /tmp/aivm-secrets-{result.channel}* 2>&1; echo RC=$?'
    )
    assert 'RC=2' in leftover.stdout or 'No such file' in leftover.stdout
    # Host: the runtime directory is gone and no broker process remains.
    assert list((lab.runtime / 'aivm-secrets').iterdir()) == []
    assert 'No live secret sessions' in lab.secrets('sessions').stdout
    assert brokers(lab.private / 'teardown.json') == []
    # The audit file verifies as an unbroken chain.
    (audit,) = (lab.state / 'secrets-audit').glob(f'{result.channel}*.jsonl')
    verified = lab.secrets('audit-verify', str(audit))
    assert verified.returncode == 0 and 'chain intact' in verified.stdout


def test_a_plain_ssh_session_is_unchanged_by_the_feature(lab: Lab) -> None:
    """No policy, no broker, no client, no environment: nothing is implied."""
    work = lab.workspace / 'plain'
    work.mkdir()
    listing = 'ls -d /tmp/aivm-secrets-* 2>/dev/null | sort'
    before = lab.guest(listing).stdout
    terminal = Terminal(
        [sys.executable, '-m', 'aivm', 'ssh', str(lab.workspace), '--yes',
         '--config', str(lab.cfg_path)],
        env=lab.env, cwd=REPO_ROOT,
    )  # fmt: skip
    # The log line announcing the interactive command itself.
    terminal.expect('exec $SHELL -l', timeout=SESSION_TIMEOUT)
    terminal.ready(timeout=SESSION_TIMEOUT)
    terminal.send(
        'env | grep -c AIVM_SECRETS > plain/env; command -v aivm-secrets > plain/which; '
        f'{listing} > plain/dirs; exit\n'
    )
    assert terminal.wait(timeout=SESSION_TIMEOUT) == 0
    assert (work / 'env').read_text().strip() == '0'
    assert (work / 'which').read_text().strip() == ''
    assert (work / 'dirs').read_text() == before
    assert 'Secret session' not in terminal.output


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def test_an_allowed_write_sends_exactly_the_authorized_body(lab: Lab) -> None:
    script = """
run comment aivm-secrets invoke issue.comment --arguments '{"issue":23,"body":"Looks good: caf\\u00e9 \\"quoted\\""}'
run other aivm-secrets invoke issue.comment --arguments '{"issue":24,"body":"wrong issue"}'
printf '{"issue":23,"body":"%s"}' "$(head -c 250 /dev/zero | tr '\\0' x)" > big.json
run big aivm-secrets invoke issue.comment --arguments-file big.json
"""
    result = open_session(lab, 'write', script, writes='allow')
    assert result.rc('comment') == 0 and result.json('comment')['result'] == {
        'created': True
    }
    assert result.err('other') == 'aivm-secrets: denied'
    assert result.err('big') == 'aivm-secrets: denied'
    (post,) = result.requests
    assert (post['method'], post['target']) == (
        'POST',
        '/v1/issues/23/comments',
    )
    assert json.loads(post['body']) == {'body': 'Looks good: café "quoted"'}
    assert post['headers']['content-type'] == 'application/json'
    assert post['headers']['authorization'] == 'Bearer ' + TOKEN
    # The audit names the write and its resource, never its content.
    text = json.dumps(result.audit)
    assert 'Looks good' not in text and 'wrong issue' not in text
    dispatched = [row for row in result.audit if row['event'] == 'dispatch']
    assert [(row['operation'], row['resource']) for row in dispatched] == [
        ('issue.comment', {'issue': 23})
    ]


def test_a_write_waits_for_the_operators_approval_of_its_exact_content(
    lab: Lab,
) -> None:
    seen: dict[str, Any] = {}

    def operator(terminal: Terminal, out: Path) -> None:
        wait_for(out / 'first.rc')
        # Another host terminal: review what is pending, then approve it.
        pending = lab.secrets('pending')
        seen['pending'] = pending.stdout
        (item,) = json.loads(lab.secrets('pending', '--json').stdout)
        seen['arguments'] = item['arguments']
        seen['posts_before'] = len(lab.service.seen('POST'))
        approved = lab.secrets('approve', item['digest'][:16], '--yes')
        seen['approve'] = approved.stdout + approved.stderr
        assert approved.returncode == 0, seen['approve']

    comment = 'aivm-secrets invoke issue.comment --arguments \'{"issue":23,"body":"Please merge this."}\''
    script = f"""
run first {comment}
i=0
while [ $i -lt 150 ]; do
    {comment} > "$OUT/retry.out" 2> "$OUT/retry.err" && break
    sleep 0.2; i=$((i+1))
done
echo $? > "$OUT/retry.rc"
run again {comment}
run altered aivm-secrets invoke issue.comment --arguments '{{"issue":23,"body":"Please merge this!"}}'
run read aivm-secrets invoke issue.view --arguments '{{"issue":23}}'
"""
    before = len(lab.service.seen('POST'))
    result = open_session(
        lab, 'approve', script, writes='approve', during=operator
    )
    assert result.rc('first') == 4
    assert 'approval_required' in result.err('first')
    assert 'aivm-secrets approve' in result.err('first')
    # The operator was shown the exact bytes, and nothing had been sent yet.
    assert seen['arguments'] == {'issue': 23, 'body': 'Please merge this.'}
    assert (
        'Please merge this.' in seen['pending']
        and 'Approved' in seen['approve']
    )
    assert seen['posts_before'] == before
    # The retry of the identical request went through, exactly once.
    assert result.rc('retry') == 0
    assert (result.rc('again'), result.rc('altered')) == (4, 4)
    assert result.rc('read') == 0  # reads never wait
    posts = lab.service.seen('POST')[before:]
    assert [json.loads(post['body']) for post in posts] == [
        {'body': 'Please merge this.'}
    ]
    events = result.events()
    assert events.count('approved') == 1 and events.count('dispatch') == 2
    assert 'Please merge' not in json.dumps(result.audit)


def test_a_write_the_provider_answers_4xx_is_reported_as_unknown(
    lab: Lab,
) -> None:
    """No HTTP status proves a sent write did nothing.

    This provider receives the label and then answers 409. The guest must
    be told the outcome is unknown -- not "rejected", which would invite the
    very retry that applies it twice -- and nothing may be retried for it.
    """
    script = """
run label aivm-secrets invoke issue.label --arguments '{"issue":23,"label":"needs-review"}'
run read aivm-secrets invoke debug.forbidden
run after aivm-secrets invoke profile.read
"""
    result = open_session(lab, 'conflict', script, writes='allow')
    assert result.rc('label') == 3
    assert result.err('label') == 'aivm-secrets: outcome_unknown (HTTP 409)'
    assert result.text('label') == ''
    # The same class of status on a read is an ordinary, definite refusal.
    assert result.err('read') == 'aivm-secrets: upstream_rejected (HTTP 403)'
    assert result.rc('after') == 0
    posts = [item for item in result.requests if item['method'] == 'POST']
    assert [(post['target'], json.loads(post['body'])) for post in posts] == [
        ('/v1/issues/23/labels', {'label': 'needs-review'})
    ]
    failed = [
        (row['operation'], row['code'], row.get('status'))
        for row in result.audit
        if row['event'] == 'rejected_or_failed'
    ]
    assert failed == [
        ('issue.label', 'outcome_unknown', 409),
        ('debug.forbidden', 'upstream_rejected', 403),
    ]
    for produced in result.out.iterdir():
        assert 'already present' not in produced.read_text(errors='replace')


def test_a_state_changing_get_is_gated_as_the_write_it_is_declared_to_be(
    lab: Lab,
) -> None:
    """``issue.close`` is a GET. Only its declared effect makes it a write."""
    target = '/v1/issues/23/close'
    close = 'aivm-secrets invoke issue.close --arguments \'{"issue":23}\''
    view = 'aivm-secrets invoke issue.view --arguments \'{"issue":23}\''

    def closes() -> int:
        return [item['target'] for item in lab.service.seen('GET')].count(
            target
        )

    # Host writes denied: refused before egress, while a read still works.
    denied = open_session(
        lab, 'close-deny', f'run close {close}\nrun view {view}'
    )
    assert denied.err('close') == 'aivm-secrets: denied'
    assert denied.rc('view') == 0
    assert denied.targets() == ['/v1/issues/23'] and closes() == 0

    seen: dict[str, Any] = {}

    def operator(terminal: Terminal, out: Path) -> None:
        wait_for(out / 'first.rc')
        (item,) = json.loads(lab.secrets('pending', '--json').stdout)
        seen['pending'] = (item['operation'], item['arguments'])
        seen['sent_before_approval'] = closes()
        approved = lab.secrets('approve', item['digest'][:16], '--yes')
        assert approved.returncode == 0, approved.stderr

    script = f"""
run first {close}
i=0
while [ $i -lt 150 ]; do
    {close} > "$OUT/retry.out" 2> "$OUT/retry.err" && break
    sleep 0.2; i=$((i+1))
done
echo $? > "$OUT/retry.rc"
run again {close}
"""
    result = open_session(
        lab, 'close-approve', script, writes='approve', during=operator
    )
    assert result.rc('first') == 4
    assert 'approval_required' in result.err('first')
    assert seen == {
        'pending': ('issue.close', {'issue': 23}),
        'sent_before_approval': 0,
    }
    assert result.rc('retry') == 0
    assert json.loads(result.text('retry'))['result'] == {'state': 'closed'}
    assert result.rc('again') == 4  # one approval buys one request
    (sent,) = result.requests
    assert (sent['method'], sent['target'], sent['body']) == ('GET', target, '')
    events = result.events()
    assert events.count('approved') == 1 and events.count('dispatch') == 1


# ---------------------------------------------------------------------------
# Limits: time, budget, revocation
# ---------------------------------------------------------------------------


def test_an_expired_grant_is_refused_while_the_shell_stays_open(
    lab: Lab,
) -> None:
    script = """
run before aivm-secrets invoke profile.read
sleep 9
run after aivm-secrets invoke profile.read
run describe aivm-secrets operations
"""
    result = open_session(
        lab, 'expiry', script, policy=lab.policy(lifetime_seconds=7)
    )
    assert result.rc('before') == 0
    assert (result.rc('after'), result.err('after')) == (
        3,
        'aivm-secrets: expired',
    )
    assert result.err('describe') == 'aivm-secrets: expired'
    assert result.targets() == ['/v1/account']  # nothing was sent after expiry
    assert result.code == 0  # the shell itself was unaffected


def test_the_request_budget_holds_under_sequential_and_concurrent_use(
    lab: Lab,
) -> None:
    script = """
for i in 1 2 3 4 5; do run seq$i aivm-secrets invoke profile.read; done
"""
    result = open_session(
        lab, 'budget', script, policy=lab.policy(max_requests=3)
    )
    codes = [result.rc(f'seq{i}') for i in range(1, 6)]
    assert codes == [0, 0, 0, 3, 3]
    assert result.err('seq5') == 'aivm-secrets: exhausted'
    assert len(result.requests) == 3

    script = """
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    ( run par$i aivm-secrets invoke issue.view --arguments '{"issue":24}' ) &
done
wait
"""
    result = open_session(
        lab, 'race', script, policy=lab.policy(max_requests=5)
    )
    codes = sorted(result.rc(f'par{i}') for i in range(1, 13))
    assert codes == [0] * 5 + [3] * 7
    assert len(result.requests) == 5  # the provider saw exactly the budget
    assert result.events().count('authorized') == 5


def test_the_operator_can_revoke_a_live_session_from_the_host(lab: Lab) -> None:
    seen: dict[str, str] = {}

    def operator(terminal: Terminal, out: Path) -> None:
        wait_for(out / 'before.rc')
        listing = lab.secrets('sessions')
        seen['sessions'] = listing.stdout
        revoked = lab.secrets('revoke', '--vm', lab.vm)
        seen['revoke'] = revoked.stdout + revoked.stderr
        (out / 'revoked').touch()

    script = """
run before aivm-secrets invoke profile.read
i=0; while [ ! -e "$OUT/revoked" ] && [ $i -lt 300 ]; do sleep 0.2; i=$((i+1)); done
run after aivm-secrets invoke profile.read
run describe aivm-secrets operations
"""
    result = open_session(lab, 'revoke', script, during=operator)
    assert result.rc('before') == 0
    assert f'vm={lab.vm}' in seen['sessions'] and 'active' in seen['sessions']
    assert 'Revoked' in seen['revoke']
    assert result.err('after') == 'aivm-secrets: revoked'
    assert result.err('describe') == 'aivm-secrets: revoked'
    assert len(result.requests) == 1
    assert 'revoked' in result.events()


# ---------------------------------------------------------------------------
# Capabilities: replay, delegation, a crashed host
# ---------------------------------------------------------------------------


def test_a_capability_is_worthless_outside_its_own_session(lab: Lab) -> None:
    first = open_session(
        lab, 'replay-a',
        'cp "$AIVM_SECRETS_CAPABILITY_FILE" stolen.cap\nrun ok aivm-secrets invoke profile.read',
    )  # fmt: skip
    assert first.rc('ok') == 0
    stolen = lab.workspace / 'replay-a' / 'stolen.cap'
    assert stolen.read_text().startswith('aivs1.')
    script = """
run stolen aivm-secrets --capability-file ../replay-a/stolen.cap invoke profile.read
run own aivm-secrets invoke profile.read
"""
    second = open_session(lab, 'replay-b', script)
    assert second.err('stolen') == 'aivm-secrets: invalid_capability'
    assert second.rc('own') == 0
    assert len(second.requests) == 1
    assert first.channel != second.channel


def test_a_guest_can_hand_a_helper_a_strictly_smaller_capability(
    lab: Lab,
) -> None:
    script = """
run delegate aivm-secrets delegate --scope '{"operations":{"issue.view":{"issue":[24]}},"max_requests":2}' --output helper.cap
stat -c %a helper.cap > "$OUT/mode"
H="aivm-secrets --capability-file helper.cap"
run h_ops $H operations
run h_ok $H invoke issue.view --arguments '{"issue":24}'
run h_other $H invoke issue.view --arguments '{"issue":23}'
run h_profile $H invoke profile.read
run h_widen $H delegate --scope '{"operations":{"issue.view":{"issue":[23,24]}}}' --output wider.cap
run h_ok2 $H invoke issue.view --arguments '{"issue":24}'
run h_spent $H invoke issue.view --arguments '{"issue":24}'
run widen aivm-secrets delegate --scope '{"operations":{"issue.view":{"issue":[99]}}}' --output evil.cap
run parent aivm-secrets operations
run renounce $H renounce
run h_gone $H operations
ls *.cap > "$OUT/caps"
"""
    result = open_session(
        lab, 'delegate', script, policy=lab.policy(max_requests=10)
    )
    assert (
        result.rc('delegate') == 0
        and (result.out / 'mode').read_text().strip() == '600'
    )
    helper = result.json('h_ops')['grant']
    assert helper['remaining_requests'] == 2
    assert helper['operations'] == [
        {
            'name': 'issue.view',
            'write': False,
            'parameters': {'issue': [24]},
            'fields': {},
        }
    ]
    assert (result.rc('h_ok'), result.rc('h_ok2')) == (0, 0)
    for step, expected in [('h_other', 'denied'), ('h_profile', 'denied'),
                           ('h_widen', 'denied'), ('h_spent', 'exhausted'),
                           ('widen', 'denied'), ('h_gone', 'revoked')]:  # fmt: skip
        assert result.err(step) == f'aivm-secrets: {expected}', step
    # The helper's two requests were paid for by the parent's budget.
    assert result.json('parent')['grant']['remaining_requests'] == 8
    assert (result.out / 'caps').read_text().split() == ['helper.cap']
    assert result.targets() == ['/v1/issues/24', '/v1/issues/24']
    assert {'delegated', 'renounced'} <= set(result.events())
    # The child carries the same sealed credential, still unreadable.
    assert TOKEN not in (lab.workspace / 'delegate' / 'helper.cap').read_text()


def test_killing_the_host_session_ends_its_authority(lab: Lab) -> None:
    """A crash (SIGKILL: no cleanup code runs) must not orphan a live broker."""
    facts: dict[str, Any] = {}

    def crash(terminal: Terminal, out: Path) -> None:
        wait_for(out / 'ok.rc')
        facts['brokers'] = brokers(lab.private / 'crash.json')
        facts['runtime'] = [
            p.name for p in (lab.runtime / 'aivm-secrets').iterdir()
        ]
        terminal.kill()

    script = """
run ok aivm-secrets invoke profile.read
cp "$AIVM_SECRETS_CAPABILITY_FILE" orphan.cap
echo "$AIVM_SECRETS_SOCKET" > orphan.sock
sleep 600
"""
    killed = open_session(lab, 'crash', script, during=crash)
    assert killed.code == -9 and killed.rc('ok') == 0
    assert len(facts['brokers']) == 1 and len(facts['runtime']) == 1
    (broker,) = facts['brokers']
    deadline = time.monotonic() + 30
    while os.path.exists(f'/proc/{broker}') and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not os.path.exists(f'/proc/{broker}'), (
        'the broker outlived its session'
    )
    assert list((lab.runtime / 'aivm-secrets').iterdir()) == []
    # No cleanup ran in the guest, so the ciphertext is still there -- and
    # is inert: its key died with the broker.
    channel = facts['runtime'][0]
    assert channel.startswith(killed.channel)
    # The broker noticed the lost lease and sealed its own audit file.
    audit = lab.state / 'secrets-audit' / f'{channel}.jsonl'
    events = [
        json.loads(line)['event'] for line in audit.read_text().splitlines()
    ]
    assert events[-1] == 'session_close'
    assert lab.secrets('audit-verify', str(audit)).returncode == 0
    leftovers = lab.guest(f'ls /tmp/aivm-secrets-{channel}/').stdout.split()
    assert 'capability' in leftovers
    script = """
run orphan aivm-secrets --capability-file ../crash/orphan.cap invoke profile.read
run dead aivm-secrets --socket "$(cat ../crash/orphan.sock)" --capability-file ../crash/orphan.cap invoke profile.read
run own aivm-secrets invoke profile.read
"""
    after = open_session(lab, 'after-crash', script)
    assert after.err('orphan') == 'aivm-secrets: invalid_capability'
    assert after.rc('dead') == 2  # nothing is listening on the old socket
    assert after.rc('own') == 0
    lab.guest(f'rm -rf /tmp/aivm-secrets-{channel}')


# ---------------------------------------------------------------------------
# Hostile parties
# ---------------------------------------------------------------------------

ABUSE = r"""
import json, os, socket, sys
path = os.environ['AIVM_SECRETS_SOCKET']
capability = open(os.environ['AIVM_SECRETS_CAPABILITY_FILE']).read().strip()

def send(raw, read=True):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(15)
        sock.connect(path)
        try:
            sock.sendall(raw)
            data = b''
            while read and not data.endswith(b'\n'):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError as ex:
            return 'closed:' + type(ex).__name__
    try:
        return json.loads(data)['error']['code']
    except Exception:
        return 'no-reply' if not data else 'ok:' + data[:40].decode('ascii', 'replace')

def frame(**fields):
    return json.dumps({'version': 1, 'capability': capability, **fields}).encode() + b'\n'

flipped = capability[:-6] + ('A' if capability[-6] != 'A' else 'B') + capability[-5:]
view = {'operation': 'issue.view', 'arguments': {'issue': 23}}
results = {
    # The host control plane is not reachable through the guest socket.
    'control_status': send(b'{"command":"status"}\n'),
    'control_approve': send(frame(command='approve', digest='a' * 64)),
    'verb_approve': send(frame(approve='a' * 64)),
    'verb_revoke': send(frame(revoke=True)),
    'verb_exec': send(frame(exec=['id'])),
    # Routing, identity and credentials cannot be supplied by a request.
    'two_verbs': send(frame(request=view, describe=True)),
    'request_url': send(frame(request={**view, 'url': 'https://attacker.invalid'})),
    'request_method': send(frame(request={**view, 'method': 'DELETE'})),
    'argument_host': send(frame(request={'operation': 'issue.view',
                          'arguments': {'issue': 23, 'host': 'attacker.invalid'}})),
    'path_escape': send(frame(request={'operation': 'issue.view',
                        'arguments': {'issue': '../../admin'}})),
    'binding_claim': send(json.dumps({'version': 1, 'capability': capability,
                          'request': view, 'binding': {'owner_uid': 0}}).encode() + b'\n'),
    # Malformed and abusive framing.
    'not_json': send(b'GET / HTTP/1.1\r\n\r\n'),
    'duplicate_key': send(b'{"version":1,"version":1}\n'),
    'wrong_version': send(json.dumps({'version': 2, 'capability': capability,
                          'request': view}).encode() + b'\n'),
    'oversized': send(b'{"pad":"' + b'x' * 70000 + b'"}\n'),
    'pipelined': send(frame(request=view) + frame(request=view)),
    'deep': send(b'[' * 5000 + b']' * 5000 + b'\n'),
    # Capability tampering.
    'flipped': send(json.dumps({'version': 1, 'capability': flipped,
                    'request': view}).encode() + b'\n'),
    'truncated': send(json.dumps({'version': 1, 'capability': capability[:-10],
                      'request': view}).encode() + b'\n'),
    'empty_capability': send(json.dumps({'version': 1, 'capability': '',
                             'request': view}).encode() + b'\n'),
}
# Many idle connections, then a legitimate request must still be served.
idle = []
for _ in range(60):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        idle.append(sock)
    except OSError:
        break
for sock in idle:
    sock.close()
import time
deadline = time.time() + 30
results['after_flood'] = 'pending'
while time.time() < deadline:
    reply = send(frame(request=view))
    if reply.startswith('ok:'):
        results['after_flood'] = 'served'
        break
    time.sleep(0.5)
json.dump(results, open(sys.argv[1], 'w'), indent=1, sort_keys=True)
"""


def test_a_hostile_guest_cannot_talk_its_way_past_the_broker(lab: Lab) -> None:
    (lab.workspace / 'abuse.py').write_text(ABUSE)
    script = """
python3 ../abuse.py "$OUT/abuse.json" > "$OUT/abuse.log" 2>&1
run still_works aivm-secrets invoke profile.read
"""
    result = open_session(
        lab, 'abuse', script, policy=lab.policy(max_requests=40)
    )
    replies = json.loads((result.out / 'abuse.json').read_text())
    invalid = [
        'control_status', 'control_approve', 'verb_approve', 'verb_revoke', 'verb_exec',
        'two_verbs', 'request_url', 'request_method', 'argument_host', 'binding_claim',
        'not_json', 'duplicate_key', 'wrong_version', 'oversized', 'pipelined', 'deep',
        'empty_capability',
    ]  # fmt: skip
    for name in invalid:
        assert replies[name] in ('invalid_request', 'invalid_capability'), (
            name,
            replies,
        )
    assert replies['path_escape'] == 'denied'
    assert replies['flipped'] == replies['truncated'] == 'invalid_capability'
    assert replies['after_flood'] == 'served'
    assert result.rc('still_works') == 0
    # Of everything above, the provider saw only the two legitimate reads.
    assert result.targets() == ['/v1/issues/23', '/v1/account']
    assert all(
        item['headers']['host'].startswith(lab.service.host)
        for item in result.requests
    )
    text = json.dumps(result.audit)
    assert 'attacker.invalid' not in text and '../../admin' not in text


def test_a_misbehaving_provider_cannot_leak_or_redirect_the_credential(
    lab: Lab,
) -> None:
    script = """
run echo aivm-secrets invoke debug.echo
run redirect aivm-secrets invoke debug.redirect
run forbidden aivm-secrets invoke debug.forbidden
run healthy aivm-secrets invoke profile.read
"""
    result = open_session(lab, 'provider', script)
    # The provider reflected the Authorization header; the guest got a
    # refusal instead of the response.
    assert result.err('echo') == 'aivm-secrets: upstream_response'
    assert result.text('echo') == ''
    # A redirect is reported, never followed.
    assert result.err('redirect') == 'aivm-secrets: upstream_error (HTTP 302)'
    # A refusal is reported by status only; provider text is never relayed.
    assert (
        result.err('forbidden') == 'aivm-secrets: upstream_rejected (HTTP 403)'
    )
    assert result.rc('healthy') == 0
    assert result.targets() == [
        '/v1/secret-echo', '/v1/moved', '/v1/forbidden', '/v1/account',
    ]  # fmt: skip
    for produced in result.out.iterdir():
        text = produced.read_text(errors='replace')
        assert TOKEN not in text and 'provider says no' not in text, (
            produced.name
        )
    assert TOKEN not in result.transcript + json.dumps(result.audit)
    statuses = {row.get('status') for row in result.audit if row.get('status')}
    assert statuses == {302, 403}


# ---------------------------------------------------------------------------
# Refusals before any authority exists
# ---------------------------------------------------------------------------


def test_a_policy_inside_the_shared_workspace_is_refused(lab: Lab) -> None:
    """The guest can write there, so it must not define its own authority."""
    from aivm_secrets.kernel import codec

    shared = lab.workspace / 'planted-policy.json'
    fd = os.open(shared, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(codec.dumps(lab.policy()))
    before = len(lab.service.requests)
    result = open_session(
        lab, 'planted', 'true', policy_path=shared, expect_session=False
    )
    assert result.code == 1
    assert 'Secret session failed' in result.transcript
    assert 'outside the shared workspace' in result.transcript
    assert 'Guest client:' not in result.transcript
    assert len(lab.service.requests) == before
    assert list((lab.runtime / 'aivm-secrets').iterdir()) == []


def test_bad_trust_anchor_and_resolver_fail_before_the_guest_is_touched(
    lab: Lab,
) -> None:
    for name, change, expected in [
        ('no-ca', {'egress': dict(lab.service.egress(), ca_file='/nonexistent/ca.pem')},
         'unsafe'),
        ('no-resolver',
         {'credential_source': {'kind': 'command', 'argv': ['aivm-no-such-resolver']}},
         'Could not obtain a valid host service credential'),
        ('bad-schema', {'operations': []}, 'Invalid policy'),
    ]:  # fmt: skip
        result = open_session(
            lab, name, 'true', policy=lab.policy(**change), expect_session=False
        )
        assert result.code == 1, name
        assert expected in result.transcript, (name, result.transcript[-600:])
        assert 'Guest client:' not in result.transcript


def test_an_untrusted_provider_certificate_sends_no_credential(
    lab: Lab,
) -> None:
    """Pin a different CA: TLS must fail closed before any request is sent."""
    from tests.secrets_helpers import make_certificates

    other = lab.private / 'other-ca'
    other.mkdir()
    stranger = make_certificates(other)['ca']
    policy = lab.policy(
        egress=dict(lab.service.egress(), ca_file=str(stranger))
    )
    result = open_session(
        lab,
        'wrong-ca',
        'run read aivm-secrets invoke profile.read',
        policy=policy,
    )
    assert result.err('read') == 'aivm-secrets: unreachable'
    assert result.requests == []


# ---------------------------------------------------------------------------
# Code and paths the guest controls
# ---------------------------------------------------------------------------


def test_a_guest_made_link_out_of_the_workspace_cannot_carry_a_policy(
    lab: Lab,
) -> None:
    """The review's symlink case, with a real guest making the link.

    Inside the shared folder the guest creates ``switch``, a link to the
    host directory that holds the operator's genuine policy and credential.
    Every path through it resolves to a perfectly good host file -- and is
    still chosen by the guest, which can re-point the link at any moment.
    """
    planted = open_session(
        lab,
        'plant-link',
        f'ln -s {shlex.quote(str(lab.private))} ../switch\n'
        'run listed ls -l ../switch',
    )
    assert planted.rc('listed') == 0
    link = lab.workspace / 'switch'
    assert link.is_symlink() and os.path.realpath(link) == str(lab.private)
    genuine = lab.private / 'plant-link.json'
    assert genuine.is_file()
    before = len(lab.service.requests)
    try:
        through_policy = open_session(
            lab, 'link-policy', 'true',
            policy_path=link / 'plant-link.json', expect_session=False,
        )  # fmt: skip
        through_token = open_session(
            lab, 'link-token', 'true', policy_path=genuine,
            extra=('--secrets_token_file', str(link / 'token')),
            expect_session=False,
        )  # fmt: skip
    finally:
        link.unlink()
    for result in (through_policy, through_token):
        assert result.code == 1
        assert 'outside the shared workspace' in result.transcript
        assert 'Guest client:' not in result.transcript
    assert len(lab.service.requests) == before
    assert list((lab.runtime / 'aivm-secrets').iterdir()) == []
    # Named directly, the very same files open a session.
    direct = open_session(
        lab, 'link-direct', 'run read aivm-secrets invoke profile.read',
        policy_path=genuine,
    )  # fmt: skip
    assert direct.rc('read') == 0


def test_guest_written_python_cannot_become_the_broker(lab: Lab) -> None:
    """The review's ``PYTHONPATH`` case, with a real guest writing the code.

    From inside the VM the guest drops a shadow ``aivm_secrets`` package and
    a ``sitecustomize.py`` into the shared folder. The operator then opens a
    secret session with ``PYTHONPATH`` pointing there and from that
    directory. The broker that holds the credential must be the installed
    one, and none of the guest's files may have run in it.
    """
    record = (
        'import os\n'
        'here = os.path.dirname(os.path.abspath(__file__))\n'
        'root = here if os.path.basename(here) != "aivm_secrets" else os.path.dirname(here)\n'
        'with open(os.path.join(root, "ran-guest-code"), "ab") as stream:\n'
        '    stream.write(open("/proc/self/cmdline", "rb").read() + b"\\n")\n'
    )
    script = f"""
mkdir ../aivm_secrets
cat > ../sitecustomize.py <<'PY'
{record}PY
cp ../sitecustomize.py ../aivm_secrets/__init__.py
cat > ../aivm_secrets/__main__.py <<'PY'
import json
print(json.dumps({{"channel": "SHADOW", "socket": "/tmp/shadow"}}))
PY
run made ls ../aivm_secrets ../sitecustomize.py
"""
    assert open_session(lab, 'plant-code', script).rc('made') == 0
    marker = lab.workspace / 'ran-guest-code'
    poisoned = dict(lab.env, PYTHONPATH=str(lab.workspace))
    try:
        # The attack is real: started the old way, with ``-P`` and this
        # environment, what runs is the guest's package.
        control = subprocess.run(
            [sys.executable, '-P', '-m', 'aivm_secrets', 'serve'],
            env=poisoned, cwd=lab.workspace, capture_output=True, text=True,
            timeout=60,
        )  # fmt: skip
        assert json.loads(control.stdout)['channel'] == 'SHADOW'
        assert marker.exists()
        marker.unlink()

        result = open_session(
            lab,
            'poisoned',
            'run read aivm-secrets invoke profile.read',
            env=poisoned,
            cwd=lab.workspace,
            # The operator's own AIVM is assumed sane; what is under test is
            # the broker it starts while this variable is in the environment.
            python_flags=('-I',),
        )
        ran = marker.read_bytes() if marker.exists() else b''
    finally:
        shutil.rmtree(lab.workspace / 'aivm_secrets', ignore_errors=True)
        for name in ('sitecustomize.py', 'ran-guest-code'):
            (lab.workspace / name).unlink(missing_ok=True)
    assert result.rc('read') == 0
    assert result.json('read')['result'] == {'login': 'e2e-operator'}
    (seen,) = result.requests
    assert seen['headers']['authorization'] == 'Bearer ' + TOKEN
    assert b'aivm_secrets\x00serve' not in ran, ran
    assert 'SHADOW' not in result.transcript


# ---------------------------------------------------------------------------
# The built-in GitHub manifest and its ``gh`` command table
# ---------------------------------------------------------------------------

PULL = '/repos/taucetiproject/tauceti'


def test_gh_commands_run_through_the_general_mechanism_on_a_real_vm(
    lab: Lab,
) -> None:
    """``gh pr ...`` in the guest, end to end, with no GitHub-specific code.

    The policy is the built-in manifest exactly as ``policy-check`` prints
    it, with only its destination and credential source replaced so that it
    reaches this suite's provider instead of GitHub. Everything else -- the
    fact check on the PR, the bound commit hash, pagination, the ``gh``
    command table the guest client reads -- is that manifest's own data.
    """
    from aivm_secrets.kernel import presets
    from tests.secrets_helpers import github_policy, metadata

    manifest = presets.github_pr(github_policy(max_requests=30))
    manifest.update(
        host=lab.service.host,
        egress=lab.service.egress(),
        credential_source={'kind': 'file', 'path': str(lab.token_file)},
    )
    stranger = metadata()
    stranger.update(number=13862)
    stranger['user']['login'] = 'someone-else'
    checks = f'{PULL}/commits/{"a" * 40}/check-runs?page=1&per_page=100'
    lab.service.routes.update(
        {
            ('GET', f'{PULL}/pulls/13861'): lambda seen: (
                (200, {}, b'diff --git a/x b/x\n+proof\n')
                if 'diff' in seen['headers']['accept']
                else (200, {}, json.dumps(metadata()).encode())
            ),
            ('GET', f'{PULL}/pulls/13862'): stranger,
            ('GET', f'{PULL}/issues/13861/comments?page=1&per_page=100'): [
                {'id': 1, 'body': 'first'}
            ],
            ('GET', f'{PULL}/pulls/13861/reviews?page=2&per_page=100'): [],
            ('GET', checks): {'total_count': 1, 'check_runs': [{'name': 'lean'}]},
            ('POST', f'{PULL}/issues/13861/comments'): lambda seen: (
                201, {}, b'{"id": 99}'
            ),
            ('PATCH', f'{PULL}/pulls/13861'): {'title': 'New title'},
        }
    )  # fmt: skip
    repo = '--repo TauCetiProject/TauCeti'
    script = f"""
command -v gh > "$OUT/which"
readlink "$(command -v gh)" > "$OUT/link"
run view gh pr view 13861 {repo}
run diff gh pr diff 13861 -R TAUCETIPROJECT/tauceti
run comments gh pr comments 13861 {repo}
run reviews gh pr reviews 13861 {repo} --page 2
run checks gh pr checks 13861 {repo}
printf 'Reviewed in the guest.\\n' > body.md
run comment gh pr comment 13861 {repo} --body-file body.md
run edit gh pr edit 13861 {repo} --title 'New title'
run spelled aivm-secrets as gh pr view 13861 {repo}
run wrong_author gh pr view 13862 {repo}
run wrong_author_write gh pr comment 13862 {repo} --body nope
run other_pr gh pr view 9 {repo}
run other_repo gh pr view 13861 --repo attacker/TauCeti
run api gh api /user
run token gh auth token
run merge gh pr merge 13861 {repo}
run web gh pr view 13861 {repo} --web
run bypass aivm-secrets invoke pr.view --arguments '{{"repository":"attacker/x","pr":13861}}'
"""
    result = open_session(lab, 'gh', script, policy=manifest, writes='allow')
    assert (result.out / 'which').read_text().strip().endswith('/gh')
    assert (result.out / 'link').read_text().strip() == 'aivm-secrets'
    assert result.json('view')['result']['user']['login'] == 'Erotemic'
    assert result.text('diff') == 'diff --git a/x b/x\n+proof\n'  # raw text
    assert result.json('comments')['result'] == [{'id': 1, 'body': 'first'}]
    assert result.json('comments')['pagination'] == {
        'page': 1, 'per_page': 100, 'possibly_more': False,
    }  # fmt: skip
    assert result.json('reviews')['pagination']['page'] == 2
    assert result.json('checks')['result']['check_runs'] == [{'name': 'lean'}]
    assert result.json('comment')['result'] == {'id': 99}
    assert result.json('edit')['result'] == {'title': 'New title'}
    assert result.json('spelled') == result.json('view')
    # Fresh metadata gates everything: PR 13862 is in the grant by number
    # but has another author, so nothing follows the one fact fetch.
    for step in ('wrong_author', 'wrong_author_write'):
        assert result.err(step) == 'aivm-secrets: resource_mismatch', step
    for step in ('other_pr', 'other_repo', 'bypass'):
        assert result.err(step) == 'aivm-secrets: denied', step
    # Not the real gh: anything the table does not list stops in the guest.
    for step in ('api', 'token', 'merge', 'web'):
        assert result.rc(step) == 2 and result.text(step) == '', step
        assert 'not the real gh' in result.err(step), step
    fetch = f'{PULL}/pulls/13861'
    assert [(item['method'], item['target']) for item in result.requests] == [
        ('GET', fetch),  # view: the checked facts are the answer
        ('GET', fetch), ('GET', fetch),  # diff
        ('GET', fetch), ('GET', f'{PULL}/issues/13861/comments?page=1&per_page=100'),
        ('GET', fetch), ('GET', f'{PULL}/pulls/13861/reviews?page=2&per_page=100'),
        ('GET', fetch), ('GET', checks),
        ('GET', fetch), ('POST', f'{PULL}/issues/13861/comments'),
        ('GET', fetch), ('PATCH', fetch),
        ('GET', fetch),  # spelled
        ('GET', f'{PULL}/pulls/13862'), ('GET', f'{PULL}/pulls/13862'),
    ]  # fmt: skip
    post = next(item for item in result.requests if item['method'] == 'POST')
    assert json.loads(post['body']) == {'body': 'Reviewed in the guest.\n'}
    patch = next(item for item in result.requests if item['method'] == 'PATCH')
    assert json.loads(patch['body']) == {'title': 'New title'}
    for item in result.requests:
        assert item['headers']['authorization'] == 'Bearer ' + TOKEN
        assert item['headers']['x-github-api-version'] == '2026-03-10'
    assert TOKEN not in result.transcript + json.dumps(result.audit)
    for produced in result.out.iterdir():
        assert TOKEN not in produced.read_text(errors='replace'), produced.name


def test_the_github_shorthand_uses_the_operators_gh_login_and_installs_gh(
    lab: Lab,
) -> None:
    """Policy ``schema: 1`` as shipped, without ever contacting GitHub.

    The host credential comes from a stand-in ``gh`` on the operator's PATH.
    Every request below is refused before egress, so nothing leaves the
    host; live GitHub reads are an explicit operator step, not a test.
    """
    from tests.secrets_helpers import github_policy, write_private

    bindir = lab.private / 'bin'
    bindir.mkdir()
    record = lab.private / 'gh-argv'
    write_private(
        bindir / 'gh',
        f'#!/bin/sh\nprintf "%s " "$@" > {record}\necho {TOKEN}\n'.encode(),
        0o700,
    )
    env = dict(lab.env, PATH=f'{bindir}:{lab.env["PATH"]}')
    saved, lab.env = lab.env, env
    try:
        policy = github_policy(operations=['pr.view', 'pr.diff', 'pr.comments'])
        script = """
command -v gh > "$OUT/which"
run ops aivm-secrets operations
run other_pr gh pr view 9 --repo TauCetiProject/TauCeti
run other_repo gh pr view 13861 --repo attacker/TauCeti
run not_granted gh pr checks 13861 --repo TauCetiProject/TauCeti
run write gh pr comment 13861 --repo TauCetiProject/TauCeti --body hi
run bypass aivm-secrets invoke pr.comment --arguments '{"repository":"TauCetiProject/TauCeti","pr":13861,"body":"hi"}'
run api gh api /user
run json gh pr view 13861 --repo TauCetiProject/TauCeti --json title
"""
        result = open_session(lab, 'github', script, policy=policy)
    finally:
        lab.env = saved
    assert record.read_text().split() == [
        'auth',
        'token',
        '--hostname',
        'github.com',
    ]
    assert (result.out / 'which').read_text().strip().endswith('/gh')
    described = result.json('ops')
    names = [op['name'] for op in described['grant']['operations']]
    assert names == ['pr.comments', 'pr.diff', 'pr.view']
    # The command table offers exactly the granted operations ...
    assert sorted(' '.join(row['command']) for row in described['cli']['gh']) == [
        'pr comments', 'pr diff', 'pr view',
    ]  # fmt: skip
    for step in ('other_pr', 'other_repo'):
        assert result.err(step) == 'aivm-secrets: denied', step
    # ... so an ungranted command stops in the client, and going around the
    # client changes nothing: the broker refuses the operation itself.
    for step in ('not_granted', 'write', 'api', 'json'):
        assert result.rc(step) == 2 and 'not the real gh' in result.err(step)
    assert result.err('bypass') == 'aivm-secrets: denied'
    assert result.requests == []
    assert result.events().count('rejected_or_failed') == 3
    assert TOKEN not in result.transcript


# ---------------------------------------------------------------------------
# Measured, not estimated
# ---------------------------------------------------------------------------


def test_measure_session_and_request_overhead(lab: Lab) -> None:
    script = """
start=$(date +%s%N)
for i in $(seq 20); do aivm-secrets invoke profile.read > /dev/null; done
end=$(date +%s%N)
echo $(( (end - start) / 20000000 )) > "$OUT/request_ms"
start=$(date +%s%N)
for i in $(seq 20); do python3 -c pass; done
end=$(date +%s%N)
echo $(( (end - start) / 20000000 )) > "$OUT/python_ms"
"""
    result = open_session(
        lab, 'timing', script, policy=lab.policy(max_requests=30)
    )
    request_ms = int((result.out / 'request_ms').read_text())
    python_ms = int((result.out / 'python_ms').read_text())
    assert len(result.requests) == 20
    report = {
        'guest_request_round_trip_ms': request_ms,
        'guest_python_startup_ms': python_ms,
        'session_open_seconds': round(
            lab.timings.get('session_open_seconds', 0.0), 1
        ),
    }
    print('\naivm-secrets e2e timings:', json.dumps(report))
    destination = os.getenv('AIVM_E2E_SECRETS_TIMINGS', '')
    if destination:
        Path(destination).write_text(json.dumps(report, indent=1) + '\n')
    # Generous ceilings: this guards against a pathological regression, it
    # is not a benchmark.
    assert request_ms < 2000
