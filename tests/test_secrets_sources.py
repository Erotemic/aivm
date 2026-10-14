"""Host-only credential acquisition: no shell, no guest-chosen programs."""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host import sources
from aivm_secrets.host.files import verify_program
from aivm_secrets.host.sources import (
    credential_from_command,
    credential_from_file,
    credential_from_stream,
    resolve_source,
)
from aivm_secrets.kernel.presets import GH_SOURCE
from tests.secrets_helpers import write_private

TOKEN = 'NOT_REAL_generic_host_command_token_1234'
def _trusted_test_python() -> str:
    """Use a Python executable whose entire path passes the real policy.

    Hosted CI can install its Python under a world-writable ``/opt``. That
    interpreter correctly cannot be a secrets resolver. The system Python
    runs these stdlib-only subprocess fixtures instead, while the security
    checks on the real credential path stay unchanged.
    """
    for candidate in (sys.executable, '/usr/bin/python3', '/usr/bin/python'):
        try:
            return str(verify_program(Path(candidate)))
        except SecretsError:
            continue
    return ''


PYTHON = _trusted_test_python()
if not PYTHON:
    raise RuntimeError('secrets resolver tests need a trusted Python interpreter')


def failed(call, *args, code='credential_source', **kwargs):
    with pytest.raises(SecretsError) as caught:
        call(*args, **kwargs)
    assert caught.value.code == code
    return caught.value


def script(directory: Path, name: str, body: str, mode: int = 0o700) -> Path:
    return write_private(
        directory / name, f'#!/bin/sh\n{body}\n'.encode(), mode
    )


def test_host_command_resolver_no_shell_and_only_selected_environment(
    monkeypatch,
):
    monkeypatch.setenv('DANGEROUS_ENV', 'do-not-inherit')
    monkeypatch.setenv('GH_DEBUG', 'api')
    monkeypatch.setenv('HTTPS_PROXY', 'http://attacker.invalid:3128')
    monkeypatch.setenv('WANTED', 'yes')
    program = (
        'import os, sys\n'
        "leaked = [k for k in ('DANGEROUS_ENV','GH_DEBUG','HTTPS_PROXY') if k in os.environ]\n"
        "ok = not leaked and os.environ.get('WANTED') == 'yes' and 'HOME' in os.environ\n"
        "ok = ok and sys.stdin.read() == ''\n"
        f"print({TOKEN!r} if ok else 'FAILED_' + '_'.join(leaked))\n"
    )
    command = [PYTHON, '-c', program]
    assert credential_from_command(command, ['WANTED']) == TOKEN
    source = {'kind': 'command', 'argv': command, 'inherit_env': ['WANTED']}
    assert resolve_source(source) == TOKEN
    # Without the explicit opt-in the variable is not inherited either.
    failed(credential_from_command, command)


def test_shell_metacharacters_are_literal_arguments(tmp_path):
    marker = tmp_path / 'pwned'
    command = [
        PYTHON, '-c', 'import sys; print(sys.argv[1])',
        f'{TOKEN}; touch {marker}; echo $(id) `id` | cat > {marker}',
    ]  # fmt: skip
    # The whole argument reaches the program verbatim (and is then refused
    # as a credential because it contains spaces). Nothing was executed.
    failed(credential_from_command, command)
    assert not marker.exists()


@pytest.mark.parametrize(
    'body',
    [
        "print('bad')",
        "print('A' * 10000)",
        'import sys; sys.exit(1)',
        f'import sys; print({TOKEN!r}); sys.exit(3)',
        f"print({TOKEN!r}); print('second line')",
        f"print({TOKEN!r} + ' trailing')",
        "import sys; sys.stdout.buffer.write(b'\\xff' * 32)",
        'pass',
    ],
)
def test_resolver_rejects_bad_output_and_failure(body):
    failed(credential_from_command, [PYTHON, '-c', body])


def test_resolver_stderr_never_reaches_this_process(capfd):
    noisy = f"import sys; sys.stderr.write('debug: token=hunter2\\n'); print({TOKEN!r})"
    assert credential_from_command([PYTHON, '-c', noisy]) == TOKEN
    captured = capfd.readouterr()
    assert 'hunter2' not in captured.err + captured.out
    assert TOKEN not in captured.err + captured.out


def test_resolver_has_a_total_deadline(monkeypatch):
    monkeypatch.setattr(sources, 'RESOLVER_TIMEOUT', 0.4)
    started = time.monotonic()
    # Silent forever, then trickling forever: neither may outlive the deadline.
    failed(
        credential_from_command, [PYTHON, '-c', 'import time; time.sleep(30)']
    )
    trickle = (
        'import sys, time\n'
        'while True:\n'
        "    sys.stdout.write('x'); sys.stdout.flush(); time.sleep(0.05)\n"
    )
    failed(credential_from_command, [PYTHON, '-c', trickle])
    assert time.monotonic() - started < 5


def test_missing_and_untrusted_resolvers_are_never_run(tmp_path, monkeypatch):
    error = failed(credential_from_command, ['aivm-no-such-resolver-xyz'])
    assert 'not found' in error.detail
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    marker = tmp_path / 'ran'
    planted = script(workspace, 'resolver', f'touch {marker}; echo {TOKEN}')
    failed(
        credential_from_command,
        [str(planted)],
        untrusted=(workspace,),
        code='shared_source',
    )
    # Found through PATH or through a link from a trusted directory: same.
    monkeypatch.setenv('PATH', f'{workspace}:{os.environ["PATH"]}')
    failed(
        credential_from_command,
        ['resolver'],
        untrusted=(workspace,),
        code='shared_source',
    )
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (bindir / 'innocent').symlink_to(planted)
    failed(
        credential_from_command, [str(bindir / 'innocent')],
        untrusted=(workspace,), code='shared_source',
    )  # fmt: skip
    assert not marker.exists()
    # Outside any untrusted root the same script is a legitimate resolver.
    assert credential_from_command([str(planted)]) == TOKEN


def test_resolver_arguments_cannot_point_into_the_workspace(tmp_path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    config = workspace / 'config.toml'
    config.write_text('x')
    echo = [PYTHON, '-c', f'print({TOKEN!r})']
    for argument in [
        str(config),
        str(workspace),
        f'{workspace}/../workspace/config.toml',
    ]:
        failed(
            credential_from_command, [*echo, argument],
            untrusted=(workspace,), code='shared_source',
        )  # fmt: skip
    assert (
        credential_from_command(
            [*echo, '/etc/hostname'], untrusted=(workspace,)
        )
        == TOKEN
    )
    assert (
        credential_from_command(
            [*echo, 'op://vault/item'], untrusted=(workspace,)
        )
        == TOKEN
    )


def test_a_resolver_link_swapped_after_the_check_runs_the_checked_program(
    tmp_path, monkeypatch
):
    """The race the review described, made deterministic.

    ``resolver`` is a link to a good program. The instant it has been
    verified, the link is re-pointed at a different one. What runs must be
    what was verified: the executable is a resolved location, not a name
    looked up a second time.
    """
    marker = tmp_path / 'evil-ran'
    good = script(tmp_path, 'good', f'echo {TOKEN}')
    evil = script(tmp_path, 'evil', f'touch {marker}; echo {"E" * 40}')
    name = tmp_path / 'resolver'
    name.symlink_to(good)
    verify = sources.verify_program

    def verify_then_swap(path, untrusted=()):
        verified = verify(path, untrusted)
        name.unlink()
        name.symlink_to(evil)
        return verified

    monkeypatch.setattr(sources, 'verify_program', verify_then_swap)
    assert credential_from_command([str(name)]) == TOKEN
    assert os.path.realpath(name) == str(evil) and not marker.exists()


def test_a_resolver_reached_by_link_still_sees_its_own_name(tmp_path):
    """A program that dispatches on ``argv[0]`` is run under the name used."""
    link = tmp_path / 'my-python'
    link.symlink_to(os.path.realpath(PYTHON))
    body = f'import sys; print({TOKEN!r} if sys.argv[0] == "-c" else "bad")'
    assert credential_from_command([str(link), '-c', body]) == TOKEN
    seen = tmp_path / 'argv0'
    probe = (
        'import pathlib, sys; '
        f'pathlib.Path({str(seen)!r}).write_text(sys.executable); '
        f'print({TOKEN!r})'
    )
    assert credential_from_command([str(link), '-I', '-c', probe]) == TOKEN
    assert seen.read_text() == str(link)


def test_a_world_writable_resolver_is_refused(tmp_path):
    loose = script(tmp_path, 'loose', f'echo {TOKEN}', 0o757)
    failed(credential_from_command, [str(loose)], code='unsafe_file')


def test_file_source_is_private_and_outside_the_workspace(tmp_path):
    path = write_private(tmp_path / 'token', (TOKEN + '\n').encode())
    assert credential_from_file(path) == TOKEN
    assert resolve_source({'kind': 'file', 'path': str(path)}) == TOKEN
    failed(
        credential_from_file, path, untrusted=(tmp_path,), code='shared_source'
    )
    path.chmod(0o644)
    failed(credential_from_file, path, code='unsafe_file')
    for content in [b'short\n', b'two words here ok\n', b'\xff' * 32, b'']:
        bad = write_private(tmp_path / f'bad{len(content)}', content)
        failed(credential_from_file, bad)
    # Too large to be a credential at all: refused before it is fully read.
    huge = write_private(tmp_path / 'huge', b'x' * 5000)
    failed(credential_from_file, huge, code='unsafe_file')


def test_stream_source_reads_one_bounded_credential():
    assert credential_from_stream(io.BytesIO((TOKEN + '\n').encode())) == TOKEN
    failed(credential_from_stream, io.BytesIO(b'x' * 5000))
    failed(credential_from_stream, io.BytesIO(b''))


def test_gh_source_is_fixed_command_and_never_logs_output(
    tmp_path, monkeypatch, capfd
):
    """The legacy default: the operator's own ``gh`` login, argv fixed."""
    record = tmp_path / 'record'
    fake = script(
        tmp_path, 'gh',
        f'printf "%s\\n" "$@" > {record}; env | sort >> {record}; echo {TOKEN}',
    )  # fmt: skip
    assert fake.name == 'gh'
    monkeypatch.setenv('PATH', f'{tmp_path}:{os.environ["PATH"]}')
    monkeypatch.setenv('GH_DEBUG', 'api')
    monkeypatch.setenv('GH_CONFIG_DIR', '/operator/gh')
    monkeypatch.setenv('GH_TOKEN', 'ambient-token-must-not-be-forwarded')
    assert resolve_source(GH_SOURCE) == TOKEN
    seen = record.read_text().splitlines()
    assert seen[:4] == ['auth', 'token', '--hostname', 'github.com']
    assert 'GH_CONFIG_DIR=/operator/gh' in seen
    assert not any(line.startswith(('GH_DEBUG=', 'GH_TOKEN=')) for line in seen)
    captured = capfd.readouterr()
    assert TOKEN not in captured.out + captured.err


def test_resolve_source_validates_before_touching_anything():
    for bad in [
        {'kind': 'shell', 'script': 'id'},
        {'kind': 'command', 'argv': 'id'},
        None,
    ]:
        failed(resolve_source, bad, code='invalid_policy')
