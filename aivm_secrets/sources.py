"""Explicit host-only credential acquisition; no guest-selected commands."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .envelope import validate_credential
from .errors import SecretsError
from .files import read_owned


def credential_from_file(path: Path) -> str:
    try:
        return validate_credential(read_owned(path, private=True, limit=4097)
                                   .decode('ascii').rstrip('\n'))
    except UnicodeError:
        raise SecretsError('credential_source') from None


def credential_from_gh() -> str:
    """Use the owning operator's gh login; never put output into command logs."""
    gh = shutil.which('gh')
    if gh is None:
        raise SecretsError('credential_source')
    env = dict(os.environ)
    env.pop('GH_DEBUG', None)
    env['GH_PROMPT_DISABLED'] = '1'
    try:
        result = subprocess.run([gh, 'auth', 'token', '--hostname', 'github.com'],
                                capture_output=True, text=True, env=env,
                                timeout=15, check=False)
        if result.returncode:
            raise SecretsError('credential_source')
        return validate_credential(result.stdout.rstrip('\n'))
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise SecretsError('credential_source') from None


def parse_source(value):
    """Validate an operator-owned source, never supplied by a guest request.

    Credential *acquisition* is independent of the HTTP/CLI being authorized.
    Commands are literal argv (no shell), with explicit inherited environment.
    """
    import re
    from .kernel import exact_keys, text
    code = 'invalid_policy'
    if type(value) is not dict:
        raise SecretsError(code)
    kind = value.get('kind')
    if kind == 'file':
        exact_keys(value, {'kind', 'path'}, code=code)
        path = text(value['path'], 4096, code=code)
        if not Path(path).is_absolute():
            raise SecretsError(code)
        return {'kind': 'file', 'path': path}
    if kind == 'command':
        exact_keys(value, {'kind', 'argv'}, {'inherit_env'}, code=code)
        argv = value['argv']
        env = value.get('inherit_env', [])
        if (type(argv) is not list or not 1 <= len(argv) <= 32
                or type(env) is not list or len(env) > 32):
            raise SecretsError(code)
        argv = [text(arg, 1024, code=code) for arg in argv]
        if sum(len(arg) for arg in argv) > 8192:
            raise SecretsError(code)
        if any(type(var) is not str or not re.fullmatch(r'[A-Z_][A-Z0-9_]{0,63}', var)
               for var in env) or len(set(env)) != len(env):
            raise SecretsError(code)
        if any(var in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME',
                       'BASH_ENV', 'ENV', 'GH_DEBUG') for var in env):
            raise SecretsError(code)
        return {'kind': 'command', 'argv': argv, 'inherit_env': sorted(env)}
    raise SecretsError(code)


def credential_from_command(argv, inherit_env=()):
    """Run a trusted host credential resolver with bounded stdout, no shell.

    Operators must review a resolver's executable and argv as trusted code.
    This resolves credentials; it does not grant authority to run a guest CLI.
    """
    import select
    import time
    executable = shutil.which(argv[0])
    if executable is None:
        raise SecretsError('credential_source')
    env = {key: os.environ[key] for key in ('HOME', 'PATH') if key in os.environ}
    for key in inherit_env:
        if key in os.environ:
            env[key] = os.environ[key]
    # Absence of debugging/proxy vars matters for token retrieval/logging.
    command = [executable, *argv[1:]]
    proc = None
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, close_fds=True, cwd=os.path.expanduser('~'))
        assert proc.stdout is not None
        deadline = time.monotonic() + 15
        output = bytearray()
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise SecretsError('credential_source')
            if not select.select([proc.stdout], [], [], remain)[0]:
                raise SecretsError('credential_source')
            chunk = os.read(proc.stdout.fileno(), 4098 - len(output))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 4097:
                raise SecretsError('credential_source')
        if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise SecretsError('credential_source')
        return validate_credential(output.decode('ascii').rstrip('\n'))
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        raise SecretsError('credential_source') from None
    finally:
        if proc is not None:
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def resolve_source(value):
    source = parse_source(value)
    if source['kind'] == 'file':
        return credential_from_file(Path(source['path']))
    return credential_from_command(source['argv'], source['inherit_env'])
