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
