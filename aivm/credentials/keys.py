"""Host-side deploy-key storage and fingerprint helpers."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from pathlib import Path

from ..config_store import app_data_dir
from ..errors import AIVMError
from .validation import (
    CredentialValidationError,
    credential_id,
    validate_credential_id_format,
)

_SAFE_PART = re.compile(r'[^A-Za-z0-9_.-]+')


def _safe_vm_name(vm_name: str) -> str:
    value = _SAFE_PART.sub('_', vm_name.strip()).strip('._')
    if not value:
        raise AIVMError(f'Cannot derive credential path from VM name {vm_name!r}.')
    return value


def _trusted_app_data_root() -> Path:
    """Resolve the application-data directory used as the trust boundary."""
    lexical_root = app_data_dir()
    try:
        root = lexical_root.resolve(strict=True)
        info = root.lstat()
    except (OSError, RuntimeError) as ex:
        raise AIVMError(
            f'Could not establish the AIVM application-data root '
            f'{lexical_root}: {ex}'
        ) from ex
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AIVMError(
            f'AIVM application-data root must resolve to a real directory: '
            f'{root}'
        )
    if info.st_uid != os.getuid():
        raise AIVMError(
            f'AIVM application-data root is not owned by the current user: '
            f'{root}'
        )
    return root


def _require_managed_directory(path: Path, *, label: str) -> None:
    """Reject symlinked or foreign-owned managed path components."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AIVMError(
            f'{label} must be a real directory, not a symlink or other '
            f'file type: {path}'
        )
    if info.st_uid != os.getuid():
        raise AIVMError(f'{label} is not owned by the current user: {path}')


def host_credential_dir(vm_name: str, cred_id: str) -> Path:
    """Return a credential path after validating every managed ancestor."""
    try:
        safe_id = validate_credential_id_format(cred_id)
    except CredentialValidationError as ex:
        raise AIVMError(str(ex)) from ex

    root = _trusted_app_data_root()
    vm_dir = root / _safe_vm_name(vm_name)
    credentials_dir = vm_dir / 'credentials'
    path = credentials_dir / safe_id
    if path.parent != credentials_dir:
        raise AIVMError('Credential path escaped its managed host directory.')

    # Every component below the resolved application-data trust boundary must
    # be a real directory. Otherwise creation or recursive deletion could be
    # redirected outside AIVM's data tree through an intermediate symlink.
    _require_managed_directory(vm_dir, label='AIVM VM data directory')
    _require_managed_directory(
        credentials_dir, label='AIVM credential parent directory'
    )
    _require_managed_directory(path, label='Host credential directory')
    return path


def host_private_key_path(vm_name: str, cred_id: str) -> Path:
    return host_credential_dir(vm_name, cred_id) / 'id_ed25519'


def host_public_key_path(vm_name: str, cred_id: str) -> Path:
    return host_credential_dir(vm_name, cred_id) / 'id_ed25519.pub'


def normalized_public_key(text: str) -> str:
    parts = str(text or '').strip().split()
    if len(parts) < 2:
        raise AIVMError('Malformed SSH public key.')
    return f'{parts[0]} {parts[1]}'


def public_key_fingerprint(text: str) -> str:
    parts = normalized_public_key(text).split()
    try:
        blob = base64.b64decode(parts[1].encode('ascii'), validate=True)
    except Exception as ex:
        raise AIVMError('Malformed SSH public key payload.') from ex
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii')
    return 'SHA256:' + digest.rstrip('=')
