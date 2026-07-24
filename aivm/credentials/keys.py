"""Host-side deploy-key storage and fingerprint helpers."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from ..config_store import app_data_path
from ..errors import AIVMError

_SAFE_PART = re.compile(r'[^A-Za-z0-9_.-]+')


def credential_id(vm_name: str, canonical_repo: str) -> str:
    payload = f'{vm_name}\0{canonical_repo}'.encode('utf-8')
    return 'git-' + hashlib.sha256(payload).hexdigest()[:12]


def _safe_vm_name(vm_name: str) -> str:
    value = _SAFE_PART.sub('_', vm_name.strip()).strip('._')
    if not value:
        raise AIVMError(f'Cannot derive credential path from VM name {vm_name!r}.')
    return value


def host_credential_dir(vm_name: str, cred_id: str) -> Path:
    return app_data_path(_safe_vm_name(vm_name), 'credentials', cred_id)


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
