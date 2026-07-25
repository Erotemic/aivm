"""Host-side deploy-key storage and fingerprint helpers."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from dataclasses import replace
from pathlib import Path

from ..commands import CommandManager
from ..config_store.models import CredentialEntry
from ..config_store.paths import app_data_dir
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
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022:
        raise AIVMError(
            f'AIVM application-data root is writable by group or others: '
            f'{root} has mode {mode:04o}.'
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
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022:
        raise AIVMError(
            f'{label} is writable by group or others: '
            f'{path} has mode {mode:04o}.'
        )


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


def _require_safe_host_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as ex:
        raise AIVMError(f'Host credential directory is missing: {path}') from ex
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AIVMError(
            f'Host credential directory must be a real directory, not a '
            f'symlink or other file type: {path}'
        )
    if info.st_uid != os.getuid():
        raise AIVMError(
            f'Host credential directory is not owned by the current user: {path}'
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise AIVMError(
            f'Host credential directory permissions are too broad: '
            f'{path} has mode {mode:04o}; expected no group or other access.'
        )


def _require_safe_host_file(
    path: Path,
    *,
    private: bool,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as ex:
        raise AIVMError(f'Host credential file is missing: {path}') from ex
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AIVMError(
            f'Host credential file must be a regular file, not a symlink or '
            f'other file type: {path}'
        )
    if info.st_uid != os.getuid():
        raise AIVMError(
            f'Host credential file is not owned by the current user: {path}'
        )
    mode = stat.S_IMODE(info.st_mode)
    if private and mode & 0o077:
        raise AIVMError(
            f'Host private key permissions are too broad: {path} has mode '
            f'{mode:04o}; expected no group or other access.'
        )
    if not private and mode & 0o022:
        raise AIVMError(
            f'Host public key is writable by group or others: {path} has '
            f'mode {mode:04o}.'
        )


def inspect_host_keypair(
    entry: CredentialEntry,
    *,
    manager: CommandManager,
) -> tuple[str, str]:
    """Validate host key material and return public text plus fingerprint."""
    private_path = host_private_key_path(entry.vm_name, entry.id)
    public_path = host_public_key_path(entry.vm_name, entry.id)
    _require_safe_host_directory(private_path.parent)
    _require_safe_host_file(private_path, private=True)
    _require_safe_host_file(public_path, private=False)

    try:
        public_text = public_path.read_text(encoding='utf-8').strip()
    except (OSError, UnicodeError) as ex:
        raise AIVMError(f'Could not read host public key {public_path}: {ex}') from ex
    normalized_public = normalized_public_key(public_text)
    # Validate the public-key payload before comparing it with the key
    # derived from the private key. Otherwise an arbitrary two-token string
    # is reported as a keypair mismatch instead of malformed public data.
    fingerprint = public_key_fingerprint(normalized_public)
    result = manager.run(
        ['ssh-keygen', '-y', '-f', str(private_path)],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        input_text='',
        timeout=10,
        summary=f'Validate host deploy-key pair {entry.id}',
        detail=f'private={private_path} public={public_path}',
    )
    if result.code != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Host private key for credential {entry.id} is invalid or '
            f'unreadable: {detail or "ssh-keygen -y failed"}'
        )
    derived_public = normalized_public_key(result.stdout)
    if derived_public != normalized_public:
        raise AIVMError(
            f'Host private and public keys for credential {entry.id} do not '
            'form a matching keypair.'
        )
    if entry.key_fingerprint and fingerprint != entry.key_fingerprint:
        raise AIVMError(
            f'Host keypair for credential {entry.id} does not match the '
            'fingerprint recorded by AIVM.'
        )
    return public_text, fingerprint


def generate_host_key(
    entry: CredentialEntry, *, manager: CommandManager
) -> CredentialEntry:
    private_path = host_private_key_path(entry.vm_name, entry.id)
    public_path = host_public_key_path(entry.vm_name, entry.id)
    directory = private_path.parent
    directory_exists = os.path.lexists(directory)
    if directory_exists:
        # Reject an existing symlink or other unsafe leaf before chmod,
        # ssh-keygen, or any other operation can follow it.
        _require_safe_host_directory(directory)
    private_exists = os.path.lexists(private_path)
    public_exists = os.path.lexists(public_path)
    if private_exists and public_exists:
        if not entry.key_fingerprint:
            raise AIVMError(
                f'Untracked host key material already exists for credential '
                f'{entry.id}. Refusing to reuse a keypair that is not recorded '
                'in AIVM state.'
            )
        _, actual_fingerprint = inspect_host_keypair(entry, manager=manager)
        return replace(entry, key_fingerprint=actual_fingerprint)
    if private_exists or public_exists:
        raise AIVMError(
            f'Credential keypair is incomplete under {private_path.parent}. '
            'Remove the partial directory or revoke the pending credential.'
        )
    if entry.key_fingerprint:
        raise AIVMError(
            f'Host keypair for recorded credential {entry.id} is missing. '
            'Refusing to generate a replacement because GitHub may still '
            'contain the deploy key identified by provider key id '
            f'{entry.provider_key_id or "(unknown)"} and fingerprint '
            f'{entry.key_fingerprint}. Revoke or abandon the recorded '
            'credential before creating a new grant.'
        )
    with manager.step(
        f'Generate scoped deploy key {entry.id}',
        why='Create a unique SSH keypair for one VM and one repository.',
        approval_scope=f'vm-credential-key:{entry.id}',
    ):
        if not directory_exists:
            # Create each managed descendant separately. A pre-existing VM or
            # credentials directory has already been lstat-validated by
            # host_credential_dir(); avoiding mkdir -p prevents silently
            # traversing an intermediate symlink.
            vm_directory = directory.parent.parent
            credentials_directory = directory.parent
            if not os.path.lexists(vm_directory):
                manager.submit(
                    ['mkdir', '-m', '700', str(vm_directory)],
                    role='modify',
                    summary='Create protected VM data directory',
                )
            if not os.path.lexists(credentials_directory):
                manager.submit(
                    ['mkdir', '-m', '700', str(credentials_directory)],
                    role='modify',
                    summary='Create protected credential parent directory',
                )
            manager.submit(
                ['mkdir', '-m', '700', str(directory)],
                role='modify',
                summary='Create protected host credential directory',
            )
        # Recheck the complete descendant chain after creation and immediately
        # before writing key material. In dry-run mode missing directories are
        # permitted, while real execution validates what was just created.
        host_credential_dir(entry.vm_name, entry.id)
        manager.submit(
            [
                'ssh-keygen',
                '-q',
                '-t',
                'ed25519',
                '-N',
                '',
                '-f',
                str(private_path),
                '-C',
                entry.provider_key_title,
            ],
            role='modify',
            summary='Generate repository-scoped SSH keypair',
            detail=f'private={private_path} public={public_path}',
        )
        manager.submit(
            ['chmod', '600', str(private_path)],
            role='modify',
            summary='Protect host deploy-key private key',
        )
        manager.submit(
            ['chmod', '644', str(public_path)],
            role='modify',
            summary='Set host deploy-key public key permissions',
        )
    generated_entry = replace(entry, key_fingerprint='')
    _, fingerprint = inspect_host_keypair(generated_entry, manager=manager)
    return replace(entry, key_fingerprint=fingerprint)
