"""Small helpers for comparing OpenSSH public keys by key material."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import AIVMError


@dataclass(frozen=True)
class SSHPublicKeyIdentity:
    algorithm: str
    blob: str


def ssh_public_key_identity(line: str) -> SSHPublicKeyIdentity:
    """Parse an OpenSSH public-key line, ignoring its optional comment."""
    parts = str(line or '').strip().split()
    if len(parts) < 2:
        raise AIVMError('SSH public key must contain an algorithm and key blob')
    algorithm, blob = parts[0], parts[1]
    if not algorithm.startswith(('ssh-', 'ecdsa-', 'sk-')):
        raise AIVMError(f'Unsupported SSH public-key algorithm: {algorithm!r}')
    if not blob:
        raise AIVMError('SSH public key blob is empty')
    return SSHPublicKeyIdentity(algorithm=algorithm, blob=blob)


def same_ssh_public_key(left: str, right: str) -> bool:
    """Return whether two public-key lines contain the same key material."""
    try:
        return ssh_public_key_identity(left) == ssh_public_key_identity(right)
    except AIVMError:
        return False
