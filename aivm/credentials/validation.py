"""Validation for persisted and generated VM credential identities."""

from __future__ import annotations

import hashlib
import re

from .models import GitRepository

_CREDENTIAL_ID_RE = re.compile(r'^git-[0-9a-f]{12}$')
_HOST_RE = re.compile(r'^[A-Za-z0-9.-]+$')
_REPO_PART_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
_FINGERPRINT_RE = re.compile(r'^SHA256:[A-Za-z0-9+/]+$')


class CredentialValidationError(ValueError):
    """Raised when credential metadata is unsafe or internally inconsistent."""


def _reject_control_characters(field: str, value: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CredentialValidationError(
            f'Credential field {field!r} may not contain control characters.'
        )


def credential_id(vm_name: str, canonical_repo: str) -> str:
    """Return the deterministic id for one VM/repository authorization."""
    payload = f'{vm_name}\0{canonical_repo}'.encode('utf-8')
    return 'git-' + hashlib.sha256(payload).hexdigest()[:12]


def validate_credential_id_format(value: str) -> str:
    """Validate a credential id before using it as a path/config component."""
    text = str(value or '')
    _reject_control_characters('id', text)
    if not _CREDENTIAL_ID_RE.fullmatch(text):
        raise CredentialValidationError(
            f'Invalid credential id {text!r}; expected git-[0-9a-f]{{12}}.'
        )
    return text


def validate_repository_identity(
    provider_host: str,
    owner: str,
    repository: str,
) -> GitRepository:
    """Validate repository components used in SSH and Git configuration."""
    host = str(provider_host or '').strip().lower()
    owner_text = str(owner or '').strip()
    repo_text = str(repository or '').strip()
    for field, value in (
        ('provider_host', host),
        ('owner', owner_text),
        ('repository', repo_text),
    ):
        _reject_control_characters(field, value)
    if not host or not _HOST_RE.fullmatch(host):
        raise CredentialValidationError(
            f'Unsupported repository host syntax: {provider_host!r}'
        )
    if not _REPO_PART_RE.fullmatch(owner_text):
        raise CredentialValidationError(
            f'Unsupported repository owner syntax: {owner!r}'
        )
    if not _REPO_PART_RE.fullmatch(repo_text):
        raise CredentialValidationError(
            f'Unsupported repository name syntax: {repository!r}'
        )
    return GitRepository(host=host, owner=owner_text, name=repo_text)


def validate_credential_identity(
    *,
    vm_name: str,
    cred_id: str,
    provider_host: str,
    owner: str,
    repository: str,
) -> GitRepository:
    """Validate and cross-check the persisted identity of a credential."""
    validated_id = validate_credential_id_format(cred_id)
    repo = validate_repository_identity(provider_host, owner, repository)
    expected_id = credential_id(vm_name, repo.canonical)
    if validated_id != expected_id:
        raise CredentialValidationError(
            f'Credential id {validated_id!r} does not match VM {vm_name!r} '
            f'and repository {repo.display!r}; expected {expected_id!r}.'
        )
    return repo


def validate_metadata_text(field: str, value: str) -> str:
    """Reject control characters in metadata copied to commands or logs."""
    text = str(value or '').strip()
    _reject_control_characters(field, text)
    return text


def validate_provider_key_id(value: str) -> str:
    """Validate an optional GitHub deploy-key identifier."""
    text = validate_metadata_text('provider_key_id', value)
    if text and not text.isdigit():
        raise CredentialValidationError(
            f'Invalid GitHub deploy-key id {text!r}; expected decimal digits.'
        )
    return text


def validate_key_fingerprint(value: str) -> str:
    """Validate the stored OpenSSH SHA256 fingerprint spelling."""
    text = validate_metadata_text('key_fingerprint', value)
    if text and not _FINGERPRINT_RE.fullmatch(text):
        raise CredentialValidationError(
            f'Invalid SSH key fingerprint {text!r}.'
        )
    return text
