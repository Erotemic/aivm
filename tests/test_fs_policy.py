"""Shared machine-store filesystem policy: converge, don't insist.

chmod/chown require *ownership*, but a machine store is used by every member
of the trusted group. These tests pin the multi-principal contract: metadata
that already complies is never touched, an over-permissive mode a non-owner
cannot tighten is tolerated, and only metadata that actually denies the group
is a hard error.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aivm.config_store.fs_policy import (
    StoreFilesystemPolicy,
    apply_store_file_descriptor_policy,
    ensure_store_directory,
)


def _policy(root: Path) -> StoreFilesystemPolicy:
    return StoreFilesystemPolicy(
        managed_root=root,
        directory_mode=0o2770,
        file_mode=0o660,
        group_gid=os.getgid(),
        reject_symlinks=True,
    )


def test_compliant_metadata_is_never_touched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A root-owned but compliant tree must not trigger chmod/chown at all.

    Regression: unconditional chmod on every load meant a group member could
    never use a store root created per the documented
    `sudo install -d -o root -g aivm` bootstrap (chmod by a non-owner is
    EPERM even when the mode is already correct).
    """
    root = tmp_path / 'store'
    root.mkdir(mode=0o2770)
    os.chmod(root, 0o2770)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError('metadata change attempted on compliant path')

    monkeypatch.setattr(os, 'chmod', forbidden)
    monkeypatch.setattr(os, 'chown', forbidden)

    ensure_store_directory(root, _policy(root))


def test_over_permissive_mode_is_tolerated_for_non_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-owner who cannot tighten 2775 -> 2770 still gets a working store."""
    root = tmp_path / 'store'
    root.mkdir(mode=0o2775)
    os.chmod(root, 0o2775)

    def eperm(*args: object, **kwargs: object) -> None:
        raise PermissionError('Operation not permitted')

    monkeypatch.setattr(os, 'chmod', eperm)

    ensure_store_directory(root, _policy(root))


def test_group_denying_mode_is_a_hard_error_for_non_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / 'store'
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)

    def eperm(*args: object, **kwargs: object) -> None:
        raise PermissionError('Operation not permitted')

    monkeypatch.setattr(os, 'chmod', eperm)

    with pytest.raises(PermissionError, match='denies the trusted'):
        ensure_store_directory(root, _policy(root))


def test_foreign_group_is_a_hard_error_with_guidance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / 'store'
    root.mkdir(mode=0o2770)

    policy = StoreFilesystemPolicy(
        managed_root=root,
        directory_mode=0o2770,
        group_gid=os.getgid() + 1,
    )

    def eperm(*args: object, **kwargs: object) -> None:
        raise PermissionError('Operation not permitted')

    monkeypatch.setattr(os, 'chown', eperm)

    with pytest.raises(
        PermissionError,
        match='trusted\nmachine-store group|trusted machine-store group',
    ):
        ensure_store_directory(root, policy)


def test_lock_fd_owned_by_other_principal_is_usable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Entering a lock another member created must not require ownership.

    Regression: an unconditional fchown/fchmod on the shared lock file raised
    EPERM for every principal except its creator, making every load and save
    of the shared store fail.
    """
    lock_path = tmp_path / 'store.lock'
    lock_path.touch(mode=0o660)
    os.chmod(lock_path, 0o660)

    def eperm(*args: object, **kwargs: object) -> None:
        raise PermissionError('Operation not permitted')

    monkeypatch.setattr(os, 'fchown', eperm)
    monkeypatch.setattr(os, 'fchmod', eperm)

    fd = os.open(lock_path, os.O_RDWR)
    try:
        apply_store_file_descriptor_policy(
            fd, StoreFilesystemPolicy(file_mode=0o660, group_gid=os.getgid())
        )
    finally:
        os.close(fd)
