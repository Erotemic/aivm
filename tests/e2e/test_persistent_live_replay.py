"""E2E checks for non-destructive foreground persistent replay.

These tests use real Linux bind mounts because ``findmnt`` presentation and
mountpoint behavior are precisely what unit fakes can accidentally model wrong.
They do not create a VM; they exercise the generated guest replay helper against
the same kernel mount primitives it uses inside a guest.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from aivm.persistent_replay import persistent_replay_python
from tests.e2e._helpers import require_passwordless_sudo
from tests.persistent_helpers import _exec_guest_replay_helper

pytestmark = pytest.mark.e2e


def _require_e2e() -> None:
    if os.getenv('AIVM_E2E') != '1':
        pytest.skip('Set AIVM_E2E=1 to run e2e tests.')
    require_passwordless_sudo()


def _sudo(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ['sudo', '-n', *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _mount_bind_or_skip(source: Path, target: Path) -> None:
    proc = subprocess.run(
        ['sudo', '-n', 'mount', '--bind', str(source), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return
    detail = (proc.stderr or proc.stdout or '').strip()
    if 'permission denied' in detail.lower() or 'operation not permitted' in detail.lower():
        pytest.skip(f'E2E runner lacks mount capability: {detail}')
    raise AssertionError(f'Could not create E2E bind mount: {detail}')


def test_foreground_replay_keeps_busy_bind_of_same_directory(
    tmp_path: Path,
) -> None:
    """A healthy busy workspace is already converged, regardless of SOURCE text."""
    _require_e2e()
    persistent_root = tmp_path / 'persistent-root'
    source = persistent_root / 'token'
    target = tmp_path / 'workspace'
    source.mkdir(parents=True)
    target.mkdir()
    (source / 'sentinel.txt').write_text('live', encoding='utf-8')

    _mount_bind_or_skip(source, target)
    holder = subprocess.Popen(['sleep', '60'], cwd=target)
    try:
        ns = _exec_guest_replay_helper(persistent_replay_python())
        ns['PERSISTENT_ROOT_MOUNT'] = str(persistent_root)
        unmount_calls: list[str] = []
        real_unmount = ns['unmount_guest_dst']

        def record_unmount(guest_dst: str, *, ignore_busy: bool = False) -> None:
            unmount_calls.append(guest_dst)
            real_unmount(guest_dst, ignore_busy=ignore_busy)

        ns['unmount_guest_dst'] = record_unmount
        ns['ensure_record'](
            {
                'guest_dst': str(target),
                'shared_root_token': 'token',
                'access': 'rw',
                'enabled': True,
            },
            preserve_live_mounts=True,
        )

        assert unmount_calls == []
        assert ns['same_directory_object'](str(source), str(target))
        assert (target / 'sentinel.txt').read_text(encoding='utf-8') == 'live'
    finally:
        holder.terminate()
        holder.wait(timeout=5)
        _sudo('umount', str(target))


def test_foreground_replay_refuses_to_replace_different_busy_bind(
    tmp_path: Path,
) -> None:
    """A genuine conflict is diagnosed while the live mount remains intact."""
    _require_e2e()
    persistent_root = tmp_path / 'persistent-root'
    desired = persistent_root / 'desired-token'
    live = tmp_path / 'live-source'
    target = tmp_path / 'workspace'
    desired.mkdir(parents=True)
    live.mkdir()
    target.mkdir()
    (live / 'sentinel.txt').write_text('do-not-disrupt', encoding='utf-8')

    _mount_bind_or_skip(live, target)
    holder = subprocess.Popen(['sleep', '60'], cwd=target)
    try:
        ns = _exec_guest_replay_helper(persistent_replay_python())
        ns['PERSISTENT_ROOT_MOUNT'] = str(persistent_root)
        unmount_calls: list[str] = []
        real_unmount = ns['unmount_guest_dst']

        def record_unmount(guest_dst: str, *, ignore_busy: bool = False) -> None:
            unmount_calls.append(guest_dst)
            real_unmount(guest_dst, ignore_busy=ignore_busy)

        ns['unmount_guest_dst'] = record_unmount
        with pytest.raises(ns['LiveMountConflictError'], match='leaves live mounts untouched'):
            ns['ensure_record'](
                {
                    'guest_dst': str(target),
                    'shared_root_token': 'desired-token',
                    'access': 'rw',
                    'enabled': True,
                },
                preserve_live_mounts=True,
            )

        assert unmount_calls == []
        assert ns['same_directory_object'](str(live), str(target))
        assert (target / 'sentinel.txt').read_text(encoding='utf-8') == 'do-not-disrupt'
    finally:
        holder.terminate()
        holder.wait(timeout=5)
        _sudo('umount', str(target))
