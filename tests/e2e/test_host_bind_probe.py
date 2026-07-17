"""End-to-end proof the findmnt probe reads real bind mounts.

The probe once named a column real findmnt does not have (``ROOT``
instead of ``FSROOT``), so against a live system it always failed and
every result read as "not a mountpoint" -- turning each session's
access check into a privileged remount. Unit fakes reproduced the
broken command faithfully; only a real mount catches this class, so
this suite makes one.

Needs passwordless sudo (only to create and remove the bind; the probe
itself is unprivileged). Guarded by ``AIVM_E2E=1`` like the other e2e
suites.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from aivm.attachments.shared_root import (
    _ensure_host_bind_access,
    _probe_findmnt_target_source,
)
from aivm.commands import CommandManager
from tests.e2e._helpers import require_passwordless_sudo

pytestmark = pytest.mark.e2e


def _require_e2e() -> None:
    if os.getenv('AIVM_E2E') != '1':
        pytest.skip('Set AIVM_E2E=1 to run e2e tests.')
    require_passwordless_sudo()


def test_probe_reads_live_bind_and_access_check_stays_sudo_free(
    tmp_path: Path,
) -> None:
    _require_e2e()
    source = tmp_path / 'src'
    target = tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    subprocess.run(
        ['sudo', '-n', 'mount', '--bind', str(source), str(target)],
        check=True,
        capture_output=True,
    )
    try:
        # 'never' turns any escalation into a raise: the assertion that an
        # already-rw bind needs no privileged remount is structural.
        CommandManager.activate(CommandManager(privilege_mode='never'))
        probe = _probe_findmnt_target_source(target)

        assert probe.is_mountpoint
        assert 'rw' in probe.options.split(',')
        # FSROOT is the bind's source path; the repair detector keys off it.
        assert probe.root == str(source)

        _ensure_host_bind_access(target, 'rw')  # must not attempt a mount
    finally:
        CommandManager.reset_current()
        subprocess.run(
            ['sudo', '-n', 'umount', str(target)],
            check=True,
            capture_output=True,
        )


def test_probe_reports_plain_directory_as_no_mount(tmp_path: Path) -> None:
    _require_e2e()
    CommandManager.activate(CommandManager(privilege_mode='never'))
    try:
        probe = _probe_findmnt_target_source(tmp_path / 'just-a-dir')
        assert not probe.is_mountpoint
        assert probe.code != 0
    finally:
        CommandManager.reset_current()
