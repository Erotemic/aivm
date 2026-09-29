"""Executable E2E checks for the guest VS Code tunnel helper."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aivm.rc.guest import tunnel_helper

pytestmark = pytest.mark.e2e


def _require_e2e() -> None:
    if os.getenv('AIVM_E2E') != '1':
        pytest.skip('Set AIVM_E2E=1 to run e2e tests.')


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding='utf-8')
    path.chmod(0o755)


def test_tunnel_helper_executes_as_installed_program_with_safe_arguments(
    tmp_path: Path,
) -> None:
    """Exercise the copied helper as a process, including unusual path/name text."""
    _require_e2e()
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    log_path = tmp_path / 'tmux.log'
    _write_executable(
        fake_bin / 'tmux',
        """#!/bin/sh
printf '%s\\n' "$@" >> "$AIVM_TMUX_LOG"
if [ "$1" = has-session ]; then
    exit 1
fi
exit 0
""",
    )
    _write_executable(fake_bin / 'code', '#!/bin/sh\nexit 0\n')
    work = tmp_path / 'project with space; safe'
    work.mkdir()
    env = dict(os.environ)
    env['PATH'] = str(fake_bin)
    env['AIVM_TMUX_LOG'] = str(log_path)

    result = subprocess.run(
        [
            sys.executable,
            str(Path(tunnel_helper.__file__).resolve()),
            'start',
            '--guest-path',
            str(work),
            '--name',
            'name with space; safe',
            '--session',
            'aivm-tunnel',
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    logged = log_path.read_text(encoding='utf-8').splitlines()
    assert logged[:3] == ['has-session', '-t', 'aivm-tunnel']
    assert 'new-session' in logged
    assert str(work) in logged
    assert (
        "code tunnel --name 'name with space; safe' "
        "--accept-server-license-terms"
        in logged
    )
