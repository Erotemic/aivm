"""Shared fixtures for the persistent-attachment test modules.

The in-guest replay helper is exercised by executing its rendered source
in-process and feeding it a fake ``subprocess.run``.  Both the executor
and the mount-simulating fake live here so the template tests and the
guest-replay tests can share them without one test module importing from
another.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from typing import Any

from tests.helpers import FakeProc


def _exec_guest_replay_helper(source: str) -> dict[str, Any]:
    """Execute the rendered replay helper and return its namespace.

    The helper's ``subprocess`` reference is replaced with a stand-in so a
    test can swap ``run`` without mutating the real :mod:`subprocess`
    module.
    """
    ns: dict[str, Any] = {'__name__': 'not_main'}
    exec(source, ns)
    real_subprocess = ns.get('subprocess')
    ns['subprocess'] = SimpleNamespace(
        run=getattr(real_subprocess, 'run', subprocess.run),
        PIPE=getattr(real_subprocess, 'PIPE', subprocess.PIPE),
        DEVNULL=getattr(real_subprocess, 'DEVNULL', subprocess.DEVNULL),
    )
    return ns


def _make_guest_replay_fake_run(
    mounts: dict[str, dict[str, str]],
    *,
    calls: list[list[Any]] | None = None,
    root_mount: str | None = None,
    register_root_mount: bool = True,
    findmnt_target_always_root: bool = False,
    umount_busy: bool = False,
) -> Any:
    """Build a fake ``subprocess.run`` that simulates guest mount state.

    ``mounts`` is the mutable mount table the fake reads and writes.  The
    keyword arguments cover the handful of behaviors the individual tests
    need on top of the common dispatcher:

    - ``calls``: when given, every command list is appended to it.
    - ``root_mount``: a path reported as an already-live mountpoint by
      ``mountpoint -q`` even though it is not in ``mounts``.
    - ``register_root_mount``: whether a ``mount -t`` records the root
      mount back into ``mounts`` (the default) or is a no-op.
    - ``findmnt_target_always_root``: force ``findmnt --target`` to report
      the root filesystem regardless of ``mounts``.
    - ``umount_busy``: make ``umount`` report a busy target (rc 16)
      instead of removing the mount.
    """
    tracked_root: str = ''

    def fake_run(
        cmd: list,
        check: bool = False,
        capture_output: bool = False,
        text: bool = False,
        stdout: Any = None,
        stderr: Any = None,
        **kwargs: Any,
    ) -> FakeProc:
        del check, capture_output, text, stdout, stderr, kwargs
        nonlocal tracked_root
        if calls is not None:
            calls.append(list(cmd))
        if cmd[:2] == ['mountpoint', '-q']:
            target = cmd[-1]
            mounted = target in mounts or (
                root_mount is not None and target == root_mount
            )
            return FakeProc(returncode=0 if mounted else 1)
        if cmd and cmd[0] == 'findmnt' and '--mountpoint' in cmd:
            target = cmd[-1]
            info = mounts.get(target)
            if info is None:
                return FakeProc(returncode=1)
            return FakeProc(
                stdout=(
                    f'TARGET="{target}" SOURCE="{info["source"]}" '
                    f'OPTIONS="{info["options"]}"'
                )
            )
        if cmd[:2] == ['mount', '-t']:
            tracked_root = cmd[-1]
            if register_root_mount:
                mounts[tracked_root] = {
                    'source': tracked_root,
                    'options': 'rw',
                }
            return FakeProc()
        if cmd and cmd[0] == 'mount' and '--bind' in cmd:
            target = cmd[-1]
            source = cmd[cmd.index('--bind') + 1]
            mounts[target] = {'source': source, 'options': 'rw'}
            return FakeProc()
        if cmd and cmd[0] == 'mount' and 'remount,bind,ro' in cmd[-2]:
            target = cmd[-1]
            if target in mounts:
                mounts[target]['options'] = 'ro'
            return FakeProc()
        if cmd and cmd[0] == 'mount' and 'remount,bind,rw' in cmd[-2]:
            target = cmd[-1]
            if target in mounts:
                mounts[target]['options'] = 'rw'
            return FakeProc()
        if cmd and cmd[0] == 'findmnt' and '--target' in cmd:
            target = cmd[-1]
            info = None if findmnt_target_always_root else mounts.get(target)
            if info is None:
                return FakeProc(
                    stdout='TARGET="/" SOURCE="/dev/vda1" OPTIONS="rw"'
                )
            return FakeProc(
                stdout=(
                    f'TARGET="{target}" SOURCE="{info["source"]}" '
                    f'OPTIONS="{info["options"]}"'
                )
            )
        if cmd and cmd[0] == 'findmnt':
            lines = [
                f'TARGET="{target}" SOURCE="{info["source"]}"'
                for target, info in mounts.items()
            ]
            return FakeProc(stdout='\n'.join(lines))
        if cmd and cmd[0] == 'umount':
            if umount_busy:
                return FakeProc(
                    returncode=16, stderr='umount: target is busy'
                )
            mounts.pop(cmd[-1], None)
            return FakeProc()
        raise AssertionError(f'unhandled fake command: {cmd}')

    setattr(fake_run, 'mounts', mounts)
    return fake_run
