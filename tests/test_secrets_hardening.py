"""Best-effort process hardening, observed from outside the process."""

from __future__ import annotations

import subprocess
import sys


def test_hardening_disables_core_dumps_and_ptrace_visibility():
    program = (
        'import os, resource\n'
        'from aivm_secrets.host.hardening import harden_process\n'
        'before = os.stat("/proc/self/environ").st_uid\n'
        'print(harden_process())\n'
        'print(resource.getrlimit(resource.RLIMIT_CORE))\n'
        'print(before, os.stat("/proc/self/environ").st_uid, os.getuid())\n'
    )
    done = subprocess.run(
        [sys.executable, '-c', program],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    hardened, core, owners = done.stdout.splitlines()
    assert hardened == 'True' and core == '(0, 0)'
    before, after, uid = map(int, owners.split())
    # A non-dumpable process's /proc files belong to root, not to its user.
    assert before == uid and after == 0


def test_hardening_never_raises(monkeypatch):
    from aivm_secrets.host import hardening

    def refuse(*args, **kwargs):
        raise OSError('not permitted')

    monkeypatch.setattr(hardening.resource, 'setrlimit', refuse)
    monkeypatch.setattr(hardening.ctypes, 'CDLL', refuse)
    assert hardening.harden_process() is False
