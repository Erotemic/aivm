"""Best-effort process hardening, observed from outside the process."""

from __future__ import annotations

import subprocess
import sys
import types

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host import hardening


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
    def refuse(*args, **kwargs):
        raise OSError('not permitted')

    monkeypatch.setattr(hardening.resource, 'setrlimit', refuse)
    monkeypatch.setattr(hardening.ctypes, 'CDLL', refuse)
    assert hardening.harden_process() is False


# -- where the running code came from ----------------------------------------


def refused(untrusted) -> str:
    with pytest.raises(SecretsError) as caught:
        hardening.verify_runtime(untrusted)
    assert caught.value.code == 'shared_source'
    return caught.value.detail


def test_an_ordinary_runtime_is_accepted(tmp_path):
    hardening.verify_runtime(())
    hardening.verify_runtime((tmp_path / 'workspace',))


def test_a_search_path_entry_in_the_workspace_is_refused(tmp_path, monkeypatch):
    workspace = tmp_path / 'workspace'
    (workspace / 'lib').mkdir(parents=True)
    monkeypatch.setattr(sys, 'path', [*sys.path, str(workspace / 'lib')])
    assert 'module search path entry' in refused((workspace,))
    # An entry that merely *links* into the workspace is the same thing.
    link = tmp_path / 'innocent'
    link.symlink_to(workspace / 'lib')
    monkeypatch.setattr(sys, 'path', [*sys.path[:-1], str(link)])
    assert 'module search path entry' in refused((workspace,))
    # ... and so is the empty entry, which means the current directory.
    monkeypatch.setattr(sys, 'path', [*sys.path[:-1], ''])
    hardening.verify_runtime((workspace,))
    monkeypatch.chdir(workspace)
    assert 'module search path entry' in refused((workspace,))


def test_a_module_already_loaded_from_the_workspace_is_refused(
    tmp_path, monkeypatch
):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    planted = types.ModuleType('sitecustomize')
    planted.__file__ = str(workspace / 'sitecustomize.py')
    monkeypatch.setitem(sys.modules, 'sitecustomize', planted)
    assert 'loaded module sitecustomize' in refused((workspace,))
    # Namespace packages and builtins have no file; they are not a reason.
    monkeypatch.setitem(sys.modules, 'sitecustomize', types.ModuleType('x'))
    hardening.verify_runtime((workspace,))


def test_the_interpreter_and_the_broker_itself_are_checked(tmp_path):
    from pathlib import Path

    package = Path(hardening.__file__).resolve().parents[2]
    assert 'broker code' in refused((package,))
    assert 'broker python environment' in refused((Path(sys.prefix),))
