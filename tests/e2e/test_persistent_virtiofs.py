"""Real virtiofs coverage for guest submount identity and foreground safety.

Unlike the bind-only replay tests, this boots a disposable VM and exercises
virtiofs auto-submount recreation while its original workspace remains busy.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import textwrap
from pathlib import Path

import pytest

from aivm.config_store import (
    Store, find_attachment_for_vm, load_store, split_fragment_paths,
)
from aivm.config_store.models import STORE_SCHEMA_VERSION
from aivm.scoped_store import persist_creator_vm, resolve_store_scope
from tests.e2e._helpers import (
    REPO_ROOT,
    Terminal,
    _host_context_enabled,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
    apply_shared_image_cache,
    e2e_teardown,
    make_e2e_config,
    require_passwordless_sudo,
    run_ssh_command,
)

pytestmark = pytest.mark.e2e


def test_foreground_preserves_busy_workspace_after_virtiofs_submount_recreation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capture SOURCE=none / differing st_dev on a newly created VM.

    The harness knows both views originate from the same host directory. The
    current helper cannot prove that from mountinfo, and must preserve the
    workspace while reporting degraded state. Keep that safety assertion when
    improving automatic recognition/recovery of these mounts.
    """
    if not _host_context_enabled():
        pytest.skip('Set AIVM_E2E=1 to run the real virtiofs lifecycle test.')
    require_passwordless_sudo()
    home, private_key, public_key = _make_temp_ssh_material(tmp_path)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('AIVM_MACHINE_STORE_ROOT', str(tmp_path / 'machine'))
    env = os.environ.copy()
    timeout = int(os.getenv('AIVM_E2E_TIMEOUT', '600'))
    _require_e2e_host_dependencies(cwd=REPO_ROOT, timeout_s=timeout, env=env)
    cfg = make_e2e_config(
        tmp_path, priv=private_key, pub=public_key,
        name_prefix='aivm-e2e-vfs', cpus=2,
    )
    apply_shared_image_cache(cfg)
    scope = resolve_store_scope(None)
    store = Store(store_kind='machine', schema_version=STORE_SCHEMA_VERSION)
    persist_creator_vm(scope, store, cfg, set_active=True,
                       reason='Prepare an isolated real-virtiofs regression VM.')
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'sentinel').write_text('original-host-directory')

    def cli(*argv: str):
        return _run_cli(
            [*argv, '--yes', '--config', str(scope.store_path)],
            cwd=REPO_ROOT, env=env, timeout_s=timeout,
        )

    with e2e_teardown(scope.store_path, env=env, timeout_s=timeout):
        cli('host', 'net', 'create')
        cli('vm', 'up')
        ip = cli('vm', 'wait_ip').stdout.strip().splitlines()[-1]
        cli('vm', 'attach', str(workspace), '--mirror_home', 'no')
        attachment = find_attachment_for_vm(
            load_store(scope.store_path), workspace, cfg.vm.name,
        )
        assert attachment is not None and attachment.mode == 'persistent'
        source = '/mnt/aivm-persistent/' + attachment.tag
        fragments = split_fragment_paths(load_store(scope.store_path), scope.store_path)
        before = {
            path: (path.read_bytes(), path.stat()) for path in fragments.values()
        }
        for _ in range(2):
            terminal = Terminal(
                [sys.executable, '-m', 'aivm', 'ssh', str(workspace), '--yes',
                 '--config', str(scope.store_path)],
                cwd=REPO_ROOT, env=env,
            )
            try:
                terminal.ready(timeout=60)
                terminal.send('exit\n')
                assert terminal.wait(timeout=15) == 0
                assert 'Writing split config store' not in terminal.output
                assert 'completed in degraded mode' not in terminal.output
            finally:
                if terminal.returncode is None:
                    terminal.kill()
        for path, (content, info) in before.items():
            assert path.read_bytes() == content
            current = path.stat()
            assert (current.st_ino, current.st_mtime_ns) == (info.st_ino, info.st_mtime_ns)
        # Only the disposable guest's source-side automount is expired. Keep
        # its workspace bind busy so recovery cannot silently replace it.
        script = textwrap.dedent(r'''
            import json
            import os
            from pathlib import Path
            import subprocess
            import sys

            source, target = sys.argv[1:]
            def mount_info(path):
                result = subprocess.run(
                    ['findmnt', '--json', '--mountpoint', path,
                     '-o', 'ID,TARGET,SOURCE,FSTYPE,FSROOT,MAJ:MIN'],
                    check=True, capture_output=True, text=True,
                )
                return json.loads(result.stdout)['filesystems'][0]

            before_source, before_target = os.stat(source), os.stat(target)
            assert (before_source.st_dev, before_source.st_ino) == (
                before_target.st_dev, before_target.st_ino)
            before_mount = mount_info(target)
            holder = subprocess.Popen(['sleep', '120'], cwd=target)
            try:
                subprocess.run(['sudo', '-n', 'umount', source], check=True)
                # stat of the mountpoint itself can avoid triggering an automount. Cross
                # into a child to recreate the virtiofs submount before comparing views.
                assert Path(source, 'sentinel').read_text() == 'original-host-directory'
                current_source, current_target = os.stat(source), os.stat(target)
                assert current_source.st_dev != current_target.st_dev
                assert current_source.st_ino == current_target.st_ino
                source_mount, target_mount = mount_info(source), mount_info(target)
                assert source_mount['fstype'] == target_mount['fstype'] == 'virtiofs'
                assert source_mount['source'] == target_mount['source'] == 'none'
                result = subprocess.run(
                    ['sudo', '-n', '/usr/local/libexec/aivm-persistent-attachment-replay',
                     '--only-guest-dst', target, '--preserve-live-mounts'],
                    capture_output=True, text=True,
                )
                assert result.returncode == 3, (result.stdout, result.stderr)
                assert 'foreground session preparation leaves live mounts untouched' in result.stderr
                assert mount_info(target)['id'] == before_mount['id']
                assert holder.poll() is None
                assert Path(target, 'sentinel').read_text() == 'original-host-directory'
                print(json.dumps({'source': source_mount, 'workspace': target_mount,
                                  'replay_code': result.returncode, 'diagnostic': result.stderr}))
            finally:
                holder.terminate()
                holder.wait(timeout=5)
        ''')
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['python3', '-c', shlex.quote(script), shlex.quote(source),
                    shlex.quote(attachment.guest_dst)],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(result.stdout.strip())
        print(json.dumps(report, indent=2, sort_keys=True))
