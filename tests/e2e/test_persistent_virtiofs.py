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
    helper must use its protected kernel reference to recognize that view,
    preserve a busy workspace, and recover it once idle. Reboot and detach also
    exercise rebuilding and releasing those private references.
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
    workspace = home / 'code' / 'workspace'
    workspace.mkdir(parents=True)
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
        # SSH can become ready before first-boot package/service setup ends.
        # Warm-entry and reboot assertions require that setup to be complete.
        # Report module errors separately: this test verifies attachments, not
        # bootstrap-account enrollment, and independently checks its helpers.
        initialized = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['sudo', '-n', 'cloud-init', 'status', '--wait', '--long'],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert initialized.returncode in (0, 1, 2), initialized.stdout + initialized.stderr
        assert 'done' in initialized.stdout, initialized.stdout + initialized.stderr
        if initialized.returncode:
            print('Cloud-init completion diagnostics:\n' + initialized.stdout + initialized.stderr)
        cli('vm', 'attach', str(workspace), '--mirror_home', 'yes')
        attachment = find_attachment_for_vm(
            load_store(scope.store_path), workspace, cfg.vm.name,
        )
        assert attachment is not None and attachment.mode == 'persistent'
        source = '/mnt/aivm-persistent/' + attachment.tag
        # Initial foreground setup also installs the host's managed SSH alias.
        # Complete that approved setup before testing two genuinely warm runs.
        setup = Terminal(
            [sys.executable, '-m', 'aivm', 'ssh', str(workspace), '--yes',
             '--config', str(scope.store_path)], cwd=REPO_ROOT, env=env,
        )
        try:
            setup.ready(timeout=60)
            setup.send('exit\n')
            assert setup.wait(timeout=15) == 0
        finally:
            if setup.returncode is None:
                setup.kill()
        fragments = split_fragment_paths(load_store(scope.store_path), scope.store_path)
        before = {
            path: (path.read_bytes(), path.stat()) for path in fragments.values()
        }
        def manifest_stat():
            result = run_ssh_command(
                user=cfg.vm.user, ip=ip, identity_file=private_key,
                remote=['sudo', '-n', 'python3', '-c', shlex.quote(
                    'import os,json; paths=["/var/lib/aivm/attachments.json",'
                    '"/run/aivm-persistent-mounts","/run/aivm-persistent-mounts/lock"]; '
                    'print(json.dumps([[s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode] '
                    'for s in map(os.stat,paths)]))'
                )], cwd=REPO_ROOT, env=env, timeout=timeout,
            )
            assert result.returncode == 0, result.stderr
            return result.stdout.strip()

        guest_manifest_before = manifest_stat()
        for _ in range(2):
            terminal = Terminal(
                [sys.executable, '-m', 'aivm', 'ssh', str(workspace),
                 '--config', str(scope.store_path)],
                cwd=REPO_ROOT, env=env,
            )
            try:
                terminal.ready(timeout=60)
                terminal.send('exit\n')
                assert terminal.wait(timeout=15) == 0
                assert 'Writing split config store' not in terminal.output
                assert 'OMITTED FROM THE COMMAND ABOVE' not in terminal.output
                assert 'Reconcile guest attachment symlink' not in terminal.output
                assert 'Sync persistent attachment manifest into guest' not in terminal.output
                assert '--dry-run' in terminal.output
                assert 'completed in degraded mode' not in terminal.output
                assert 'Continue?' not in terminal.output
                assert 'Approve this step?' not in terminal.output
                assert 'Check guest replay helper hash' not in terminal.output
                assert 'Check guest replay unit hash' not in terminal.output
                assert 'Inspect guest attachment symlink' not in terminal.output
                assert 'Inspect guest workspace' in terminal.output
                inspections = [line for line in terminal.output.splitlines()
                               if line.startswith('ssh ') and '/usr/local/libexec/aivm/session-inspect' in line]
                assert len(inspections) == 1
                assert '--only-guest-dst' not in terminal.output
            finally:
                if terminal.returncode is None:
                    terminal.kill()
        assert manifest_stat() == guest_manifest_before
        for path, (content, info) in before.items():
            assert path.read_bytes() == content
            current = path.stat()
            assert (current.st_ino, current.st_mtime_ns) == (info.st_ino, info.st_mtime_ns)

        def enter_with_approval(prompt, answer, *, succeeds):
            terminal = Terminal(
                [sys.executable, '-m', 'aivm', 'ssh', str(workspace),
                 '--config', str(scope.store_path)], cwd=REPO_ROOT, env=env,
            )
            try:
                terminal.expect(prompt, timeout=60)
                terminal.send(answer + '\n')
                if succeeds:
                    terminal.ready(timeout=60)
                    terminal.send('exit\n')
                    assert terminal.wait(timeout=15) == 0
                else:
                    assert terminal.wait(timeout=15) != 0
                    assert '__AIVM_SHELL_42__' not in terminal.output
                assert terminal.output.count(prompt) == 1
                assert 'OMITTED FROM THE COMMAND ABOVE' not in terminal.output
            finally:
                if terminal.returncode is None:
                    terminal.kill()

        # Real missing-mount drift must request approval, and declining must
        # not repair it or open a shell. A subsequent approval repairs it.
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['sudo', '-n', 'umount', shlex.quote(attachment.guest_dst)],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode == 0, result.stderr
        enter_with_approval('Continue?', 'n', succeeds=False)
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['mountpoint', '-q', shlex.quote(attachment.guest_dst)],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode in (1, 32)  # mountpoint's not-mounted status varies
        enter_with_approval('Continue?', 'y', succeeds=True)
        # Symlink drift uses its own inspectable, approved helper repair.
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['sudo', '-n', 'rm', '--', '/home/agent/code/workspace'],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode == 0, result.stderr
        enter_with_approval('Approve this step?', 'y', succeeds=True)
        # A missing inspection helper must be installed through the ordinary
        # reviewed deployment path, then inspected again without a restart.
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['sudo', '-n', 'rm', '--', '/usr/local/libexec/aivm/session-inspect'],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode == 0, result.stderr
        enter_with_approval('Approve this step?', 'a', succeeds=True)
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
            command = ['sudo', '-n', '/usr/local/libexec/aivm-persistent-attachment-replay',
                       '--only-guest-dst', target, '--preserve-live-mounts']
            # An existing reference for another token must confer no authority
            # on this target. Run inspection as root, as the service does.
            proof_check = (
                'import runpy, sys; ns=runpy.run_path(sys.argv[1]); '
                'assert not ns["has_pinned_provenance"]('
                '{"guest_dst":sys.argv[2], "shared_root_token":"other-token"})'
            )
            subprocess.run(['sudo', '-n', 'python3', '-c', proof_check,
                            command[2], target], check=True)
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
                assert 'belongs to the requested token but is busy' in result.stderr
                assert mount_info(target)['id'] == before_mount['id']
                assert holder.poll() is None
                assert Path(target, 'sentinel').read_text() == 'original-host-directory'
                print(json.dumps({'source': source_mount, 'workspace': target_mount,
                                  'replay_code': result.returncode, 'diagnostic': result.stderr,
                                  'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
            finally:
                holder.terminate()
                holder.wait(timeout=5)
            recovered = subprocess.run(command, capture_output=True, text=True)
            assert recovered.returncode == 0, recovered.stderr
            repaired_mount = mount_info(target)
            # Linux can immediately reuse a numeric mount ID. Object identity,
            # not a changed ID, proves convergence to the recreated submount.
            assert repaired_mount['maj:min'] != before_mount['maj:min']
            assert (os.stat(source).st_dev, os.stat(source).st_ino) == (
                os.stat(target).st_dev, os.stat(target).st_ino)
            repeated = subprocess.run(command, capture_output=True, text=True)
            assert repeated.returncode == 0, repeated.stderr
            assert mount_info(target)['id'] == repaired_mount['id']
            # Losing proof must fail closed, even with matching inode numbers.
            import hashlib
            key = hashlib.sha256((target + '\0' + Path(source).name).encode()).hexdigest()
            pin = '/run/aivm-persistent-mounts/' + key
            subprocess.run(['sudo', '-n', 'umount', source], check=True)
            assert Path(source, 'sentinel').read_text() == 'original-host-directory'
            assert os.stat(source).st_dev != os.stat(target).st_dev
            assert os.stat(source).st_ino == os.stat(target).st_ino
            subprocess.run(['sudo', '-n', 'umount', pin], check=True)
            unknown = subprocess.run(command, capture_output=True, text=True)
            assert unknown.returncode == 3, unknown.stderr
            assert 'cannot verify' in unknown.stderr
            assert mount_info(target)['id'] == repaired_mount['id']
            # A permissive provenance directory cannot authorize recovery.
            subprocess.run(['sudo', '-n', 'chmod', '0777', '/run/aivm-persistent-mounts'], check=True)
            try:
                unsafe = subprocess.run(command, capture_output=True, text=True)
                assert unsafe.returncode not in (0, 3)
                assert 'unsafe persistent mount provenance directory' in unsafe.stderr
                assert mount_info(target)['id'] == repaired_mount['id']
            finally:
                subprocess.run(['sudo', '-n', 'chmod', '0700', '/run/aivm-persistent-mounts'], check=True)
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
        # Reboot is a normal lifecycle recovery path for old, unproven mounts.
        # Both /run and kernel references must be rebuilt, without hand repair.
        try:
            cli('vm', 'restart')
        except AssertionError:
            # Preserve the original failure and capture late shutdown messages
            # before ordinary E2E teardown removes the disposable guest.
            import time

            console = Terminal(
                ['virsh', '-c', 'qemu:///system', 'console', cfg.vm.name, '--force'],
                cwd=REPO_ROOT, env=env,
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and console._pump(0.2):
                    pass
            finally:
                if console.returncode is None:
                    console.kill()
            raise
        terminal = Terminal(
            [sys.executable, '-m', 'aivm', 'ssh', str(workspace), '--yes',
             '--config', str(scope.store_path)], cwd=REPO_ROOT, env=env,
        )
        try:
            terminal.ready(timeout=90)
            terminal.send('exit\n')
            assert terminal.wait(timeout=15) == 0
            assert 'completed in degraded mode' not in terminal.output
            assert 'OMITTED FROM THE COMMAND ABOVE' not in terminal.output
        finally:
            if terminal.returncode is None:
                terminal.kill()
        verify = textwrap.dedent('''
            import runpy, sys
            from pathlib import Path
            ns = runpy.run_path('/usr/local/libexec/aivm-persistent-attachment-replay')
            record = {'guest_dst': sys.argv[1], 'shared_root_token': sys.argv[2]}
            assert ns['has_pinned_provenance'](record)
            print(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        ''')
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['sudo', '-n', 'python3', '-c', shlex.quote(verify),
                    shlex.quote(attachment.guest_dst), shlex.quote(attachment.tag)],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() != report['boot_id']
        cli('vm', 'detach', str(workspace))
        result = run_ssh_command(
            user=cfg.vm.user, ip=ip, identity_file=private_key,
            remote=['sudo', '-n', 'find', '/run/aivm-persistent-mounts',
                    '-mindepth', '1', '!', '-name', 'lock'],
            cwd=REPO_ROOT, env=env, timeout=timeout,
        )
        assert result.returncode == 0, result.stderr
        assert not result.stdout.strip(), result.stdout
