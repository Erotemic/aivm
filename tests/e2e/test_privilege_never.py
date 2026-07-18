"""End-to-end ``privilege_mode = 'never'`` lifecycle test.

Runs the full network/VM/attach lifecycle with
``behavior.privilege_mode = 'never'``, under which the CommandManager
refuses to execute any sudo command --- so a pass proves the whole flow
worked without privilege escalation.

Requirements beyond the usual e2e host (libvirt/KVM):

* the invoking user is in the ``libvirt`` group with live access
  (``virsh -c qemu:///system list`` works without sudo), and
* ``setfacl`` is available.

Guarded by ``AIVM_E2E=1`` like the other e2e suites.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from aivm.config_store import load_store
from tests.e2e._helpers import (
    REPO_ROOT,
    _host_context_enabled,
    _libvirt_without_sudo_available,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
    apply_shared_image_cache,
    e2e_teardown,
    make_e2e_config,
    run_ssh_command,
    save_e2e_store,
)

pytestmark = pytest.mark.e2e


def test_e2e_privilege_never_lifecycle(tmp_path: Path) -> None:
    if not _host_context_enabled():
        pytest.skip(
            'Set AIVM_E2E_HOST_CONTEXT=1 (and AIVM_E2E=1) to run '
            'host-context e2e tests.'
        )
    if not _libvirt_without_sudo_available():
        pytest.skip(
            'The privilege-never e2e test needs libvirt group membership with live '
            'qemu:///system access.'
        )
    if shutil.which('setfacl') is None:
        pytest.skip('The privilege-never e2e test needs setfacl (acl package).')

    home, priv, pub = _make_temp_ssh_material(tmp_path)
    env = os.environ.copy()
    env['HOME'] = str(home)

    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '2400'))
    # The lifecycle under test never escalates, so the dependency preflight
    # must not require passwordless sudo either.
    _require_e2e_host_dependencies(
        cwd=REPO_ROOT, timeout_s=timeout_s, env=env, sudo=False
    )

    cfg_path = tmp_path / 'e2e-privilege-never.toml'
    base_dir = tmp_path / 'vmstore'
    cfg = make_e2e_config(
        tmp_path,
        priv=priv,
        pub=pub,
        name_prefix='aivm-e2e-sl',
        net_prefix='aivm-e2e-sl-net',
        bridge_prefix='vbs',
        subnet_base='10.251',
        base_dir=str(base_dir),
    )
    # nftables management needs root; the never policy requires the firewall off.
    apply_shared_image_cache(cfg)

    share_dir = tmp_path / 'hostshare'
    share_dir.mkdir()
    (share_dir / 'flag.txt').write_text('privilege-never', encoding='utf-8')

    # Setup establishes host capabilities; choosing the never-sudo policy is
    # the user's act, not setup's, so the test makes that choice explicitly.
    save_e2e_store(cfg_path, cfg, privilege_mode='never')

    # Establish host permission prerequisites through the real setup tool.
    _run_cli(
        [
            'host',
            'permissions',
            'setup',
            '--yes',
            '--base_dir',
            str(base_dir),
            '--config',
            str(cfg_path),
        ],
        cwd=REPO_ROOT,
        timeout_s=timeout_s,
        env=env,
    )
    reg = load_store(cfg_path)
    # Setup must not have touched policy. The mode is the one we wrote, and
    # setup did not invent a defaults section to hold a base_dir override.
    assert reg.behavior.privilege_mode == 'never'
    assert reg.defaults is None
    _run_cli(
        ['host', 'permissions', 'check', '--config', str(cfg_path)],
        cwd=REPO_ROOT,
        timeout_s=timeout_s,
        env=env,
    )

    with e2e_teardown(cfg_path, env=env, timeout_s=timeout_s):
        _run_cli(
            ['host', 'net', 'create', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        _run_cli(
            ['vm', 'up', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        wait_res = _run_cli(
            ['vm', 'wait_ip', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        ip = wait_res.stdout.strip().splitlines()[-1]
        assert ip.count('.') == 3, f'unexpected wait_ip output tail: {ip!r}'

        status_res = _run_cli(
            ['status', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        assert 'Privilege mode: never' in status_res.stdout

        attach_res = _run_cli(
            [
                'attach',
                str(share_dir),
                '--mode',
                'shared',
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        assert 'Attached' in attach_res.stdout

        # Verify the share is usable from inside the guest with a direct
        # ssh command (the CLI `vm ssh` helper is interactive-only).
        proc = run_ssh_command(
            user=cfg.vm.user,
            ip=ip,
            identity_file=priv,
            remote=['cat', str(share_dir / 'flag.txt')],
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert 'privilege-never' in proc.stdout

        _run_cli(
            [
                'detach',
                str(share_dir),
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
