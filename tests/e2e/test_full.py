"""More comprehensive end-to-end tests for local execution.

These exercises go well beyond the minimal "smoke" path in
``test_nested.py`` and are intended for developers running against real
libvirt/KVM hosts (hence guarded by ``AIVM_E2E=1``).  The goal is not to
replace the fast unit tests with mocks, but rather to provide a suite
that puts the actual CLI and VM/network plumbing through its paces when a
capable environment is available.  Shared scaffolding is imported from
:mod:`tests.e2e._helpers`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aivm.config_store import find_attachment_for_vm, load_store
from tests.e2e._helpers import (
    REPO_ROOT,
    _host_context_enabled,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
    apply_shared_image_cache,
    e2e_teardown,
    make_e2e_config,
    require_passwordless_sudo,
    run_ssh_command,
    save_e2e_store,
)

pytestmark = pytest.mark.e2e


def test_e2e_full_cycle(tmp_path: Path) -> None:
    """Full end-to-end exercise.

    This test drives the CLI through:

    * network creation
    * VM creation/start
    * IP discovery
    * status probing
    * SSH connectivity (via "vm ssh")
    * provisioning
    * firewall inspection
    * attaching a host folder
    * session cleanup (vm delete, network destroy)

    The test is fairly slow and requires a host with libvirt/KVM and
    passwordless sudo; it is skipped unless ``AIVM_E2E=1``.
    """

    if not _host_context_enabled():
        pytest.skip(
            'Set AIVM_E2E_HOST_CONTEXT=1 (and AIVM_E2E=1) to run '
            'host-context e2e tests.'
        )

    home, priv, pub = _make_temp_ssh_material(tmp_path)
    env = os.environ.copy()
    env['HOME'] = str(home)

    # Ensure sudo can be used non-interactively.
    require_passwordless_sudo()

    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '2400'))
    _require_e2e_host_dependencies(cwd=REPO_ROOT, timeout_s=timeout_s, env=env)

    cfg_path = tmp_path / 'e2e-full.toml'
    cfg = make_e2e_config(
        tmp_path, priv=priv, pub=pub, firewall_enabled=True
    )
    cfg.firewall.allow_tcp_ports = [22, 2222]
    apply_shared_image_cache(cfg)

    # host folder we will later attach to the VM
    share_dir = tmp_path / 'hostshare'
    share_dir.mkdir()
    (share_dir / 'flag.txt').write_text('e2e', encoding='utf-8')

    save_e2e_store(cfg_path, cfg)

    with e2e_teardown(cfg_path, env=env, timeout_s=timeout_s):
        # network/VM lifecycle
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
        # CLI prints logs before the IP; take last non-empty line as the
        # address.
        ip = wait_res.stdout.strip().splitlines()[-1]
        _run_cli(
            ['host', 'fw', 'status', '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )

        # verify ssh connectivity by running a simple remote command using
        # the generated key pair rather than going through the CLI.
        proc = run_ssh_command(
            user=cfg.vm.user,
            ip=ip,
            identity_file=priv,
            remote=['ls', '/'],
            cwd=REPO_ROOT,
            env=env,
        )
        if proc.returncode != 0:
            raise AssertionError(
                'SSH connectivity check failed:\n'
                f'rc={proc.returncode}\n'
                f'stdout={proc.stdout}\n'
                f'stderr={proc.stderr}\n'
            )

        # exercise the provision command in dry-run mode (we disabled
        # real provisioning above to avoid flakes with apt locks).
        _run_cli(
            [
                'vm',
                'provision',
                '--yes',
                '--dry_run',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )

        # Attach with no explicit mode and verify the new default is persistent.
        _run_cli(
            [
                'vm',
                'attach',
                str(share_dir),
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        reg_after_default_attach = load_store(cfg_path)
        default_att = find_attachment_for_vm(
            reg_after_default_attach, share_dir, cfg.vm.name
        )
        assert default_att is not None
        assert default_att.mode == 'persistent'

        # Explicit mode disagreement on existing attachment should error.
        mismatch_res = _run_cli(
            [
                'vm',
                'attach',
                str(share_dir),
                '--mode',
                'git',
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
            check=False,
        )
        assert mismatch_res.returncode != 0
        assert 'Attachment mode mismatch' in mismatch_res.stdout
        print(
            'Verified expected failure: conflicting attachment mode request '
            'is rejected with a detach+reattach guidance message.'
        )

        # Detach then reattach explicitly in shared-root mode.
        _run_cli(
            [
                'vm',
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
        reg_after_detach = load_store(cfg_path)
        assert (
            find_attachment_for_vm(reg_after_detach, share_dir, cfg.vm.name)
            is None
        )
        _run_cli(
            [
                'vm',
                'attach',
                str(share_dir),
                '--mode',
                'shared-root',
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
        )
        reg_after_shared_root_attach = load_store(cfg_path)
        shared_root_att = find_attachment_for_vm(
            reg_after_shared_root_attach, share_dir, cfg.vm.name
        )
        assert shared_root_att is not None
        assert shared_root_att.mode == 'shared-root'
