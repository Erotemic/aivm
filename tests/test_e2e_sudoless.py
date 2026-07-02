"""End-to-end sudoless lifecycle test.

Runs the full network/VM/attach lifecycle with
``behavior.privilege_mode = 'sudoless'``, under which the CommandManager
refuses to execute any sudo command — so a pass proves the whole flow
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
import subprocess
import uuid
from pathlib import Path

import pytest

from test_e2e_nested import (
    _default_shared_image_path,
    _ensure_user_cached_image,
    _host_context_enabled,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
)

from aivm.config import AgentVMConfig
from aivm.config_store import Store, load_store, save_store, upsert_vm


def _sudoless_libvirt_available() -> bool:
    probe = subprocess.run(
        ['virsh', '-c', 'qemu:///system', 'list', '--name'],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return probe.returncode == 0


def test_e2e_sudoless_lifecycle(tmp_path: Path) -> None:
    if not _host_context_enabled():
        pytest.skip(
            'Set AIVM_E2E_HOST_CONTEXT=1 (and AIVM_E2E=1) to run host-context e2e tests.'
        )
    if not _sudoless_libvirt_available():
        pytest.skip(
            'Sudoless e2e needs libvirt group membership with live '
            'qemu:///system access.'
        )
    if shutil.which('setfacl') is None:
        pytest.skip('Sudoless e2e needs setfacl (acl package).')

    home, priv, pub = _make_temp_ssh_material(tmp_path)
    env = os.environ.copy()
    env['HOME'] = str(home)

    repo_root = Path(__file__).resolve().parent.parent
    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '2400'))
    _require_e2e_host_dependencies(cwd=repo_root, timeout_s=timeout_s, env=env)

    cfg_path = tmp_path / 'e2e-sudoless.toml'
    suffix = uuid.uuid4().hex[:6]
    subnet_octet = 100 + (int(suffix[:2], 16) % 100)
    base_dir = tmp_path / 'vmstore'

    cfg = AgentVMConfig()
    cfg.vm.name = f'aivm-e2e-sl-{suffix}'
    cfg.vm.cpus = 1
    cfg.vm.ram_mb = 2048
    cfg.vm.disk_gb = 16
    cfg.network.name = f'aivm-e2e-sl-net-{suffix}'
    cfg.network.bridge = f'vbs{suffix}'
    cfg.network.subnet_cidr = f'10.251.{subnet_octet}.0/24'
    cfg.network.gateway_ip = f'10.251.{subnet_octet}.1'
    cfg.network.dhcp_start = f'10.251.{subnet_octet}.100'
    cfg.network.dhcp_end = f'10.251.{subnet_octet}.200'
    # nftables management needs root; the sudoless story is "firewall off".
    cfg.firewall.enabled = False
    cfg.provision.enabled = False
    cfg.paths.base_dir = str(base_dir)
    cfg.paths.state_dir = str(tmp_path / 'state')
    cfg.paths.ssh_identity_file = str(priv)
    cfg.paths.ssh_pubkey_path = str(pub)

    if os.getenv('AIVM_E2E_INDEPENDENT_IMAGE') != '1':
        user_home = Path(os.environ.get('HOME', '~')).expanduser()
        default_shared = _default_shared_image_path(user_home)
        shared_img = Path(
            os.getenv('AIVM_E2E_SHARED_IMAGE', str(default_shared))
        ).expanduser()
        _ensure_user_cached_image(shared_img)
        cfg.image.ubuntu_img_url = f'file://{shared_img}'

    share_dir = tmp_path / 'hostshare'
    share_dir.mkdir()
    (share_dir / 'flag.txt').write_text('sudoless', encoding='utf-8')

    store = Store()
    upsert_vm(store, cfg)
    save_store(store, cfg_path)

    # Establish sudoless prerequisites through the real setup tool, then
    # verify the whole store runs in sudoless mode from here on.
    _run_cli(
        [
            'host',
            'sudoless',
            'setup',
            '--yes',
            '--base_dir',
            str(base_dir),
            '--config',
            str(cfg_path),
        ],
        cwd=repo_root,
        timeout_s=timeout_s,
        env=env,
    )
    reg = load_store(cfg_path)
    assert reg.behavior.privilege_mode == 'sudoless'
    _run_cli(
        ['host', 'sudoless', 'check', '--config', str(cfg_path)],
        cwd=repo_root,
        timeout_s=timeout_s,
        env=env,
    )

    try:
        _run_cli(
            ['host', 'net', 'create', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        _run_cli(
            ['vm', 'up', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        wait_res = _run_cli(
            ['vm', 'wait_ip', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        ip = wait_res.stdout.strip().splitlines()[-1]
        assert ip.count('.') == 3, f'unexpected wait_ip output tail: {ip!r}'

        status_res = _run_cli(
            ['status', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        assert 'Privilege mode: sudoless' in status_res.stdout

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
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        assert 'Attached' in attach_res.stdout

        # Verify the share is usable from inside the guest with a direct
        # ssh command (the CLI `vm ssh` helper is interactive-only).
        ssh_cmd = [
            'ssh',
            '-i',
            str(priv),
            '-o',
            'UserKnownHostsFile=/dev/null',
            '-o',
            'StrictHostKeyChecking=accept-new',
            f'{cfg.vm.user}@{ip}',
            'cat',
            str(share_dir / 'flag.txt'),
        ]
        proc = subprocess.run(
            ssh_cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert 'sudoless' in proc.stdout

        _run_cli(
            [
                'detach',
                str(share_dir),
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
    finally:
        _run_cli(
            ['vm', 'delete', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
            check=False,
        )
        _run_cli(
            ['host', 'net', 'destroy', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
            check=False,
        )
