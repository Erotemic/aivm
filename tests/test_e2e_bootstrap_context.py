"""Opt-in bootstrap-context e2e test.

This test validates a two-level flow:

1) current host context creates a fresh outer VM
2) inside that outer VM, host-context e2e tests are executed

It is intentionally opt-in because runtime is long and environment requirements
are strict.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
import uuid
from pathlib import Path

import pytest

from test_e2e_nested import (
    _default_shared_image_path,
    _ensure_user_cached_image,
    _make_temp_ssh_material,
    _require_e2e_host_dependencies,
    _run_cli,
)

from aivm.config import AgentVMConfig
from aivm.store import Store, save_store, upsert_vm


def _bootstrap_context_enabled() -> bool:
    raw = os.getenv('AIVM_E2E_BOOTSTRAP', '0')
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def _run_remote_script(
    *,
    user: str,
    ip: str,
    identity_file: Path,
    env: dict[str, str],
    timeout_s: int,
    script: str,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        'ssh',
        '-i',
        str(identity_file),
        '-o',
        'UserKnownHostsFile=/dev/null',
        '-o',
        'StrictHostKeyChecking=accept-new',
        f'{user}@{ip}',
        'bash',
        '-lc',
        script,
    ]
    proc = subprocess.Popen(
        cmd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out_lines: list[str] = []
    try:
        assert proc.stdout is not None
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            out_lines.append(line)
            print(line, end='')
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        tail = ''.join(out_lines[-200:])
        raise AssertionError(
            f'Remote bootstrap script timed out after {timeout_s}s.\n'
            f'--- output tail ---\n{tail}\n'
        )
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
    stdout = ''.join(out_lines)
    completed = subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr='')
    if completed.returncode != 0:
        raise AssertionError(
            'Remote bootstrap script failed.\n'
            f'rc={completed.returncode}\n'
            f'--- output ---\n{completed.stdout}\n'
        )
    return completed


def test_e2e_bootstrap_context(tmp_path: Path) -> None:
    if not _bootstrap_context_enabled():
        pytest.skip('Set AIVM_E2E_BOOTSTRAP=1 to run bootstrap-context e2e.')
    if os.getenv('AIVM_E2E') != '1':
        pytest.skip('Set AIVM_E2E=1 to run bootstrap-context e2e.')

    home, priv, pub = _make_temp_ssh_material(tmp_path)
    env = os.environ.copy()
    env['HOME'] = str(home)

    sudo_probe = subprocess.run(
        ['sudo', '-n', 'true'], check=False, capture_output=True, text=True
    )
    if sudo_probe.returncode != 0:
        pytest.skip('Bootstrap e2e requires passwordless sudo (sudo -n true).')

    repo_root = Path(__file__).resolve().parent.parent
    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '3600'))
    _require_e2e_host_dependencies(cwd=repo_root, timeout_s=timeout_s, env=env)

    cfg_path = tmp_path / 'e2e-bootstrap.toml'
    suffix = uuid.uuid4().hex[:6]
    subnet_octet = 100 + (int(suffix[:2], 16) % 100)
    cfg = AgentVMConfig()
    cfg.vm.name = f'aivm-e2e-bootstrap-{suffix}'
    cfg.vm.cpus = 2
    cfg.vm.ram_mb = 4096
    cfg.vm.disk_gb = 24
    cfg.network.name = f'aivm-e2e-boot-net-{suffix}'
    cfg.network.bridge = f'vbrb{suffix[:4]}'
    cfg.network.subnet_cidr = f'10.251.{subnet_octet}.0/24'
    cfg.network.gateway_ip = f'10.251.{subnet_octet}.1'
    cfg.network.dhcp_start = f'10.251.{subnet_octet}.100'
    cfg.network.dhcp_end = f'10.251.{subnet_octet}.200'
    cfg.firewall.enabled = False
    cfg.provision.enabled = False
    cfg.paths.base_dir = '/var/lib/libvirt/aivm-e2e-bootstrap'
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

    store = Store()
    upsert_vm(store, cfg)
    save_store(store, cfg_path)

    guest_repo_path = '/workspace/aivm'
    inner_timeout_s = int(os.getenv('AIVM_E2E_BOOTSTRAP_TIMEOUT', '7200'))
    remote_script = textwrap.dedent(
        f"""\
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        if [ ! -e /dev/kvm ]; then
          echo "ERROR: /dev/kvm missing in bootstrap guest. Nested virtualization unavailable."
          exit 1
        fi
        sudo apt-get update -y
        sudo apt-get install -y \\
          qemu-kvm qemu-system-common \\
          libvirt-daemon-system libvirt-clients \\
          virtinst cloud-image-utils qemu-utils \\
          nftables curl openssh-client iproute2 \\
          python3 python3-venv python3-pip
        sudo systemctl enable --now libvirtd
        cd {guest_repo_path}
        python3 -m pip install -e '.[tests]'
        AIVM_E2E=1 AIVM_E2E_HOST_CONTEXT=1 pytest \\
          tests/test_e2e_nested.py tests/test_e2e_full.py -s -v
        """
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
        _run_cli(
            [
                'vm',
                'attach',
                str(repo_root),
                '--guest_dst',
                guest_repo_path,
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        _run_remote_script(
            user=cfg.vm.user,
            ip=ip,
            identity_file=priv,
            env=env,
            timeout_s=inner_timeout_s,
            script=remote_script,
        )
    finally:
        _run_cli(
            ['vm', 'destroy', '--yes', '--config', str(cfg_path)],
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

