"""End-to-end rootless session-runtime lifecycle test.

Runs the full VM lifecycle on the per-user ``qemu:///session`` daemon:
user-owned storage, passt user-mode networking with a forwarded localhost
SSH port, and ``behavior.privilege_mode='sudoless'`` (forced structurally
by session activation) — so a pass proves the whole flow worked with no
root daemon and no privilege escalation at all.

Requirements (deliberately weaker than every other e2e suite):

* the invoking user can open ``/dev/kvm`` (kvm group membership),
* ``passt`` is installed, and
* ``virsh -c qemu:///session version`` works.

No libvirt group membership, managed network, or nftables access needed.
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
    _run_cli,
)

from aivm.config import AgentVMConfig
from aivm.config_store import Store, load_store, save_store, upsert_vm


def _session_runtime_available() -> str | None:
    """Return a skip reason when the rootless prerequisites are missing."""
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        return 'Session e2e needs user access to /dev/kvm (kvm group).'
    if shutil.which('passt') is None:
        return 'Session e2e needs passt installed.'
    probe = subprocess.run(
        ['virsh', '-c', 'qemu:///session', 'version'],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    if probe.returncode != 0:
        return 'Session e2e needs a working qemu:///session daemon.'
    return None


def test_e2e_session_lifecycle(tmp_path: Path) -> None:
    if not _host_context_enabled():
        pytest.skip(
            'Set AIVM_E2E_HOST_CONTEXT=1 (and AIVM_E2E=1) to run host-context e2e tests.'
        )
    skip_reason = _session_runtime_available()
    if skip_reason:
        pytest.skip(skip_reason)

    home, priv, pub = _make_temp_ssh_material(tmp_path)
    env = os.environ.copy()
    env['HOME'] = str(home)

    repo_root = Path(__file__).resolve().parent.parent
    timeout_s = int(os.getenv('AIVM_E2E_TIMEOUT', '2400'))

    cfg_path = tmp_path / 'e2e-session.toml'
    suffix = uuid.uuid4().hex[:6]
    base_dir = tmp_path / 'vmstore'
    state_dir = tmp_path / 'state'

    cfg = AgentVMConfig()
    cfg.vm.name = f'aivm-e2e-se-{suffix}'
    cfg.runtime.mode = 'session'
    cfg.vm.cpus = 1
    cfg.vm.ram_mb = 2048
    cfg.vm.disk_gb = 16
    # Session runtime: no managed network and no nftables firewall.
    cfg.firewall.enabled = False
    cfg.provision.enabled = False
    cfg.paths.base_dir = str(base_dir)
    cfg.paths.state_dir = str(state_dir)
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
    store.behavior.privilege_mode = 'sudoless'
    save_store(store, cfg_path)

    check_res = _run_cli(
        ['host', 'rootless', 'check', '--config', str(cfg_path)],
        cwd=repo_root,
        timeout_s=timeout_s,
        env=env,
        check=False,
    )
    assert '/dev/kvm access' in check_res.stdout

    try:
        _run_cli(
            ['vm', 'up', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )

        # The forward port must have been allocated and persisted.
        port_file = state_dir / cfg.vm.name / 'ssh-forward-port'
        assert port_file.exists(), 'session VM did not persist a forward port'
        ssh_port = int(port_file.read_text(encoding='utf-8').strip())

        wait_res = _run_cli(
            ['vm', 'wait_ip', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        ip = wait_res.stdout.strip().splitlines()[-1]
        assert ip == '127.0.0.1', f'unexpected session endpoint: {ip!r}'

        status_res = _run_cli(
            ['status', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
        )
        assert 'Privilege mode: sudoless' in status_res.stdout
        assert 'Runtime mode: session' in status_res.stdout
        assert f'127.0.0.1:{ssh_port}' in status_res.stdout

        # The domain must live on the session daemon, not the system one.
        session_list = subprocess.run(
            ['virsh', '-c', 'qemu:///session', 'list', '--name'],
            check=True,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        assert cfg.vm.name in session_list.stdout

        # SSH through the forwarded localhost port with a bounded retry:
        # wait_ip returns immediately for session VMs, so the guest may
        # still be booting.
        ssh_cmd = [
            'ssh',
            '-i',
            str(priv),
            '-p',
            str(ssh_port),
            '-o',
            'UserKnownHostsFile=/dev/null',
            '-o',
            'StrictHostKeyChecking=accept-new',
            '-o',
            'ConnectTimeout=5',
            f'{cfg.vm.user}@127.0.0.1',
            'echo session-ok',
        ]
        import time

        deadline = time.time() + 600
        proc = None
        while time.time() < deadline:
            proc = subprocess.run(
                ssh_cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                break
            time.sleep(5)
        assert proc is not None and proc.returncode == 0, (
            proc.stderr if proc else 'ssh never ran'
        )
        assert 'session-ok' in proc.stdout
    finally:
        _run_cli(
            ['vm', 'delete', '--yes', '--config', str(cfg_path)],
            cwd=repo_root,
            timeout_s=timeout_s,
            env=env,
            check=False,
        )
