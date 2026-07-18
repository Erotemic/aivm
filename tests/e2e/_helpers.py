"""Shared scaffolding for the opt-in end-to-end suite.

The end-to-end tests each drive the real ``aivm`` CLI (as ``python -m
aivm``) against a libvirt/KVM host through a series of subprocesses.  The
plumbing they need --- generating throwaway SSH material, invoking the CLI
with a captured/streamed transcript, caching the base image, building a
per-run isolated ``AgentVMConfig``, and tearing the VM/network back down
--- is identical across the four suites.  It lives here so no test module
has to double as a helper library for its siblings.

``REPO_ROOT`` is the anchor every suite relies on: the CLI subprocesses run
with ``cwd=REPO_ROOT`` so ``python -m aivm`` resolves against this checkout.
It is asserted at test time (see ``conftest.py``) so a future move of this
file can never silently point it at the wrong directory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Iterator, Mapping, Sequence
from urllib.parse import urlparse

import pytest

from aivm.config import (
    DEFAULT_UBUNTU_NOBLE_IMG_URL,
    SUPPORTED_IMAGE_SHA256,
    AgentVMConfig,
)
from aivm.config_store import Store, save_store, upsert_vm

# tests/e2e/_helpers.py -> tests/e2e -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Opt-in gates
# ---------------------------------------------------------------------------


def _host_context_enabled() -> bool:
    raw = os.getenv(
        'AIVM_E2E_HOST_CONTEXT',
        '1' if os.getenv('AIVM_E2E') == '1' else '0',
    )
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def _bootstrap_context_enabled() -> bool:
    raw = os.getenv('AIVM_E2E_BOOTSTRAP', '0')
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def _libvirt_without_sudo_available() -> bool:
    probe = subprocess.run(
        ['virsh', '-c', 'qemu:///system', 'list', '--name'],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return probe.returncode == 0


def require_passwordless_sudo() -> None:
    """Skip the current test unless ``sudo -n true`` succeeds.

    Unattended e2e needs non-interactive sudo.  Every suite treats a
    missing capability as a *skip* (a machine simply not set up for
    privileged e2e), never a hard failure.
    """
    probe = subprocess.run(
        ['sudo', '-n', 'true'], check=False, capture_output=True, text=True
    )
    if probe.returncode != 0:
        pytest.skip('E2E requires passwordless sudo (sudo -n true).')


# ---------------------------------------------------------------------------
# SSH material
# ---------------------------------------------------------------------------


def _make_temp_ssh_material(tmp_path: Path) -> tuple[Path, Path, Path]:
    ssh_keygen = shutil.which('ssh-keygen')
    if not ssh_keygen:
        pytest.skip('ssh-keygen is required for e2e key generation.')

    home = tmp_path / 'home'
    ssh_dir = home / '.ssh'
    ssh_dir.mkdir(parents=True, exist_ok=True)
    priv = ssh_dir / 'id_ed25519'
    pub = ssh_dir / 'id_ed25519.pub'
    cfg = ssh_dir / 'config'
    proc = subprocess.run(
        [ssh_keygen, '-q', '-t', 'ed25519', '-N', '', '-f', str(priv)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f'Failed to generate temp ssh keypair.\n'
            f'--- stdout ---\n{proc.stdout}\n'
            f'--- stderr ---\n{proc.stderr}\n'
        )
    cfg.write_text(
        (
            'Host *\n'
            f'  IdentityFile {priv}\n'
            '  IdentitiesOnly yes\n'
            '  StrictHostKeyChecking accept-new\n'
        ),
        encoding='utf-8',
    )
    return home, priv, pub


# ---------------------------------------------------------------------------
# CLI / SSH invocation
# ---------------------------------------------------------------------------


def _run_cli(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: int,
    env: dict[str, str],
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    # Centralize CLI invocation behavior for e2e so failures always include a
    # command line, return code, and recent output tail.
    cmd = [sys.executable, '-m', 'aivm', *argv]
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
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
            # Preserve real-time output when pytest is run with -s.
            sys.stdout.write(line)
            sys.stdout.flush()
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        tail = ''.join(out_lines[-200:])
        raise AssertionError(
            f'CLI timed out after {timeout_s}s: {" ".join(cmd)}\n'
            f'--- output tail ---\n{tail}\n'
        )
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
    stdout = ''.join(out_lines)
    completed = subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr='')
    if check and completed.returncode != 0:
        raise AssertionError(
            f'CLI failed: {" ".join(cmd)}\n'
            f'rc={completed.returncode}\n'
            f'--- output ---\n{completed.stdout}\n'
        )
    return completed


def run_ssh_command(
    *,
    user: str,
    ip: str,
    identity_file: Path,
    remote: Sequence[str],
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one non-interactive command in the guest over direct ``ssh``.

    The CLI ``vm ssh`` helper always launches an interactive shell and
    does not accept an arbitrary command, so automated connectivity
    checks bypass it and talk to ``ssh`` with the generated key pair.
    """
    cmd = [
        'ssh',
        '-i',
        str(identity_file),
        '-o',
        'UserKnownHostsFile=/dev/null',
        '-o',
        'StrictHostKeyChecking=accept-new',
        f'{user}@{ip}',
        *remote,
    ]
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _require_e2e_host_dependencies(
    *, cwd: Path, timeout_s: int, env: dict[str, str], sudo: bool = True
) -> None:
    # Fail fast with actionable guidance before spending minutes on VM setup.
    # ``sudo=False`` is for the privilege-never suite: its lifecycle never escalates,
    # so its preflight must not demand passwordless sudo either.
    argv = ['host', 'doctor'] + (['--sudo'] if sudo else [])
    doctor = _run_cli(
        argv,
        cwd=cwd,
        timeout_s=timeout_s,
        env=env,
        check=False,
    )
    if doctor.returncode != 0:
        raise AssertionError(
            'E2E host dependencies are not ready. '
            f'`aivm {" ".join(argv)}` failed.\n'
            'Install missing dependencies (e.g. `aivm host install_deps --yes`) '
            'and rerun.\n'
            f'--- output ---\n{doctor.stdout}\n'
        )


# ---------------------------------------------------------------------------
# Base image cache
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    hasher = sha256()
    with path.open('rb') as file:
        while True:
            block = file.read(1024 * 1024)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


def _default_shared_image_path(user_home: Path) -> Path:
    # Keep the filename version-aware so new pinned cloud image releases can
    # coexist in cache without clobbering old files.
    parsed = urlparse(DEFAULT_UBUNTU_NOBLE_IMG_URL)
    basename = Path(parsed.path).name
    parts = [p for p in parsed.path.split('/') if p]
    version = parts[-2] if len(parts) >= 2 else 'unknown'
    name = f'{Path(basename).stem}-{version}{Path(basename).suffix}'
    return user_home / '.cache' / 'aivm' / 'e2e' / name


def _ensure_user_cached_image(shared_img: Path) -> None:
    # Maintain a single verified local copy per test host to avoid repeated
    # network downloads across e2e runs.
    expected = SUPPORTED_IMAGE_SHA256[DEFAULT_UBUNTU_NOBLE_IMG_URL]
    if shared_img.exists():
        actual = _sha256_file(shared_img)
        if actual == expected:
            print(f'Using cached base image: {shared_img}')
            return
        print(
            'Cached base image checksum mismatch; removing stale cache '
            f'and redownloading: {shared_img}'
        )
        shared_img.unlink()
    shared_img.parent.mkdir(parents=True, exist_ok=True)
    tmp_img = Path(str(shared_img) + '.part')
    if tmp_img.exists():
        tmp_img.unlink()
    print(f'Caching base image once for E2E: {shared_img}')
    proc = subprocess.run(
        [
            'curl',
            '-L',
            '--fail',
            '--progress-bar',
            '-o',
            str(tmp_img),
            DEFAULT_UBUNTU_NOBLE_IMG_URL,
        ],
        check=False,
        capture_output=False,
        text=True,
    )
    if proc.returncode != 0:
        tmp_img.unlink(missing_ok=True)
        raise AssertionError(
            f'Failed to populate shared e2e image cache at: {shared_img}'
        )
    tmp_img.replace(shared_img)
    actual = _sha256_file(shared_img)
    if actual != expected:
        shared_img.unlink(missing_ok=True)
        raise AssertionError(
            'E2E shared image cache has unexpected checksum after download.\n'
            f'Path: {shared_img}\n'
            f'Expected: {expected}\n'
            f'Actual:   {actual}'
        )


def apply_shared_image_cache(cfg: AgentVMConfig) -> None:
    """Point ``cfg`` at a locally cached base image unless opted out.

    Sourcing the pinned cloud image from a single verified local copy
    avoids re-downloading it on every e2e run.  Set
    ``AIVM_E2E_INDEPENDENT_IMAGE=1`` to skip the cache and let the CLI
    fetch the image itself.
    """
    if os.getenv('AIVM_E2E_INDEPENDENT_IMAGE') == '1':
        return
    user_home = Path(os.environ.get('HOME', '~')).expanduser()
    default_shared = _default_shared_image_path(user_home)
    shared_img = Path(
        os.getenv('AIVM_E2E_SHARED_IMAGE', str(default_shared))
    ).expanduser()
    _ensure_user_cached_image(shared_img)
    cfg.image.ubuntu_img_url = f'file://{shared_img}'


# ---------------------------------------------------------------------------
# Config / store construction
# ---------------------------------------------------------------------------


def make_e2e_config(
    tmp_path: Path,
    *,
    priv: Path,
    pub: Path,
    name_prefix: str = 'aivm-e2e',
    net_prefix: str = 'aivm-e2e-net',
    bridge_prefix: str = 'vbr',
    subnet_base: str = '10.250',
    cpus: int = 1,
    ram_mb: int = 2048,
    disk_gb: int = 16,
    base_dir: str = '/var/lib/libvirt/aivm-e2e',
    firewall_enabled: bool = False,
) -> AgentVMConfig:
    """Build a per-run isolated ``AgentVMConfig`` for an e2e suite.

    A fresh random ``suffix`` (and a derived subnet octet) name the VM,
    network, and bridge uniquely so retries and concurrent runs never
    collide with stale libvirt resources.  Provisioning is always
    disabled --- e2e drives provisioning explicitly where it wants to,
    and leaving it on invites intermittent apt-lock flakes.
    """
    suffix = uuid.uuid4().hex[:6]
    subnet_octet = 100 + (int(suffix[:2], 16) % 100)

    cfg = AgentVMConfig()
    cfg.vm.name = f'{name_prefix}-{suffix}'
    cfg.vm.cpus = cpus
    cfg.vm.ram_mb = ram_mb
    cfg.vm.disk_gb = disk_gb
    cfg.network.name = f'{net_prefix}-{suffix}'
    cfg.network.bridge = f'{bridge_prefix}{suffix}'
    cfg.network.subnet_cidr = f'{subnet_base}.{subnet_octet}.0/24'
    cfg.network.gateway_ip = f'{subnet_base}.{subnet_octet}.1'
    cfg.network.dhcp_start = f'{subnet_base}.{subnet_octet}.100'
    cfg.network.dhcp_end = f'{subnet_base}.{subnet_octet}.200'
    cfg.firewall.enabled = firewall_enabled
    cfg.provision.enabled = False
    cfg.paths.base_dir = base_dir
    cfg.paths.state_dir = str(tmp_path / 'state')
    cfg.paths.ssh_identity_file = str(priv)
    cfg.paths.ssh_pubkey_path = str(pub)
    return cfg


def save_e2e_store(
    cfg_path: Path,
    cfg: AgentVMConfig,
    *,
    privilege_mode: str | None = None,
) -> None:
    """Persist a single-VM store holding ``cfg`` to ``cfg_path``.

    ``privilege_mode`` is written onto ``behavior`` before the VM is
    upserted; the privilege-never suite uses it to record the user's ``'never'``
    choice as an explicit act rather than a side effect of setup.
    """
    store = Store()
    if privilege_mode is not None:
        store.behavior.privilege_mode = privilege_mode
    upsert_vm(store, cfg)
    save_store(store, cfg_path)


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------


@contextmanager
def e2e_teardown(
    cfg_path: Path,
    *,
    env: dict[str, str],
    timeout_s: int,
    extra_args: Sequence[str] = (),
) -> Iterator[None]:
    """Run the suite body, then always delete the VM and destroy the net.

    Teardown is best-effort (``check=False``): a run that failed partway
    should still tear down whatever it managed to create.  ``extra_args``
    threads shared CLI flags (e.g. ``--verbose``) into both commands.
    """
    try:
        yield
    finally:
        _run_cli(
            ['vm', 'delete', *extra_args, '--yes', '--config', str(cfg_path)],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
            check=False,
        )
        _run_cli(
            [
                'host',
                'net',
                'destroy',
                *extra_args,
                '--yes',
                '--config',
                str(cfg_path),
            ],
            cwd=REPO_ROOT,
            timeout_s=timeout_s,
            env=env,
            check=False,
        )
