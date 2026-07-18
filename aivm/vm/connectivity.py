"""VM connectivity helpers for IP discovery, SSH config, and readiness."""

from __future__ import annotations

import textwrap
import time

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..errors import AIVMError
from ..privilege import virsh_needs_sudo
from ..runtime import (
    require_ssh_identity,
    ssh_base_args,
    virsh_cmd,
)
from ..util import ensure_dir
from .paths import _paths

log = logger

def _mac_for_vm(cfg: AgentVMConfig) -> str:
    mgr = CommandManager.current()
    if mgr.current_plan() is None:
        with mgr.step(
            'Inspect VM network interfaces',
            why=(
                'Read the VM interface list so later IP discovery can match '
                'DHCP leases against the guest MAC address.'
            ),
            approval_scope=f'vm-network-interfaces:{cfg.vm.name}',
        ):
            res = mgr.submit(
                virsh_cmd('domiflist', cfg.vm.name),
                sudo=virsh_needs_sudo(),
                role='read',
                check=False,
                capture=True,
                eager=True,
                summary=f'Inspect network interfaces for VM {cfg.vm.name}',
            ).result()
    else:
        res = mgr.run(
            virsh_cmd('domiflist', cfg.vm.name),
            sudo=virsh_needs_sudo(),
            role='read',
            check=False,
            capture=True,
            summary=f'Inspect network interfaces for VM {cfg.vm.name}',
        )
    for line in res.stdout.splitlines():
        if (
            'network' in line.lower()
            and 'interface' not in line.lower()
            and '---' not in line
        ):
            parts = line.split()
            if parts:
                return parts[-1].strip()
    return ''

def get_ip_cached(cfg: AgentVMConfig) -> str | None:
    p = _paths(cfg, dry_run=False)
    ip_file = p['ip_file']
    if ip_file.exists():
        return ip_file.read_text(encoding='utf-8').strip() or None
    return None

def wait_for_ip(
    cfg: AgentVMConfig, *, timeout_s: int = 360, dry_run: bool = False
) -> str:
    log.debug('Waiting for VM IP via DHCP lease')
    p = _paths(cfg, dry_run=dry_run)
    ip_file = p['ip_file']
    if dry_run:
        log.info('DRYRUN: wait for IP and write {}', ip_file)
        return '0.0.0.0'
    ensure_dir(p['state_dir'])
    mac = _mac_for_vm(cfg)
    cached_ip = get_ip_cached(cfg)
    ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    if not mac:
        log.warning(
            'Could not determine VM MAC; DHCP lease lookup may fail. Falling back to domifaddr.'
        )
    if cached_ip:
        log.info(
            'Using cached IP as fallback while waiting for lease discovery: {}',
            cached_ip,
        )
    deadline = time.time() + timeout_s
    start = time.time()
    next_status_at = start
    last_state = 'unknown'
    last_lease_count = 0
    last_domif_count = 0
    warned_about_possible_hang = False
    mgr = CommandManager.current()
    with mgr.intent(
        f'Wait for IP for {cfg.vm.name}',
        why='Poll libvirt lease/interface state until the guest IP is discoverable.',
        role='read',
    ):
        while time.time() < deadline:
            ip = ''
            lease_text = ''
            domif_text = ''
            if mac:
                lease_text = mgr.run(
                    virsh_cmd('net-dhcp-leases', cfg.network.name),
                    sudo=virsh_needs_sudo(),
                    role='read',
                    check=False,
                    capture=True,
                    summary=f'Inspect DHCP leases for network {cfg.network.name}',
                ).stdout
                for line in lease_text.splitlines():
                    if mac.lower() in line.lower():
                        parts = line.split()
                        for part in parts:
                            if '/' in part and '.' in part:
                                ip = part.split('/')[0]
                                break
                    if ip:
                        break
            if not ip:
                domif_text = mgr.run(
                    virsh_cmd('domifaddr', cfg.vm.name),
                    sudo=virsh_needs_sudo(),
                    role='read',
                    check=False,
                    capture=True,
                    summary=f'Inspect interface addresses for VM {cfg.vm.name}',
                ).stdout
                for line in domif_text.splitlines():
                    if 'ipv4' in line.lower():
                        parts = line.split()
                        for part in parts:
                            if '/' in part and '.' in part:
                                ip = part.split('/')[0]
                                break
                    if ip:
                        break
            if ip:
                log.info('Writing VM IP cache to {}', ip_file)
                ip_file.write_text(ip + '\n', encoding='utf-8')
                log.info('VM IP: {} (saved to {})', ip, ip_file)
                return ip
            if cached_ip:
                ssh_probe = mgr.run(
                    [
                        'ssh',
                        *ssh_base_args(
                            ident,
                            batch_mode=True,
                            connect_timeout=3,
                            strict_host_key_checking='accept-new',
                        ),
                        f'{cfg.vm.user}@{cached_ip}',
                        'true',
                    ],
                    sudo=False,
                    check=False,
                    capture=True,
                )
                if ssh_probe.code == 0:
                    log.info('Writing VM IP cache to {}', ip_file)
                    ip_file.write_text(cached_ip + '\n', encoding='utf-8')
                    log.info(
                        'VM reachable via cached IP fallback: {} (saved to {})',
                        cached_ip,
                        ip_file,
                    )
                    return cached_ip
            now = time.time()
            if now >= next_status_at:
                st = mgr.run(
                    virsh_cmd('domstate', cfg.vm.name),
                    sudo=virsh_needs_sudo(),
                    role='read',
                    check=False,
                    capture=True,
                    summary=f'Inspect runtime state for VM {cfg.vm.name}',
                ).stdout.strip()
                if st:
                    last_state = st
                lease_lines = [
                    line
                    for line in lease_text.splitlines()
                    if line.strip() and not set(line.strip()) <= {'-'}
                ]
                last_lease_count = max(0, len(lease_lines) - 1)
                domif_lines = [
                    line
                    for line in domif_text.splitlines()
                    if line.strip() and not set(line.strip()) <= {'-'}
                ]
                last_domif_count = max(0, len(domif_lines) - 1)
                elapsed = max(0, int(now - start))
                log.info(
                    'Waiting for VM network: vm={} elapsed={}s state={} leases_seen={} domifaddr_ipv4_rows={} mac={}',
                    cfg.vm.name,
                    elapsed,
                    last_state,
                    last_lease_count,
                    last_domif_count,
                    mac or 'unknown',
                )
                if elapsed >= 45 and not warned_about_possible_hang:
                    warned_about_possible_hang = True
                    log.warning(
                        'VM network still not ready after {}s. VM may still be booting, or hung. '
                        'Quick checks: `virsh console {}` and `aivm status --sudo --detail`.',
                        elapsed,
                        cfg.vm.name,
                    )
                if 'running' not in last_state.lower():
                    raise RuntimeError(
                        f'VM {cfg.vm.name} is not running while waiting for IP (state={last_state!r}).'
                    )
                next_status_at = now + 10
            time.sleep(2)
    raise TimeoutError(
        'Timed out waiting for VM IP '
        f'(vm={cfg.vm.name}, state={last_state!r}, leases_seen={last_lease_count}, domifaddr_ipv4_rows={last_domif_count}, cached_ip={cached_ip or "none"}). '
        f'Try: sudo virsh net-dhcp-leases {cfg.network.name}'
    )

def ssh_config(cfg: AgentVMConfig) -> str:
    cfg = cfg.expanded_paths()
    ident = cfg.paths.ssh_identity_file or '~/.ssh/id_ed25519'
    host = cfg.vm.name
    ip = get_ip_cached(cfg) or 'VM_IP_UNKNOWN'
    return f"""Host {host}
  HostName {ip}
  User {cfg.vm.user}
  IdentityFile {ident}
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
"""

def _is_ssh_host_key_mismatch(stderr: str) -> bool:
    text = stderr.lower()
    patterns = [
        'remote host identification has changed',
        'host key verification failed',
        'offending ',
        'offending ecdsa key in ',
        'offending ed25519 key in ',
        'offending rsa key in ',
        'it is also possible that a host key has just been changed',
        'someone could be eavesdropping on you right now',
    ]
    return any(pattern in text for pattern in patterns)

def _ssh_host_key_mismatch_message(cfg: AgentVMConfig, ip: str) -> str:
    return textwrap.dedent(
        f"""
        SSH host key mismatch while waiting for VM {cfg.vm.name} at {ip}.
        The VM appears to have booted and obtained an IP, but SSH is failing
        because the cached host key for this address no longer matches.
        Try removing the stale key and retrying:
          ssh-keygen -f ~/.ssh/known_hosts -R {ip}
        """
    ).strip()

def wait_for_ssh(
    cfg: AgentVMConfig,
    ip: str,
    *,
    timeout_s: int = 300,
    dry_run: bool = False,
) -> None:
    cfg = cfg.expanded_paths()
    ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    if dry_run:
        log.info('DRYRUN: wait for SSH on {}@{}', cfg.vm.user, ip)
        return
    deadline = time.time() + timeout_s
    # SSH can come up slowly on first boot, especially under nested
    # virtualization where cloud-init and key generation compete for limited
    # CPU. Keep each probe bounded, but allow enough time for a real login
    # handshake to finish before declaring the guest unreachable.
    probe_timeout_s = 30
    last_stderr = ''
    while time.time() < deadline:
        cmd = [
            'ssh',
            *ssh_base_args(
                ident,
                batch_mode=True,
                connect_timeout=3,
                strict_host_key_checking='accept-new',
            ),
            f'{cfg.vm.user}@{ip}',
            'true',
        ]
        res = CommandManager.current().run(
            cmd,
            sudo=False,
            check=False,
            capture=True,
            timeout=probe_timeout_s,
        )
        if res.code == 0:
            log.info('SSH is ready on {}', ip)
            return
        last_stderr = (res.stderr or '').strip()
        if _is_ssh_host_key_mismatch(last_stderr):
            raise AIVMError(_ssh_host_key_mismatch_message(cfg, ip))
        time.sleep(2)
    detail = f' Last SSH error: {last_stderr}' if last_stderr else ''
    raise TimeoutError(f'Timed out waiting for SSH on {ip}.{detail}')
