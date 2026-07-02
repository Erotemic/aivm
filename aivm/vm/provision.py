"""Post-boot guest provisioning orchestration."""

from __future__ import annotations

import shlex

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..runtime import require_ssh_identity, ssh_base_args
from .connectivity import get_ip_cached, ssh_port_for, wait_for_ip, wait_for_ssh
from .guest_tools import (
    _guest_ensure_code_script,
    _guest_ensure_rust_script,
    _guest_ensure_uv_script,
    _guest_tool_code_enabled,
    _guest_tool_rust_enabled,
    _guest_tool_uv_enabled,
)

log = logger

def provision(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    log.debug('Provisioning VM with developer tools')
    if not cfg.provision.enabled:
        log.info('Provision disabled; skipping.')
        return
    cfg = cfg.expanded_paths()
    if dry_run:
        ip = '0.0.0.0'
    else:
        ip = get_ip_cached(cfg) or wait_for_ip(
            cfg, timeout_s=360, dry_run=False
        )
    ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    pkgs = list(cfg.provision.packages)
    docker_pkgs = (
        ['docker.io', 'docker-compose-v2']
        if cfg.provision.install_docker
        else []
    )
    install_pkgs = docker_pkgs + pkgs
    if _guest_tool_rust_enabled(cfg):
        # Keep the rustup-managed toolchain usable for native crate builds.
        for pkg in ['build-essential', 'pkg-config', 'libssl-dev']:
            if pkg not in install_pkgs:
                install_pkgs.append(pkg)
    install_cmd = ':'
    if install_pkgs:
        quoted_pkgs = ' '.join(shlex.quote(pkg) for pkg in install_pkgs)
        install_cmd = (
            'sudo DEBIAN_FRONTEND=noninteractive '
            f'apt-get install -y {quoted_pkgs}'
        )
    remote_parts = [
        'set -euo pipefail',
        'sudo apt-get update -y',
        'sudo apt-get install -y software-properties-common >/dev/null 2>&1 || true',
        'sudo add-apt-repository -y universe >/dev/null 2>&1 || true',
        'sudo apt-get update -y',
        install_cmd,
    ]
    if _guest_tool_uv_enabled(cfg):
        remote_parts.append(_guest_ensure_uv_script(cfg, ensure_transport=False))
    if _guest_tool_rust_enabled(cfg):
        remote_parts.append(_guest_ensure_rust_script(cfg, ensure_transport=False))
    if _guest_tool_code_enabled(cfg):
        remote_parts.append(_guest_ensure_code_script(cfg, ensure_transport=False))
    remote = '\n'.join(remote_parts)
    cmd = [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
            port=ssh_port_for(cfg),
        ),
        f'{cfg.vm.user}@{ip}',
        remote,
    ]
    if dry_run:
        log.info('DRYRUN: {}', ' '.join(cmd))
        return
    wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
    log.info('Running provisioning apt installs (showing progress)')
    CommandManager.current().run(cmd, sudo=False, check=True, capture=False)
    log.info('Provisioning complete.')
