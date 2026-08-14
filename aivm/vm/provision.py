"""Post-boot guest provisioning orchestration."""

from __future__ import annotations

import copy
import shlex
from collections.abc import Sequence

from loguru import logger

from aivm.config_scopes import guest_transport_from_effective_cfg

from ..commands import CommandManager, Elided
from ..config import AgentVMConfig
from ..runtime import require_ssh_identity, ssh_base_args
from .connectivity import get_ip_cached, wait_for_ip, wait_for_ssh
from .guest_tools import GUEST_TOOL_REGISTRY

log = logger


def provision_guest_requirements(
    cfg: AgentVMConfig,
    ip: str,
    *,
    packages: Sequence[str] = (),
    tools: Sequence[str] = (),
    dry_run: bool = False,
) -> None:
    """Install only the named guest requirements for an active workflow.

    This is intentionally narrower than :func:`provision`: a foreground
    feature such as ``aivm code --tunnel`` should be able to opt into the
    tools it actually needs without rerunning Docker setup, unrelated tool
    installers, or the full baseline provisioning pass.
    """
    package_names = tuple(dict.fromkeys(str(name) for name in packages if name))
    tool_names = tuple(dict.fromkeys(str(name) for name in tools if name))
    if not package_names and not tool_names:
        return

    effective = cfg.expanded_paths()
    selected = copy.deepcopy(effective)
    for name in tool_names:
        resolved = GUEST_TOOL_REGISTRY.resolve(selected.tools, name)
        if not resolved.enabled:
            selected.tools.set(name, resolved.definition.enable_default)
    context = guest_transport_from_effective_cfg(effective)
    ident = require_ssh_identity(context.ssh_identity_file)

    remote_parts = ['set -euo pipefail', 'sudo apt-get update -y']
    if package_names:
        quoted_packages = ' '.join(shlex.quote(name) for name in package_names)
        remote_parts.append(
            'sudo DEBIAN_FRONTEND=noninteractive '
            f'apt-get install -y {quoted_packages}'
        )
    for name in tool_names:
        tool = GUEST_TOOL_REGISTRY.resolve(selected.tools, name)
        remote_parts.append(tool.install_script(selected, ensure_transport=True))

    remote = '\n'.join(remote_parts)
    labels = [*package_names, *tool_names]
    detail = ', '.join(labels)
    cmd = [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
        ),
        context.ssh_target(ip),
        Elided(remote, f'guest prerequisite install payload for {detail}'),
    ]
    if dry_run:
        log.info(
            'DRYRUN: would install guest prerequisites {} on {}.',
            detail,
            effective.vm.name,
        )
        return

    mgr = CommandManager.current()
    with mgr.step(
        f'Install guest prerequisites: {detail}',
        why=(
            'Install only the commands required by the requested foreground '
            'workflow; leave unrelated guest tools and services untouched.'
        ),
        approval_scope=f'guest-prerequisites:{effective.vm.name}:{detail}',
    ):
        mgr.run(
            cmd,
            sudo=False,
            role='modify',
            check=True,
            capture=False,
            summary=f'Install guest prerequisites: {detail}',
            detail=f'vm={effective.vm.name} requirements={detail}',
        )


def provision(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    log.debug('Provisioning VM with developer tools')
    if not cfg.provision.enabled:
        log.info('Provision disabled; skipping.')
        return
    cfg = cfg.expanded_paths()
    context = guest_transport_from_effective_cfg(cfg)
    if dry_run:
        ip = '0.0.0.0'
    else:
        ip = get_ip_cached(cfg) or wait_for_ip(
            cfg, timeout_s=360, dry_run=False
        )
    ident = require_ssh_identity(context.ssh_identity_file)
    pkgs = list(cfg.provision.packages)
    docker_pkgs = (
        ['docker.io', 'docker-compose-v2']
        if cfg.provision.install_docker
        else []
    )
    install_pkgs = docker_pkgs + pkgs
    for pkg in GUEST_TOOL_REGISTRY.required_packages(cfg.tools):
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
    remote_parts.extend(
        GUEST_TOOL_REGISTRY.install_scripts(cfg, ensure_transport=False)
    )
    remote = '\n'.join(remote_parts)
    cmd = [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
        ),
        context.ssh_target(ip),
        remote,
    ]
    if dry_run:
        log.info('DRYRUN: {}', ' '.join(cmd))
        return
    wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
    log.info('Running provisioning apt installs (showing progress)')
    CommandManager.current().run(cmd, sudo=False, check=True, capture=False)
    log.info('Provisioning complete.')
