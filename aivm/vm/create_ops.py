"""VM create helpers: defaults-driven creation workflow."""

from __future__ import annotations

import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from ..cli._common import (
    _maybe_install_missing_host_deps,
    log,
)
from ..commands import CommandManager
from ..config import AgentVMConfig
from ..firewall import apply_firewall
from ..net import ensure_network
from ..resource_checks import (
    vm_resource_impossible_lines,
    vm_resource_warning_lines,
)
from ..store import (
    find_network,
    find_vm,
    load_store,
    materialize_vm_cfg,
    save_store,
    upsert_network,
    upsert_vm_with_network,
)
from ..vm import create_or_start_vm

if TYPE_CHECKING:
    from ..store import Store


def _render_vm_create_summary(cfg: AgentVMConfig, path: Path) -> str:
    """Render a summary of VM create defaults for interactive review."""
    lines = [
        'Create VM from defaults:',
        f'  config_store: {path}',
        f'  vm.name: {cfg.vm.name}',
        f'  vm.user: {cfg.vm.user}',
        f'  vm.cpus: {cfg.vm.cpus}',
        f'  vm.ram_mb: {cfg.vm.ram_mb}',
        f'  vm.disk_gb: {cfg.vm.disk_gb}',
        f'  network.name: {cfg.network.name}',
        f'  network.subnet_cidr: {cfg.network.subnet_cidr}',
        f'  network.gateway_ip: {cfg.network.gateway_ip}',
        f'  network.dhcp_start: {cfg.network.dhcp_start}',
        f'  network.dhcp_end: {cfg.network.dhcp_end}',
    ]
    return '\n'.join(lines)


def _prompt_with_default(prompt: str, default: str) -> str:
    """Prompt for a string value with a default."""
    raw = input(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


def _prompt_int_with_default(prompt: str, default: int) -> int:
    """Prompt for a positive integer with a default."""
    while True:
        raw = input(f'{prompt} [{default}]: ').strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print('Please enter a valid integer.')
            continue
        if value <= 0:
            print('Please enter a positive integer.')
            continue
        return value


def _prompt_set_created_vm_default(vm_name: str) -> bool:
    """Prompt user whether to set the created VM as the active default."""
    while True:
        ans = (
            input(
                f'Set "{vm_name}" as the active default VM for folder-based commands? [y/N]: '
            )
            .strip()
            .lower()
        )
        if ans in {'', 'n', 'no'}:
            return False
        if ans in {'y', 'yes'}:
            return True
        print("Please answer 'y' or 'n'.")


def _review_vm_create_overrides_interactive(
    cfg: AgentVMConfig, path: Path
) -> AgentVMConfig:
    """Interactively review and optionally edit VM create defaults."""
    if not sys.stdin.isatty():
        raise RuntimeError(
            'VM create defaults require confirmation in interactive mode. '
            'Re-run with --yes.'
        )
    print(_render_vm_create_summary(cfg, path))
    while True:
        ans = input('Use these values? [Y/e/n] (e=edit): ').strip().lower()
        if ans in {'', 'y', 'yes'}:
            return cfg
        if ans in {'n', 'no'}:
            raise RuntimeError('Aborted by user.')
        if ans in {'e', 'edit'}:
            cfg.vm.name = _prompt_with_default('vm.name', cfg.vm.name)
            cfg.vm.user = _prompt_with_default('vm.user', cfg.vm.user)
            cfg.vm.cpus = _prompt_int_with_default('vm.cpus', cfg.vm.cpus)
            cfg.vm.ram_mb = _prompt_int_with_default('vm.ram_mb', cfg.vm.ram_mb)
            cfg.vm.disk_gb = _prompt_int_with_default(
                'vm.disk_gb', cfg.vm.disk_gb
            )
            cfg.network.name = _prompt_with_default(
                'network.name', cfg.network.name
            )
            cfg.network.subnet_cidr = _prompt_with_default(
                'network.subnet_cidr', cfg.network.subnet_cidr
            )
            cfg.network.gateway_ip = _prompt_with_default(
                'network.gateway_ip', cfg.network.gateway_ip
            )
            cfg.network.dhcp_start = _prompt_with_default(
                'network.dhcp_start', cfg.network.dhcp_start
            )
            cfg.network.dhcp_end = _prompt_with_default(
                'network.dhcp_end', cfg.network.dhcp_end
            )
            print('')
            print(_render_vm_create_summary(cfg, path))
            continue
        print("Please answer 'y', 'e', or 'n'.")


def _resolve_create_config(
    cfg_path: Path, vm_override: str | None
) -> tuple[AgentVMConfig, Store]:
    """Resolve the config for VM creation from store defaults or fallback.

    Returns the resolved config and the store (for later persistence).
    """
    reg = load_store(cfg_path)
    if reg.defaults is not None:
        # Work on a copy so per-create overrides (e.g. --vm) never mutate
        # persisted defaults in the registry.
        cfg = deepcopy(reg.defaults).expanded_paths()
    elif reg.vms:
        # Fallback for stores that predate/omit [defaults]: use an existing
        # managed VM definition as the template source for new VM creation.
        template_name = (
            reg.active_vm if find_vm(reg, reg.active_vm) is not None else ''
        )
        if not template_name:
            template_name = sorted(v.name for v in reg.vms)[0]
        cfg = materialize_vm_cfg(reg, template_name).expanded_paths()
        log.warning(
            'No config defaults found; using managed VM {} as create template.',
            template_name,
        )
    else:
        log.error(
            f'No config defaults found in store: {cfg_path}. '
            'Run `aivm config init` first.'
        )
        raise RuntimeError('No config defaults found in store.')

    if vm_override:
        cfg.vm.name = vm_override.strip()

    return cfg, reg


def _initial_share_mapping_for_create(
    cfg: AgentVMConfig,
    cfg_path: Path,
    *,
    host_src: Path | None,
    guest_dst_opt: str = '',
    mode_opt: str = '',
    access_opt: str = '',
) -> tuple[str, str, str]:
    """Return the initial virtiofs mapping for a first attached VM create.

    Folder-oriented entry points such as ``aivm code .`` can bootstrap a VM
    and immediately need the requested folder available in the guest.  Resolve
    that attachment after interactive VM-name edits, then pass the mapping into
    ``virt-install`` so fresh creates do not depend on live virtiofs hotplug.
    """
    if host_src is None:
        return '', '', ''

    from ..attachments.persistent import _persistent_root_host_dir
    from ..attachments.resolve import (
        ATTACHMENT_MODE_PERSISTENT,
        ATTACHMENT_MODE_SHARED,
        ATTACHMENT_MODE_SHARED_ROOT,
        _resolve_attachment,
    )
    from ..attachments.shared_root import (
        SHARED_ROOT_VIRTIOFS_TAG,
        _shared_root_host_dir,
    )
    from ..persistent_replay import PERSISTENT_ROOT_VIRTIOFS_TAG

    attachment = _resolve_attachment(
        cfg,
        cfg_path,
        host_src,
        guest_dst_opt,
        mode_opt,
        access_opt,
    )
    if attachment.mode == ATTACHMENT_MODE_SHARED:
        return attachment.source_dir, attachment.tag, str(attachment.mode)
    if attachment.mode == ATTACHMENT_MODE_SHARED_ROOT:
        return (
            str(_shared_root_host_dir(cfg)),
            SHARED_ROOT_VIRTIOFS_TAG,
            str(attachment.mode),
        )
    if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
        return (
            str(_persistent_root_host_dir(cfg)),
            PERSISTENT_ROOT_VIRTIOFS_TAG,
            str(attachment.mode),
        )
    return '', '', str(attachment.mode)


def _ensure_initial_share_source_for_create(
    cfg: AgentVMConfig,
    *,
    attachment_mode: str,
    dry_run: bool,
) -> None:
    """Create VM-level share export parents needed by initial virtiofs."""
    if attachment_mode == 'persistent':
        from ..attachments.persistent import _ensure_persistent_root_parent_dir

        _ensure_persistent_root_parent_dir(cfg, dry_run=dry_run)
    elif attachment_mode == 'shared-root':
        from ..attachments.shared_root import _ensure_shared_root_parent_dir

        _ensure_shared_root_parent_dir(cfg, dry_run=dry_run)


def create_vm_from_defaults(
    cfg_path: Path,
    *,
    vm_override: str | None = None,
    set_default: bool = False,
    force: bool = False,
    dry_run: bool = False,
    yes: bool = False,
    initial_attachment_host_src: Path | None = None,
    initial_attachment_guest_dst: str = '',
    initial_attachment_mode: str = '',
    initial_attachment_access: str = '',
) -> int:
    """Create a managed VM from config-store defaults and start it.

    This is the main entry point for the VM create workflow. It handles:
    - Loading defaults from the config store
    - Applying --vm override if provided
    - Resource warnings and impossible checks
    - Interactive review/edit flow (unless --yes)
    - Network/firewall setup
    - VM creation
    - Persisting the new VM record
    - Active default selection prompt

    Args:
        cfg_path: Path to the config store.
        vm_override: Optional VM name override from --vm flag.
        set_default: Whether to set the created VM as active default.
        force: Whether to overwrite existing VM entry.
        dry_run: Whether to print actions without running.
        yes: Whether to skip all prompts.
        initial_attachment_host_src: Optional host folder that should be
            present in the initial VM domain definition. Used by fresh
            ``aivm code`` / ``aivm ssh`` bootstrap flows to avoid live
            virtiofs hotplug immediately after first create.
        initial_attachment_guest_dst: Guest path override for the initial
            attachment, if any.
        initial_attachment_mode: Attachment mode override for the initial
            attachment, if any.
        initial_attachment_access: Attachment access override for the initial
            attachment, if any.

    Returns:
        0 on success, 1 on error.
    """
    try:
        cfg, reg = _resolve_create_config(cfg_path, vm_override)
    except RuntimeError as ex:
        if 'No config defaults found in store' in str(ex):
            return 1
        raise ex

    # Apply resource warnings
    for line in vm_resource_warning_lines(cfg):
        log.warning(line)

    # Interactive review unless --yes
    if not yes:
        cfg = _review_vm_create_overrides_interactive(cfg, cfg_path)

    # Check for impossible resources
    problems = vm_resource_impossible_lines(cfg)
    if problems:
        detail = '\n  - '.join(problems)
        raise RuntimeError(
            'Requested VM resources are not feasible on this host right now:\n'
            f'  - {detail}\n'
            'Lower vm.ram_mb / vm.cpus and retry.'
        )

    # Ensure network exists
    net = find_network(reg, cfg.network.name)
    if net is None:
        upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    else:
        cfg.network = type(net.network)(**asdict(net.network))
        cfg.firewall = type(net.firewall)(**asdict(net.firewall))
        cfg.network.name = net.name

    # Check for existing VM
    existing = find_vm(reg, cfg.vm.name)
    if existing is not None and not force:
        log.error(
            f"VM '{cfg.vm.name}' already exists in config store. "
            'Use --force to overwrite. Or use a different name and try again'
        )
        return 1

    (
        initial_share_source_dir,
        initial_share_tag,
        initial_attachment_resolved_mode,
    ) = _initial_share_mapping_for_create(
        cfg,
        cfg_path,
        host_src=initial_attachment_host_src,
        guest_dst_opt=initial_attachment_guest_dst,
        mode_opt=initial_attachment_mode,
        access_opt=initial_attachment_access,
    )

    # Install host dependencies
    _maybe_install_missing_host_deps(yes=yes, dry_run=dry_run)

    # Create VM with CommandManager narration
    mgr = CommandManager.current()
    with mgr.intent(
        f'Create VM {cfg.vm.name}',
        why='Provision the managed network, firewall, and VM definition from config defaults.',
        role='modify',
    ):
        ensure_network(cfg, recreate=False, dry_run=dry_run)
        if cfg.firewall.enabled:
            apply_firewall(cfg, dry_run=dry_run)
        _ensure_initial_share_source_for_create(
            cfg,
            attachment_mode=initial_attachment_resolved_mode,
            dry_run=dry_run,
        )
        create_or_start_vm(
            cfg,
            dry_run=dry_run,
            recreate=bool(force and existing is not None),
            share_source_dir=initial_share_source_dir,
            share_tag=initial_share_tag,
        )

    # Persist the new VM record
    if not dry_run:
        prev_active_vm = reg.active_vm
        upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
        set_active = set_default
        if not set_active and not yes and prev_active_vm != cfg.vm.name:
            set_active = _prompt_set_created_vm_default(cfg.vm.name)
        if not set_active:
            reg.active_vm = prev_active_vm
        save_store(
            reg,
            cfg_path,
            reason=(
                f'Persist created VM record for {cfg.vm.name} and update '
                'the active default selection.'
            ),
        )

    return 0
