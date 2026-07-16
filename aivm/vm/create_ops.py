"""VM create helpers: defaults-driven creation workflow."""

from __future__ import annotations

import getpass
import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger as log

from ..attachments.persistent import (
    _ensure_persistent_root_parent_dir,
    _persistent_root_host_dir,
)
from ..attachments.resolve import (
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED,
    ATTACHMENT_MODE_SHARED_ROOT,
    _resolve_attachment,
)
from ..attachments.shared_root import (
    SHARED_ROOT_VIRTIOFS_TAG,
    _ensure_shared_root_parent_dir,
    _shared_root_host_dir,
)
from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_review import (
    ConfigReviewItem,
    agent_vm_review_items,
    print_config_changes,
    print_config_review,
    render_config_review,
)
from ..config_store import (
    find_network,
    find_vm,
    load_store,
    materialize_vm_cfg,
    save_store,
    upsert_network,
    upsert_vm_with_network,
)
from ..errors import AIVMError
from ..firewall import apply_firewall
from ..net import ensure_network
from ..persistent_replay import PERSISTENT_ROOT_VIRTIOFS_TAG
from ..resource_checks import (
    vm_resource_impossible_lines,
    vm_resource_warning_lines,
)
from ..services import maybe_install_missing_host_deps
from ..vm import create_or_start_vm

if TYPE_CHECKING:
    from ..config_store import Store


def _vm_create_review_items(
    cfg: AgentVMConfig, path: Path
) -> list[ConfigReviewItem]:
    return agent_vm_review_items(
        cfg,
        path,
        config_store_meaning='config source',
        vm_name_meaning='VM name, guest hostname, and SSH alias',
        include_ssh_paths=False,
    )


def _vm_create_summary_rows(
    cfg: AgentVMConfig, path: Path
) -> list[tuple[str, str, str]]:
    """Return legacy tuple rows for callers/tests that consume this helper."""
    return [
        (item.key, item.display, item.meaning)
        for item in _vm_create_review_items(cfg, path)
    ]


def _render_vm_create_summary(cfg: AgentVMConfig, path: Path) -> str:
    """Render a plain-text summary of VM create defaults for tests/fallback."""
    return render_config_review(
        'Create VM from defaults', _vm_create_review_items(cfg, path)
    )


def _print_vm_create_summary(cfg: AgentVMConfig, path: Path) -> None:
    """Print the VM-create review summary, using Rich when available."""
    print_config_review(
        'Create VM from defaults', _vm_create_review_items(cfg, path)
    )


def _prompt_with_default(prompt: str, default: str) -> str:
    """Prompt for a string value with a default."""
    raw = input(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


def _prompt_password_with_default(prompt: str, default: str) -> str:
    """Prompt without echoing the password already present in plain config."""
    state = 'configured; Enter keeps current' if default else 'empty'
    raw = getpass.getpass(f'{prompt} [{state}]: ')
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


def _prompt_bool_with_default(prompt: str, default: bool) -> bool:
    """Prompt for a boolean value with a default."""
    default_label = 'Y/n' if default else 'y/N'
    while True:
        raw = input(f'{prompt} [{default_label}]: ').strip().lower()
        if not raw:
            return bool(default)
        if raw in {'1', 'true', 't', 'y', 'yes', 'on'}:
            return True
        if raw in {'0', 'false', 'f', 'n', 'no', 'off'}:
            return False
        print("Please answer 'y' or 'n'.")


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
        raise AIVMError(
            'VM create defaults require confirmation in interactive mode. '
            'Re-run with --yes.'
        )
    _print_vm_create_summary(cfg, path)
    while True:
        ans = input('Use these values? [Y/e/n] (e=edit): ').strip().lower()
        if ans in {'', 'y', 'yes'}:
            return cfg
        if ans in {'n', 'no'}:
            raise AIVMError('Aborted by user.')
        if ans in {'e', 'edit'}:
            before = deepcopy(cfg)
            cfg.vm.name = _prompt_with_default('vm.name', cfg.vm.name)
            cfg.vm.user = _prompt_with_default('vm.user', cfg.vm.user)
            cfg.vm.cpus = _prompt_int_with_default('vm.cpus', cfg.vm.cpus)
            cfg.vm.ram_mb = _prompt_int_with_default('vm.ram_mb', cfg.vm.ram_mb)
            cfg.vm.disk_gb = _prompt_int_with_default(
                'vm.disk_gb', cfg.vm.disk_gb
            )
            cfg.vm.allow_password_login = _prompt_bool_with_default(
                'vm.allow_password_login', cfg.vm.allow_password_login
            )
            if cfg.vm.allow_password_login:
                cfg.vm.password = _prompt_password_with_default(
                    'vm.password', cfg.vm.password
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
            print_config_changes(
                _vm_create_review_items(before, path),
                _vm_create_review_items(cfg, path),
            )
            continue
        print("Please answer 'y', 'e', or 'n'.")


def _confirm_reviewed_vm_create(cfg: AgentVMConfig) -> AgentVMConfig:
    """Confirm creation without repeating a configuration reviewed moments ago."""
    while True:
        ans = (
            input(
                f'Create VM `{cfg.vm.name}` from the configuration reviewed above? '
                '[Y/n]: '
            )
            .strip()
            .lower()
        )
        if ans in {'', 'y', 'yes'}:
            return cfg
        if ans in {'n', 'no'}:
            raise AIVMError('Aborted by user.')
        print("Please answer 'y' or 'n'.")


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
        raise AIVMError('No config defaults found in store.')

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
        _ensure_persistent_root_parent_dir(cfg, dry_run=dry_run)
    elif attachment_mode == 'shared-root':
        _ensure_shared_root_parent_dir(cfg, dry_run=dry_run)


def create_vm_from_defaults(
    cfg_path: Path,
    *,
    vm_override: str | None = None,
    set_default: bool = False,
    force: bool = False,
    dry_run: bool = False,
    yes: bool = False,
    configuration_reviewed: bool = False,
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
        configuration_reviewed: Whether this exact config was already reviewed
            by the interactive config-init flow. In that case, ask only for a
            concise create confirmation instead of printing the full table
            again.
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
        if configuration_reviewed:
            cfg = _confirm_reviewed_vm_create(cfg)
        else:
            cfg = _review_vm_create_overrides_interactive(cfg, cfg_path)

    # Check for impossible resources
    problems = vm_resource_impossible_lines(cfg)
    if problems:
        detail = '\n  - '.join(problems)
        raise AIVMError(
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
    maybe_install_missing_host_deps(yes=yes, dry_run=dry_run)

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
