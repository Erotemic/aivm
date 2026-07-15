"""Reusable presentation helpers for reviewing VM configuration values."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import AgentVMConfig


@dataclass(frozen=True)
class ConfigReviewItem:
    """One configuration value shown in a review or change summary."""

    key: str
    value: object
    display: str
    meaning: str
    sensitive: bool = False


def _format_bool(value: bool) -> str:
    return 'true' if bool(value) else 'false'


def _format_secret(value: str) -> str:
    return '(configured)' if str(value or '') else '(empty)'


def agent_vm_review_items(
    cfg: AgentVMConfig,
    path: Path,
    *,
    config_store_meaning: str,
    vm_name_meaning: str,
    include_ssh_paths: bool,
) -> list[ConfigReviewItem]:
    """Build the common review model used by config-init and VM-create UI."""
    password_note = (
        'used for console/SSH password auth when vm.allow_password_login=true'
    )
    items = [
        ConfigReviewItem(
            'config_store', str(path), str(path), config_store_meaning
        ),
        ConfigReviewItem('vm.name', cfg.vm.name, cfg.vm.name, vm_name_meaning),
        ConfigReviewItem(
            'vm.user', cfg.vm.user, cfg.vm.user, 'guest login user'
        ),
        ConfigReviewItem(
            'vm.cpus', cfg.vm.cpus, str(cfg.vm.cpus), 'virtual CPUs'
        ),
        ConfigReviewItem(
            'vm.ram_mb', cfg.vm.ram_mb, str(cfg.vm.ram_mb), 'RAM in MiB'
        ),
        ConfigReviewItem(
            'vm.disk_gb',
            cfg.vm.disk_gb,
            str(cfg.vm.disk_gb),
            'root disk size',
        ),
        ConfigReviewItem(
            'vm.allow_password_login',
            cfg.vm.allow_password_login,
            _format_bool(cfg.vm.allow_password_login),
            'enables password login on console and SSH',
        ),
        ConfigReviewItem(
            'vm.password',
            cfg.vm.password,
            _format_secret(cfg.vm.password),
            password_note,
            sensitive=True,
        ),
        ConfigReviewItem(
            'network.name',
            cfg.network.name,
            cfg.network.name,
            'libvirt network',
        ),
        ConfigReviewItem(
            'network.subnet_cidr',
            cfg.network.subnet_cidr,
            cfg.network.subnet_cidr,
            'guest subnet',
        ),
        ConfigReviewItem(
            'network.gateway_ip',
            cfg.network.gateway_ip,
            cfg.network.gateway_ip,
            'guest gateway',
        ),
        ConfigReviewItem(
            'network.dhcp_start',
            cfg.network.dhcp_start,
            cfg.network.dhcp_start,
            'DHCP range start',
        ),
        ConfigReviewItem(
            'network.dhcp_end',
            cfg.network.dhcp_end,
            cfg.network.dhcp_end,
            'DHCP range end',
        ),
    ]
    if include_ssh_paths:
        items.extend(
            [
                ConfigReviewItem(
                    'paths.ssh_identity_file',
                    cfg.paths.ssh_identity_file or '',
                    cfg.paths.ssh_identity_file or '(empty)',
                    'private key used by aivm',
                ),
                ConfigReviewItem(
                    'paths.ssh_pubkey_path',
                    cfg.paths.ssh_pubkey_path or '',
                    cfg.paths.ssh_pubkey_path or '(empty)',
                    'public key injected into the guest',
                ),
            ]
        )
    return items


def render_config_review(title: str, items: Iterable[ConfigReviewItem]) -> str:
    """Render a plain-text review for tests and terminals without Rich."""
    lines = [f'{title}:']
    for item in items:
        suffix = f'  # {item.meaning}' if item.meaning else ''
        lines.append(f'  {item.key}: {item.display}{suffix}')
    return '\n'.join(lines)


def print_config_review(title: str, items: list[ConfigReviewItem]) -> None:
    """Print a full configuration review table."""
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:  # pragma: no cover - exercised only without rich
        print(render_config_review(title, items))
        return

    table = Table(title=title)
    table.add_column('Setting', style='bold cyan', no_wrap=True)
    table.add_column('Value', overflow='fold')
    table.add_column('Meaning', style='dim', overflow='fold')
    for item in items:
        table.add_row(item.key, item.display, item.meaning)
    Console().print(table)


def _change_display(item: ConfigReviewItem, *, current: bool) -> str:
    if item.sensitive:
        if current and item.value:
            return '(updated; configured)'
        return item.display
    return item.display


def print_config_changes(
    before: list[ConfigReviewItem],
    after: list[ConfigReviewItem],
    *,
    title: str = 'Updated values',
) -> bool:
    """Print only changed values, returning whether anything changed."""
    before_by_key = {item.key: item for item in before}
    changed = [
        item
        for item in after
        if item.key in before_by_key
        and before_by_key[item.key].value != item.value
    ]
    if not changed:
        print('No values changed.')
        return False

    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:  # pragma: no cover - exercised only without rich
        print(f'{title}:')
        for item in changed:
            old = before_by_key[item.key]
            print(
                f'  {item.key}: {_change_display(old, current=False)} '
                f'-> {_change_display(item, current=True)}'
            )
        return True

    table = Table(title=title)
    table.add_column('Setting', style='bold cyan', no_wrap=True)
    table.add_column('Previous', style='dim', overflow='fold')
    table.add_column('Current', overflow='fold')
    for item in changed:
        old = before_by_key[item.key]
        table.add_row(
            item.key,
            _change_display(old, current=False),
            _change_display(item, current=True),
        )
    Console().print(table)
    return True
