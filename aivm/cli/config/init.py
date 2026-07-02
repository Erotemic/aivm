"""``aivm config init`` — bootstrap config-store defaults."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import kwconf
from loguru import logger

from ...config import AgentVMConfig
from ...config_store import load_store, save_store
from ...detect import auto_defaults
from ...resource_checks import vm_resource_warning_lines
from .._common import (
    _BaseCommand,
    _cfg_path,
    _maybe_offer_create_ssh_identity,
)

log = logger


class InitCLI(_BaseCommand):
    """Initialize global config-store defaults (without creating a VM)."""

    force: bool = kwconf.Flag(
        False,
        help='Overwrite existing VM definition if the same name already exists.',
    )
    defaults: bool = kwconf.Flag(
        False,
        help='Accept detected defaults without interactive review.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        reg = load_store(path)
        cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
        _maybe_offer_create_ssh_identity(
            cfg,
            yes=bool(args.yes),
            prompt_reason=(
                'Generate a dedicated SSH keypair so aivm can access and '
                'provision VMs without reusing a generic personal key name.'
            ),
        )
        if not bool(args.yes) and not bool(args.defaults):
            cfg = _review_init_defaults_interactive(cfg, path)
        else:
            _warn_high_resource_defaults(cfg)
            warn_lines = _ssh_key_setup_warning_lines(cfg)
            for line in warn_lines:
                print(line)
        if reg.defaults is not None and not args.force:
            print(
                f'Config defaults already exist in store: {path}',
                file=sys.stderr,
            )
            print('Use --force to overwrite defaults.', file=sys.stderr)
            return 2
        reg.defaults = cfg
        save_store(reg, path)
        print(f'Updated config defaults: {path}')
        print(
            'No VM created. Use `aivm vm create` to create one from defaults.'
        )
        return 0


def _format_bool(value: bool) -> str:
    """Return a stable human-readable boolean for review prompts."""
    return 'true' if bool(value) else 'false'


def _format_secret(value: str) -> str:
    """Avoid echoing configured passwords in review summaries."""
    return '(configured)' if str(value or '') else '(empty)'


def _init_default_summary_rows(
    cfg: AgentVMConfig, path: Path
) -> list[tuple[str, str, str]]:
    """Return rows for the config-init defaults review summary."""
    password_note = (
        'used for console/SSH password auth when vm.allow_password_login=true'
    )
    return [
        ('config_store', str(path), 'config destination'),
        (
            'vm.name',
            cfg.vm.name,
            'default VM name, guest hostname, and SSH alias',
        ),
        ('vm.user', cfg.vm.user, 'guest login user'),
        ('vm.cpus', str(cfg.vm.cpus), 'virtual CPUs'),
        ('vm.ram_mb', str(cfg.vm.ram_mb), 'RAM in MiB'),
        ('vm.disk_gb', str(cfg.vm.disk_gb), 'root disk size'),
        (
            'vm.allow_password_login',
            _format_bool(cfg.vm.allow_password_login),
            'enables password login on console and SSH',
        ),
        ('vm.password', _format_secret(cfg.vm.password), password_note),
        ('network.name', cfg.network.name, 'libvirt network'),
        ('network.subnet_cidr', cfg.network.subnet_cidr, 'guest subnet'),
        ('network.gateway_ip', cfg.network.gateway_ip, 'guest gateway'),
        ('network.dhcp_start', cfg.network.dhcp_start, 'DHCP range start'),
        ('network.dhcp_end', cfg.network.dhcp_end, 'DHCP range end'),
        (
            'paths.ssh_identity_file',
            cfg.paths.ssh_identity_file or '(empty)',
            'private key used by aivm',
        ),
        (
            'paths.ssh_pubkey_path',
            cfg.paths.ssh_pubkey_path or '(empty)',
            'public key injected into the guest',
        ),
    ]


def _render_init_default_summary(cfg: AgentVMConfig, path: Path) -> str:
    """Render a plain-text review summary before persisting defaults."""
    lines = ['Detected defaults for `aivm config init`:']
    for key, value, note in _init_default_summary_rows(cfg, path):
        if note:
            lines.append(f'  {key}: {value}  # {note}')
        else:
            lines.append(f'  {key}: {value}')
    return '\n'.join(lines)


def _print_init_default_summary(cfg: AgentVMConfig, path: Path) -> None:
    """Print the config-init review summary, using Rich when available."""
    try:
        from rich.console import Console
        from rich.table import Table
    except Exception:  # pragma: no cover - exercised only without rich
        print(_render_init_default_summary(cfg, path))
        return

    table = Table(title='Detected defaults for `aivm config init`')
    table.add_column('Setting', style='bold cyan', no_wrap=True)
    table.add_column('Value', overflow='fold')
    table.add_column('Meaning', style='dim', overflow='fold')
    for key, value, note in _init_default_summary_rows(cfg, path):
        table.add_row(key, value, note)
    Console().print(table)


def _ssh_key_setup_warning_lines(cfg: AgentVMConfig) -> list[str]:
    """Return advisory warnings when SSH key paths are missing/unusable."""
    ident = (cfg.paths.ssh_identity_file or '').strip()
    pub = (cfg.paths.ssh_pubkey_path or '').strip()
    ident_ok = bool(ident) and Path(ident).expanduser().exists()
    pub_ok = bool(pub) and Path(pub).expanduser().exists()
    if ident_ok and pub_ok:
        return []
    log.warning(
        'SSH identity/public key not detected for config init '
        '(identity_file={}, pubkey_file={}). '
        'VM SSH/provisioning may fail until keys are configured.',
        ident or '(empty)',
        pub or '(empty)',
    )
    return [
        '⚠️ SSH keypair not detected for this VM config.',
        '  `aivm` expects an SSH identity + public key for VM access/provisioning.',
        '  Quick setup:',
        '    ssh-keygen -t ed25519 -f ~/.ssh/id_aivm_ed25519 -N ""',
        '  (Advisory only: config init will continue.)',
    ]


def _warn_high_resource_defaults(cfg: AgentVMConfig) -> None:
    """Log host-resource warnings for detected default VM sizing."""
    for line in vm_resource_warning_lines(cfg):
        log.warning('Config-init default resource warning: {}', line)


def _prompt_with_default(prompt: str, default: str) -> str:
    raw = input(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


def _prompt_int_with_default(prompt: str, default: int) -> int:
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


def _review_init_defaults_interactive(
    cfg: AgentVMConfig, path: Path
) -> AgentVMConfig:
    """Interactive review/edit loop for ``aivm config init`` defaults."""
    if not sys.stdin.isatty():
        raise RuntimeError(
            'Config init defaults require confirmation in interactive mode. '
            'Re-run with --yes or --defaults.'
        )
    log.trace('Start interactive default review')
    _print_init_default_summary(cfg, path)
    _warn_high_resource_defaults(cfg)
    warn_lines = _ssh_key_setup_warning_lines(cfg)
    if warn_lines:
        print('')
        for line in warn_lines:
            print(line)
    while True:
        ans = input('Use these values? [Y/e/n] (e=edit): ').strip().lower()
        if ans in {'', 'y', 'yes'}:
            return cfg
        if ans in {'n', 'no'}:
            raise RuntimeError('Aborted by user.')
        if ans in {'e', 'edit'}:
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
                cfg.vm.password = _prompt_with_default(
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
            cfg.paths.ssh_identity_file = _prompt_with_default(
                'paths.ssh_identity_file', cfg.paths.ssh_identity_file or ''
            )
            cfg.paths.ssh_pubkey_path = _prompt_with_default(
                'paths.ssh_pubkey_path', cfg.paths.ssh_pubkey_path or ''
            )
            print('')
            _print_init_default_summary(cfg, path)
            _warn_high_resource_defaults(cfg)
            warn_lines = _ssh_key_setup_warning_lines(cfg)
            if warn_lines:
                print('')
                for line in warn_lines:
                    print(line)
            continue
        print("Please answer 'y', 'e', or 'n'.")
