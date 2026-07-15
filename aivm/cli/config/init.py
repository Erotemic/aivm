"""``aivm config init`` — bootstrap config-store defaults."""

from __future__ import annotations

import getpass
import sys
import tempfile
import tomllib
from copy import deepcopy
from dataclasses import fields
from pathlib import Path
from typing import Any

import kwconf
from loguru import logger

from ...config import AgentVMConfig
from ...config_review import (
    ConfigReviewItem,
    agent_vm_review_items,
    print_config_changes,
    print_config_review,
    render_config_review,
)
from ...config_store import (
    Store,
    load_store,
    parse_store_toml,
    render_store_defaults_toml,
    save_store,
)
from ...detect import auto_defaults
from ...errors import AIVMError
from ...resource_checks import vm_resource_warning_lines
from ...services import cfg_path, maybe_offer_create_ssh_identity
from .._common import _BaseCommand
from .editor import edit_path, select_editor_command

log = logger

_EDITABLE_SECTIONS = (
    'vm',
    'network',
    'firewall',
    'image',
    'provision',
    'paths',
    'virtiofs',
)


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
        return initialize_config_defaults(
            config_opt=args.config,
            yes=bool(args.yes),
            defaults=bool(args.defaults),
            force=bool(args.force),
            standalone_guidance=True,
        )


def initialize_config_defaults(
    *,
    config_opt: str | None,
    yes: bool,
    defaults: bool,
    force: bool,
    standalone_guidance: bool,
) -> int:
    """Initialize defaults, with wording appropriate to the calling workflow."""
    path = cfg_path(config_opt)
    reg = load_store(path)
    cfg = auto_defaults(AgentVMConfig(), project_dir=Path.cwd())
    maybe_offer_create_ssh_identity(
        cfg,
        yes=yes,
        prompt_reason=(
            'Generate a dedicated SSH keypair so aivm can access and '
            'provision VMs without reusing a generic personal key name.'
        ),
    )
    if not yes and not defaults:
        cfg = _review_init_defaults_interactive(cfg, path)
    else:
        _show_init_advisories(cfg)
    if reg.defaults is not None and not force:
        print(
            f'Config defaults already exist in store: {path}',
            file=sys.stderr,
        )
        print('Use --force to overwrite defaults.', file=sys.stderr)
        return 2
    reg.defaults = cfg
    save_store(reg, path)
    print(f'Updated config defaults: {path}')
    if standalone_guidance:
        print(
            'No VM created. Use `aivm vm create` to create one from defaults.'
        )
    return 0


def _init_review_items(
    cfg: AgentVMConfig, path: Path
) -> list[ConfigReviewItem]:
    return agent_vm_review_items(
        cfg,
        path,
        config_store_meaning='config destination',
        vm_name_meaning='default VM name, guest hostname, and SSH alias',
        include_ssh_paths=True,
    )


def _init_default_summary_rows(
    cfg: AgentVMConfig, path: Path
) -> list[tuple[str, str, str]]:
    """Return legacy tuple rows for callers/tests that consume this helper."""
    return [
        (item.key, item.display, item.meaning)
        for item in _init_review_items(cfg, path)
    ]


def _render_init_default_summary(cfg: AgentVMConfig, path: Path) -> str:
    """Render a plain-text review summary before persisting defaults."""
    return render_config_review(
        'Detected defaults for `aivm config init`',
        _init_review_items(cfg, path),
    )


def _print_init_default_summary(cfg: AgentVMConfig, path: Path) -> None:
    """Print the full config-init defaults table exactly once per review."""
    print_config_review(
        'Detected defaults for `aivm config init`',
        _init_review_items(cfg, path),
    )


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


def _show_init_advisories(cfg: AgentVMConfig) -> None:
    _warn_high_resource_defaults(cfg)
    warn_lines = _ssh_key_setup_warning_lines(cfg)
    if warn_lines:
        print('')
        for line in warn_lines:
            print(line)


def _prompt_with_default(prompt: str, default: str) -> str:
    raw = input(f'{prompt} [{default}]: ').strip()
    return raw if raw else default


def _prompt_password_with_default(prompt: str, default: str) -> str:
    state = 'configured; Enter keeps current' if default else 'empty'
    raw = getpass.getpass(f'{prompt} [{state}]: ')
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


def _edit_init_defaults_with_prompts(cfg: AgentVMConfig) -> AgentVMConfig:
    """Walk through the commonly changed init values one at a time."""
    cfg.vm.name = _prompt_with_default('vm.name', cfg.vm.name)
    cfg.vm.user = _prompt_with_default('vm.user', cfg.vm.user)
    cfg.vm.cpus = _prompt_int_with_default('vm.cpus', cfg.vm.cpus)
    cfg.vm.ram_mb = _prompt_int_with_default('vm.ram_mb', cfg.vm.ram_mb)
    cfg.vm.disk_gb = _prompt_int_with_default('vm.disk_gb', cfg.vm.disk_gb)
    cfg.vm.allow_password_login = _prompt_bool_with_default(
        'vm.allow_password_login', cfg.vm.allow_password_login
    )
    if cfg.vm.allow_password_login:
        cfg.vm.password = _prompt_password_with_default(
            'vm.password', cfg.vm.password
        )
    cfg.network.name = _prompt_with_default('network.name', cfg.network.name)
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
    return cfg


def _validate_editor_document(
    text: str, template: AgentVMConfig
) -> AgentVMConfig:
    """Parse an editor document while rejecting misspelled config keys."""
    raw = tomllib.loads(text)
    unexpected_root = sorted(set(raw) - {'defaults'})
    if unexpected_root:
        raise ValueError(
            'only [defaults.*] tables may be edited here; unexpected keys: '
            + ', '.join(unexpected_root)
        )
    defaults_raw = raw.get('defaults')
    if not isinstance(defaults_raw, dict):
        raise ValueError('the edited file must contain [defaults.*] tables')
    unexpected_defaults = sorted(
        set(defaults_raw) - {'verbosity', *_EDITABLE_SECTIONS}
    )
    if unexpected_defaults:
        raise ValueError(
            'unknown defaults sections/keys: ' + ', '.join(unexpected_defaults)
        )
    for section in _EDITABLE_SECTIONS:
        body = defaults_raw.get(section)
        if body is None:
            continue
        if not isinstance(body, dict):
            raise ValueError(f'defaults.{section} must be a TOML table')
        valid = {field.name for field in fields(getattr(template, section))}
        unknown = sorted(set(body) - valid)
        if unknown:
            raise ValueError(
                f'unknown defaults.{section} keys: ' + ', '.join(unknown)
            )
    parsed = parse_store_toml(text)
    if parsed.defaults is None:
        raise ValueError('the edited file did not define defaults')
    return parsed.defaults


def _editor_document(cfg: AgentVMConfig) -> str:
    header = (
        '# Edit the detected AIVM defaults below.\n'
        '# Save and exit to return to AIVM. This temporary file may contain\n'
        '# the guest password in plain text, matching the persisted config format.\n\n'
    )
    return header + render_store_defaults_toml(Store(defaults=deepcopy(cfg)))


def _edit_init_defaults_in_editor(
    cfg: AgentVMConfig,
) -> tuple[AgentVMConfig, bool]:
    """Edit defaults in a temporary TOML file.

    Returns ``(cfg, use_prompts)``. Prompt mode is selected automatically when
    no friendly editor is available, and can also be chosen after validation
    errors.
    """
    command = select_editor_command(fallbacks=('nano', 'micro'), required=False)
    if command is None:
        print(
            'No editor was found via $EDITOR/$VISUAL, nano, or micro; '
            'using prompt-by-prompt editing instead.'
        )
        return cfg, True

    with tempfile.TemporaryDirectory(prefix='aivm-config-init-') as temp_dir:
        edit_file = Path(temp_dir) / 'defaults.toml'
        edit_file.write_text(_editor_document(cfg), encoding='utf-8')
        edit_file.chmod(0o600)
        while True:
            print(f'Opening defaults in {command[0]}.')
            edit_path(edit_file, command)
            try:
                edited = _validate_editor_document(
                    edit_file.read_text(encoding='utf-8'), cfg
                )
            except (OSError, ValueError, tomllib.TOMLDecodeError) as ex:
                print(f'Could not use the edited defaults: {ex}')
                ans = (
                    input(
                        'Reopen editor, use prompts, or discard edits? '
                        '[E/p/d]: '
                    )
                    .strip()
                    .lower()
                )
                if ans in {'p', 'prompt', 'prompts'}:
                    return cfg, True
                if ans in {'d', 'discard', 'n', 'no'}:
                    return cfg, False
                continue
            return edited, False


def _print_init_changes(
    before: AgentVMConfig, after: AgentVMConfig, path: Path
) -> None:
    print('')
    print_config_changes(
        _init_review_items(before, path),
        _init_review_items(after, path),
    )


def _review_init_defaults_interactive(
    cfg: AgentVMConfig, path: Path
) -> AgentVMConfig:
    """Review detected defaults once, then summarize only subsequent changes."""
    if not sys.stdin.isatty():
        raise AIVMError(
            'Config init defaults require confirmation in interactive mode. '
            'Re-run with --yes or --defaults.'
        )
    log.trace('Start interactive default review')
    _print_init_default_summary(cfg, path)
    _show_init_advisories(cfg)
    while True:
        ans = (
            input(
                'Use these values? [Y/e/p/n] (e=editor, p=prompt-by-prompt): '
            )
            .strip()
            .lower()
        )
        if ans in {'', 'y', 'yes'}:
            return cfg
        if ans in {'n', 'no'}:
            raise AIVMError('Aborted by user.')
        if ans in {'p', 'prompt', 'prompts'}:
            before = deepcopy(cfg)
            cfg = _edit_init_defaults_with_prompts(cfg)
            _print_init_changes(before, cfg, path)
            _show_init_advisories(cfg)
            continue
        if ans in {'e', 'edit', 'editor'}:
            before = deepcopy(cfg)
            cfg, use_prompts = _edit_init_defaults_in_editor(cfg)
            if use_prompts:
                cfg = _edit_init_defaults_with_prompts(cfg)
            _print_init_changes(before, cfg, path)
            _show_init_advisories(cfg)
            continue
        print("Please answer 'y', 'e', 'p', or 'n'.")
