"""Application-level services shared by the CLI and domain orchestration.

This module is the home for config/session preparation that is not CLI
argument parsing: resolving which VM a command targets, loading and
persisting its config, binding the process to the configured runtime,
offering to create SSH identities, and gating on missing host
dependencies.  It sits above ``config_store``/``commands`` and below
``cli``/``vm``/``attachments`` so all three can depend on it without any
package importing upward from the CLI layer.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from loguru import logger as log

from .commands import CommandManager
from .config import AgentVMConfig
from .config_store import (
    find_attachments,
    find_vm,
    load_store,
    materialize_vm_cfg,
    save_store,
    store_path,
    upsert_network,
    upsert_vm_with_network,
)
from .detect import detect_ssh_identity
from .errors import AIVMError
from .host import check_commands, host_is_debian_like, install_deps_debian
from .util import which


def cfg_path(p: str | None) -> Path:
    return Path(p).expanduser().resolve() if p else store_path().resolve()


def hydrate_ssh_identity_defaults(cfg: AgentVMConfig) -> bool:
    changed = False
    have_ident = bool((cfg.paths.ssh_identity_file or '').strip())
    have_pub = bool((cfg.paths.ssh_pubkey_path or '').strip())
    if have_ident and have_pub:
        return False
    ident, pub = detect_ssh_identity()
    if not have_ident and ident:
        cfg.paths.ssh_identity_file = ident
        changed = True
    if not have_pub and pub:
        cfg.paths.ssh_pubkey_path = pub
        changed = True
    if changed:
        log.debug(
            'Hydrated runtime defaults for vm={} ssh_identity_file={} ssh_pubkey_path={}',
            cfg.vm.name,
            cfg.paths.ssh_identity_file or '(empty)',
            cfg.paths.ssh_pubkey_path or '(empty)',
        )
    return changed


def default_aivm_identity_paths() -> tuple[Path, Path]:
    priv = Path.home() / '.ssh' / 'id_aivm_ed25519'
    return priv, Path(str(priv) + '.pub')


def maybe_offer_create_ssh_identity(
    cfg: AgentVMConfig,
    *,
    yes: bool,
    prompt_reason: str,
) -> bool:
    """Offer to create a dedicated aivm SSH keypair when none is configured."""
    ident = (cfg.paths.ssh_identity_file or '').strip()
    pub = (cfg.paths.ssh_pubkey_path or '').strip()
    ident_path = Path(ident).expanduser() if ident else None
    pub_path = Path(pub).expanduser() if pub else None
    ident_ok = ident_path is not None and ident_path.exists()
    pub_ok = pub_path is not None and pub_path.exists()
    if ident_ok and pub_ok:
        return False

    # Do not override a partially configured custom path automatically.
    if ident or pub:
        return False

    default_priv, default_pub = default_aivm_identity_paths()
    if default_priv.exists() and default_pub.exists():
        cfg.paths.ssh_identity_file = str(default_priv)
        cfg.paths.ssh_pubkey_path = str(default_pub)
        return True

    if which('ssh-keygen') is None:
        log.warning(
            'ssh-keygen not found; cannot create dedicated aivm SSH identity.'
        )
        return False

    if yes:
        approved = True
    else:
        if not sys.stdin.isatty():
            return False
        ans = (
            input(
                'No SSH identity/public key was detected for aivm VM access. '
                f'Create a dedicated keypair now at {default_priv}? [Y/n]: '
            )
            .strip()
            .lower()
        )
        approved = ans in {'', 'y', 'yes'}
    if not approved:
        return False

    mgr = CommandManager.current()
    comment = f'aivm@{os.uname().nodename}'
    with mgr.intent(
        'Create SSH identity',
        why='A VM SSH keypair is required for guest access and provisioning.',
        role='modify',
    ):
        with mgr.step(
            'Create dedicated aivm SSH keypair',
            why=prompt_reason,
            approval_scope='aivm-ssh-identity',
        ):
            mgr.submit(
                ['mkdir', '-p', str(default_priv.parent)],
                sudo=False,
                role='modify',
                summary='Create ~/.ssh directory if missing',
                detail=f'target={default_priv.parent}',
            )
            mgr.submit(
                ['chmod', '700', str(default_priv.parent)],
                sudo=False,
                role='modify',
                summary='Ensure ~/.ssh directory permissions',
                detail=f'target={default_priv.parent}',
            )
            mgr.submit(
                [
                    'ssh-keygen',
                    '-q',
                    '-t',
                    'ed25519',
                    '-f',
                    str(default_priv),
                    '-N',
                    '',
                    '-C',
                    comment,
                ],
                sudo=False,
                role='modify',
                summary='Generate dedicated aivm SSH keypair',
                detail=f'private={default_priv} public={default_pub}',
            )
    cfg.paths.ssh_identity_file = str(default_priv)
    cfg.paths.ssh_pubkey_path = str(default_pub)
    log.info(
        'Configured dedicated aivm SSH identity for vm={} private={} public={}',
        cfg.vm.name,
        default_priv,
        default_pub,
    )
    return True


def choose_vm_interactive(options: list[str], *, reason: str) -> str:
    if not sys.stdin.isatty():
        raise AIVMError(
            f'VM selection is ambiguous ({reason}). Re-run with --vm.'
        )
    print(f'Multiple VMs match ({reason}). Select one:')
    for idx, item in enumerate(options, start=1):
        print(f'  {idx}. {item}')
    while True:
        raw = input('Select VM number: ').strip()
        if not raw.isdigit():
            print('Please enter a number.')
            continue
        choice = int(raw)
        if 1 <= choice <= len(options):
            return options[choice - 1]
        print(f'Please enter a number between 1 and {len(options)}.')


def resolve_vm_name(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path | None,
) -> tuple[str, Path]:
    """Resolve a VM name using CLI intent precedence.

    Precedence is deliberate:
    explicit ``--vm`` > folder attachment mapping > active VM > single VM >
    interactive selection. This keeps one-command workflows predictable while
    still allowing explicit override.
    """
    log.trace(
        'Resolving VM name config_opt={} vm_opt={} host_src={}',
        config_opt,
        vm_opt,
        host_src,
    )
    store_path = cfg_path(config_opt)
    reg = load_store(store_path)

    if vm_opt:
        if find_vm(reg, vm_opt) is None:
            raise AIVMError(f'VM not found in config store: {vm_opt}')
        return vm_opt, store_path

    if host_src is not None:
        atts = find_attachments(reg, host_src)
        if atts:
            attached_vm_names = sorted(
                {
                    att.vm_name
                    for att in atts
                    if find_vm(reg, att.vm_name) is not None
                }
            )
            if len(attached_vm_names) == 1:
                return attached_vm_names[0], store_path
            if attached_vm_names:
                if reg.active_vm in attached_vm_names:
                    return reg.active_vm, store_path
                if not sys.stdin.isatty():
                    vm_names = ', '.join(attached_vm_names)
                    raise AIVMError(
                        'Host folder is attached to multiple VMs: '
                        f'{vm_names}. Re-run with --vm.'
                    )
                chosen = choose_vm_interactive(
                    attached_vm_names,
                    reason=(
                        f'folder {host_src} is attached to '
                        f'{len(attached_vm_names)} VMs'
                    ),
                )
                return chosen, store_path

    if reg.active_vm and find_vm(reg, reg.active_vm) is not None:
        return reg.active_vm, store_path

    if len(reg.vms) == 1:
        return reg.vms[0].name, store_path

    if len(reg.vms) > 1:
        chosen = choose_vm_interactive(
            [r.name for r in sorted(reg.vms, key=lambda x: x.name)],
            reason=f'{len(reg.vms)} configured VMs',
        )
        return chosen, store_path

    raise AIVMError(
        f'No VM definitions found in config store: {store_path}. '
        'Run `aivm config init` then `aivm vm create` first.'
    )


def load_cfg_with_path(
    config_path: str | None,
    *,
    vm_opt: str = '',
    host_src: Path | None = None,
    hydrate_runtime_defaults: bool = True,
    persist_runtime_defaults: bool = True,
) -> tuple[AgentVMConfig, Path]:
    log.trace(
        'Loading cfg with path config_path={} vm_opt={} host_src={}',
        config_path,
        vm_opt,
        host_src,
    )
    vm_name, store_path = resolve_vm_name(
        config_opt=config_path,
        vm_opt=vm_opt,
        host_src=host_src,
    )
    reg = load_store(store_path)
    rec = find_vm(reg, vm_name)
    if rec is None:
        raise AIVMError(f'VM not found in config store: {vm_name}')
    cfg = materialize_vm_cfg(reg, vm_name)
    changed = (
        hydrate_ssh_identity_defaults(cfg)
        if hydrate_runtime_defaults
        else False
    )
    if changed and persist_runtime_defaults:
        upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
        upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
        save_store(
            reg,
            store_path,
            reason=(
                f'Persist hydrated runtime defaults discovered while loading '
                f'VM {cfg.vm.name}.'
            ),
        )
    return cfg, store_path


def load_cfg(config_path: str | None, *, vm_opt: str = '') -> AgentVMConfig:
    cfg, _ = load_cfg_with_path(
        config_path,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
    )
    return cfg


def resolve_cfg_fallback(
    config_opt: str | None, *, vm_opt: str = ''
) -> tuple[AgentVMConfig, Path]:
    return load_cfg_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
    )


def record_vm(
    cfg: AgentVMConfig,
    store_file: Path | None = None,
    *,
    reason: str = '',
) -> Path:
    target = store_file or store_path()
    reg = load_store(target)
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    why = reason.strip() or f'Persist managed VM record for {cfg.vm.name}.'
    return save_store(reg, target, reason=why)


def resolve_cfg_for_code(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
) -> tuple[AgentVMConfig, Path]:
    """Resolve VM config for folder-oriented flows (``code``/``ssh``/``attach``)."""
    return load_cfg_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=host_src,
    )


@dataclass
class PreparedSession:
    cfg: AgentVMConfig
    cfg_path: Path
    host_src: Path
    attachment_mode: str
    share_source_dir: str
    share_tag: str
    share_guest_dst: str
    ip: str | None
    reg_path: Path | None
    meta_path: Path | None


def maybe_install_missing_host_deps(*, yes: bool, dry_run: bool) -> None:
    """Best-effort host dependency gate before VM lifecycle operations.

    We keep this prompt local to workflows that actively create/start/reconcile
    VMs so users see missing prerequisites at the point of need.
    """
    missing, _ = check_commands()
    if not missing:
        return
    missing_txt = ', '.join(missing)
    print(f'Missing required host dependencies: {missing_txt}')
    print('Suggested command: aivm host install_deps')
    if yes:
        print(
            '--yes was provided; skipping interactive dependency install prompt.'
        )
        return
    if dry_run:
        print(
            'DRYRUN: would prompt to install missing dependencies before VM setup.'
        )
        return
    if not host_is_debian_like():
        raise AIVMError(
            'Host is not detected as Debian/Ubuntu. Install dependencies manually, then retry.'
        )
    if not sys.stdin.isatty():
        raise AIVMError(
            'Missing required host dependencies in non-interactive mode. '
            'Run `aivm host install_deps` first.'
        )
    ans = (
        input('Install missing dependencies now with apt? [Y/n]: ')
        .strip()
        .lower()
    )
    do_install = ans in {'', 'y', 'yes'}
    if not do_install:
        raise AIVMError('Aborted by user.')
    mgr = CommandManager.current()
    with mgr.intent(
        'Prepare host dependencies',
        why='Install the host packages required before VM lifecycle work can proceed.',
        role='modify',
    ):
        install_deps_debian(assume_yes=True)
    missing_after, _ = check_commands()
    if missing_after:
        raise AIVMError(
            'Required dependencies are still missing after install attempt: '
            + ', '.join(missing_after)
        )
