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
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from loguru import logger as log

from .commands import CommandManager
from .config import AgentVMConfig
from .config_scopes import ResolvedVMContext
from .config_store import (
    AttachmentEntry,
    find_attachments,
    find_principal_for_host_identity,
    find_vm,
    require_vm,
    save_store,
    upsert_network,
    upsert_vm_with_network,
)
from .detect import detect_ssh_identity
from .errors import AIVMError, NoVMContextError
from .host import check_commands, host_is_debian_like, install_deps_debian
from .host_identity import current_host_identity
from .legacy.pre_0_6_0.context import (
    resolve_pre_0_6_0_vm_context,
)
from .profile_store import save_user_profile
from .scoped_store import (
    load_scope_profile,
    load_scope_store,
    persist_creator_vm,
    profile_from_effective_cfg,
    resolve_machine_context,
    resolve_store_scope,
)
from .util import which


def cfg_path(p: str | None) -> Path:
    return resolve_store_scope(p).store_path


_CURRENT_CONFIG_OPTION: ContextVar[str | None] = ContextVar(
    'aivm_current_config_option', default=None
)


def bind_active_config_option(value: str | None) -> None:
    """Record the ``--config`` value this invocation parsed.

    Optional features resolve their own settings from the store lazily rather
    than having the CLI push each one into them; this is how they find the
    same store the command is using. Keeping the direction of that dependency
    inward means the CLI's shared option surface stays free of any one
    feature's configuration.
    """
    _CURRENT_CONFIG_OPTION.set(str(value) if value else None)


def active_cfg_path() -> Path:
    """Return the config-store path bound by the running command."""
    return cfg_path(_CURRENT_CONFIG_OPTION.get())


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
        raise NoVMContextError(
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

    Raises :class:`NoVMContextError` when the store simply names no single VM,
    and a plain :class:`AIVMError` when the request itself cannot be honored
    (an explicit ``--vm`` that the store does not define).
    """
    log.trace(
        'Resolving VM name config_opt={} vm_opt={} host_src={}',
        config_opt,
        vm_opt,
        host_src,
    )
    scope = resolve_store_scope(config_opt)
    store_path = scope.store_path
    reg = load_scope_store(scope)
    profile = load_scope_profile(scope) if scope.is_machine else None
    active_vm = profile.active_vm if profile is not None else reg.active_vm

    if vm_opt:
        require_vm(reg, vm_opt)
        return vm_opt, store_path

    if host_src is not None:
        if scope.is_machine:
            identity = current_host_identity()
            owned: list[AttachmentEntry] = []
            for vm in reg.vms:
                principal = find_principal_for_host_identity(
                    reg, vm_name=vm.name, identity=identity
                )
                if principal is None:
                    continue
                owned.extend(
                    item
                    for item in find_attachments(
                        reg,
                        host_src,
                        owner_principal_id=principal.id,
                    )
                    if item.vm_name == vm.name
                )
            atts = owned
        else:
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
                if active_vm in attached_vm_names:
                    return active_vm, store_path
                if not sys.stdin.isatty():
                    vm_names = ', '.join(attached_vm_names)
                    raise NoVMContextError(
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

    if active_vm and find_vm(reg, active_vm) is not None:
        return active_vm, store_path

    if len(reg.vms) == 1:
        return reg.vms[0].name, store_path

    if len(reg.vms) > 1:
        chosen = choose_vm_interactive(
            [r.name for r in sorted(reg.vms, key=lambda x: x.name)],
            reason=f'{len(reg.vms)} configured VMs',
        )
        return chosen, store_path

    raise NoVMContextError(
        f'No VM definitions found in config store: {store_path}. '
        'Run `aivm config init` then `aivm vm create` first.'
    )


def _load_context_with_path(
    config_path: str | None,
    *,
    vm_opt: str = '',
    host_src: Path | None = None,
    hydrate_runtime_defaults: bool = True,
    persist_runtime_defaults: bool = True,
) -> tuple[ResolvedVMContext, Path]:
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
    scope = resolve_store_scope(str(store_path))
    reg = load_scope_store(scope)
    require_vm(reg, vm_name)
    if scope.is_machine:
        profile = load_scope_profile(scope)
        context = resolve_machine_context(reg, vm_name, profile=profile)
        cfg = context.effective_cfg
    else:
        from .config_store import materialize_vm_cfg

        cfg = materialize_vm_cfg(reg, vm_name)
        context = resolve_pre_0_6_0_vm_context(cfg)
    changed = (
        hydrate_ssh_identity_defaults(cfg)
        if hydrate_runtime_defaults
        else False
    )
    if changed and persist_runtime_defaults:
        if scope.is_machine:
            profile = profile_from_effective_cfg(cfg, existing=profile)
            assert scope.profile_path is not None
            save_user_profile(profile, scope.profile_path)
            context = resolve_machine_context(reg, vm_name, profile=profile)
        else:
            upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
            upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
            save_store(
                reg,
                store_path,
                reason=(
                    'Persist hydrated runtime defaults discovered while '
                    f'loading VM {cfg.vm.name}.'
                ),
            )
            context = resolve_pre_0_6_0_vm_context(cfg)
    return context, store_path


def load_cfg_with_path(
    config_path: str | None,
    *,
    vm_opt: str = '',
    host_src: Path | None = None,
    hydrate_runtime_defaults: bool = True,
    persist_runtime_defaults: bool = True,
) -> tuple[AgentVMConfig, Path]:
    context, path = _load_context_with_path(
        config_path,
        vm_opt=vm_opt,
        host_src=host_src,
        hydrate_runtime_defaults=hydrate_runtime_defaults,
        persist_runtime_defaults=persist_runtime_defaults,
    )
    return context.effective_cfg, path


def load_vm_context_with_path(
    config_path: str | None,
    *,
    vm_opt: str = '',
    host_src: Path | None = None,
    hydrate_runtime_defaults: bool = True,
    persist_runtime_defaults: bool = True,
) -> tuple[ResolvedVMContext, Path]:
    """Load one VM and resolve the invoking user's runtime identity.

    This is the canonical service-layer entry point for post-creation work.
    The legacy loader remains available to config editing, creation, and
    migration boundaries until the physical store split lands.
    """
    return _load_context_with_path(
        config_path,
        vm_opt=vm_opt,
        host_src=host_src,
        hydrate_runtime_defaults=hydrate_runtime_defaults,
        persist_runtime_defaults=persist_runtime_defaults,
    )


def load_vm_context(
    config_path: str | None, *, vm_opt: str = ''
) -> ResolvedVMContext:
    context, _ = load_vm_context_with_path(
        config_path,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
    )
    return context


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
    target = store_file or cfg_path(None)
    scope = resolve_store_scope(str(target))
    reg = load_scope_store(scope)
    why = reason.strip() or f'Persist managed VM record for {cfg.vm.name}.'
    if scope.is_machine:
        persist_creator_vm(
            scope,
            reg,
            cfg,
            set_active=False,
            reason=why,
        )
        return target
    upsert_network(reg, network=cfg.network, firewall=cfg.firewall)
    upsert_vm_with_network(reg, cfg, network_name=cfg.network.name)
    return save_store(reg, target, reason=why)


def resolve_cfg_for_code(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
) -> tuple[AgentVMConfig, Path]:
    """Legacy config resolver for creation/editing compatibility boundaries."""
    return load_cfg_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=host_src,
    )


def resolve_context_for_code(
    *,
    config_opt: str | None,
    vm_opt: str,
    host_src: Path,
) -> tuple[ResolvedVMContext, Path]:
    """Resolve a principal-aware context for folder-oriented runtime flows."""
    return load_vm_context_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=host_src,
    )


@dataclass
class PreparedSession:
    context: ResolvedVMContext
    cfg_path: Path
    host_src: Path
    attachment_mode: str
    share_source_dir: str
    share_tag: str
    share_guest_dst: str
    ip: str | None
    reg_path: Path | None
    meta_path: Path | None

    @property
    def cfg(self) -> AgentVMConfig:
        """Legacy machine config view for call sites not yet context-native."""
        return self.context.effective_cfg


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
