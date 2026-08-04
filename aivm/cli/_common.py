"""CLI command base class and per-invocation option resolution.

Application services (config loading, VM resolution, store persistence,
host-dependency gating) live in :mod:`aivm.services`; this module only
holds what is genuinely CLI-shaped: the shared option surface and the
logging/manager activation performed when a command parses.
"""

from __future__ import annotations

import os
import sys
from contextvars import ContextVar
from typing import Any, Self, cast

import kwconf
from loguru import logger

from ..commands import CommandManager
from ..config_store import find_vm, load_store
from ..errors import PrivilegeModeError
from ..scoped_store import load_scope_profile, resolve_store_scope
from ..services import bind_active_config_option

log = logger
_LAST_LOGGING_STATE: tuple[str, bool, int] | None = None
_CURRENT_YES_SUDO: ContextVar[bool] = ContextVar(
    'aivm_current_yes_sudo', default=False
)
_CURRENT_AUTO_APPROVE_READONLY_SUDO: ContextVar[bool] = ContextVar(
    'aivm_current_auto_approve_readonly_sudo', default=True
)


class _BaseCommand(kwconf.Config):
    """Base options shared by all commands."""

    __special_options__ = False

    config: str | None = kwconf.Value(
        None,
        help=(
            'Explicit config-store path. Without this option, AIVM uses an '
            'existing legacy user store, the shared machine store under '
            '/var/lib/aivm/machine when this host has one, or your own '
            'machine store under ~/.local/share/aivm/machine.'
        ),
    )
    verbose: int = kwconf.Value(
        0,
        short_alias=['v'],
        isflag='counter',
        help='Increase verbosity (-v, -vv).',
    )
    yes: bool = kwconf.Flag(
        False,
        help='Auto-approve interactive confirmations.',
    )
    yes_sudo: bool = kwconf.Flag(
        False,
        help='Auto-approve sudo confirmation prompts only.',
    )

    @classmethod
    def cli(cls, *args: Any, **kwargs: Any) -> Self:  # type: ignore
        parsed = cast(Self, super().cli(*args, **kwargs))
        cfg_verbosity = _resolve_cfg_verbosity(parsed.config)
        cfg_yes_sudo = _resolve_cfg_yes_sudo(parsed.config)
        cfg_auto_approve_readonly_sudo = (
            _resolve_cfg_auto_approve_readonly_sudo(parsed.config)
        )
        privilege_mode = _resolve_cfg_privilege_mode(parsed.config)
        if str(privilege_mode).strip().lower() == 'never':
            raise PrivilegeModeError(
                'behavior.privilege_mode = never is not supported in this '
                'release. Managed nftables and new host bind mounts still '
                'require escalation, so aivm refuses to advertise a global '
                'no-sudo guarantee. Use as-needed or always.'
            )
        effective_yes_sudo = bool(parsed.yes_sudo or parsed.yes or cfg_yes_sudo)
        setattr(parsed, 'yes_sudo', effective_yes_sudo)
        _CURRENT_YES_SUDO.set(effective_yes_sudo)
        _CURRENT_AUTO_APPROVE_READONLY_SUDO.set(
            bool(cfg_auto_approve_readonly_sudo)
        )
        # Optional features resolve their own settings from this store; the
        # shared option surface stays free of any single feature's config.
        bind_active_config_option(parsed.config)
        CommandManager.activate(
            CommandManager(
                yes=bool(parsed.yes),
                yes_sudo=bool(effective_yes_sudo),
                auto_approve_readonly_sudo=bool(cfg_auto_approve_readonly_sudo),
                privilege_mode=privilege_mode,
            )
        )
        args_verbose = int(parsed.verbose or 0)
        _setup_logging(args_verbose, cfg_verbosity)
        log.trace(
            'Parsed command {} with config={} verbose={} yes={} yes_sudo={} auto_approve_readonly_sudo={} privilege_mode={}',
            cls.__name__,
            parsed.config,
            args_verbose,
            bool(parsed.yes),
            bool(parsed.yes_sudo),
            bool(cfg_auto_approve_readonly_sudo),
            privilege_mode,
        )
        return parsed


def _resolve_cfg_verbosity(config_opt: str | None) -> int:
    cfg_verbosity = 1
    try:
        scope = resolve_store_scope(config_opt)
        path = scope.store_path
        if scope.is_machine:
            return int(load_scope_profile(scope).behavior.verbose or 1)
        if path.exists():
            reg = load_store(path)
            behavior_verbose = int(reg.behavior.verbose or 1)
            if behavior_verbose != 1:
                cfg_verbosity = behavior_verbose
            elif reg.active_vm:
                rec = find_vm(reg, reg.active_vm)
                if rec is not None:
                    cfg_verbosity = int(rec.cfg.verbosity)
            elif reg.defaults is not None:
                cfg_verbosity = int(reg.defaults.verbosity)
    except Exception:
        cfg_verbosity = 1
    return cfg_verbosity


def _resolve_cfg_yes_sudo(config_opt: str | None) -> bool:
    cfg_yes_sudo = False
    try:
        scope = resolve_store_scope(config_opt)
        path = scope.store_path
        if scope.is_machine:
            return bool(load_scope_profile(scope).behavior.yes_sudo)
        if path.exists():
            reg = load_store(path)
            cfg_yes_sudo = bool(reg.behavior.yes_sudo)
    except Exception:
        cfg_yes_sudo = False
    return cfg_yes_sudo


def _resolve_cfg_privilege_mode(config_opt: str | None) -> str:
    from ..modes import DEFAULT_PRIVILEGE_MODE, normalize_privilege_mode

    # An unreadable store falls back to the default, but a store that names
    # an unknown mode must not: normalize_privilege_mode raises, and letting
    # that escape is the point -- silently choosing a privilege mode for the
    # user is what we are trying to avoid.
    try:
        scope = resolve_store_scope(config_opt)
        if scope.is_machine:
            return str(
                normalize_privilege_mode(
                    load_scope_profile(scope).behavior.privilege_mode
                )
            )
        path = scope.store_path
        if not path.exists():
            return str(DEFAULT_PRIVILEGE_MODE)
        reg = load_store(path)
    except Exception:
        return str(DEFAULT_PRIVILEGE_MODE)
    return str(normalize_privilege_mode(reg.behavior.privilege_mode))


def _resolve_cfg_auto_approve_readonly_sudo(config_opt: str | None) -> bool:
    auto_approve_readonly_sudo = True
    try:
        scope = resolve_store_scope(config_opt)
        path = scope.store_path
        if scope.is_machine:
            return bool(
                load_scope_profile(scope).behavior.auto_approve_readonly_sudo
            )
        if path.exists():
            reg = load_store(path)
            auto_approve_readonly_sudo = bool(
                reg.behavior.auto_approve_readonly_sudo
            )
    except Exception:
        auto_approve_readonly_sudo = True
    return auto_approve_readonly_sudo


def _setup_logging(args_verbose: int, cfg_verbosity: int) -> None:
    global _LAST_LOGGING_STATE
    effective_verbosity = args_verbose if args_verbose > 0 else cfg_verbosity
    level = 'WARNING'
    if effective_verbosity == 1:
        level = 'INFO'
    elif effective_verbosity == 2:
        level = 'DEBUG'
    elif effective_verbosity >= 3:
        level = 'TRACE'
    colorize = sys.stderr.isatty() and os.getenv('NO_COLOR') is None
    state = (level, colorize, id(sys.stderr))
    if _LAST_LOGGING_STATE == state:
        return
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        colorize=colorize,
        format='<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>',
    )
    _LAST_LOGGING_STATE = state
    log.debug(
        'Logging configured at {} (effective_verbosity={}, colorize={})',
        level,
        effective_verbosity,
        colorize,
    )


__all__ = [
    '_BaseCommand',
    '_setup_logging',
    'log',
]
