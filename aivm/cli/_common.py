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
from ..services import cfg_path

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
        help='Path to global aivm config store (default: ~/.config/aivm/config.toml).',
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
    # Named --never_sudo (not --sudoless) so a mistyped `--sudo` cannot
    # prefix-abbreviate into the opposite of the user's intent, and (unlike
    # --no_sudo) its auto-generated negation aliases cannot collide with the
    # status command's --sudo/--no-sudo flag.
    never_sudo: bool = kwconf.Flag(
        False,
        help=(
            'Never invoke sudo for this invocation (forces sudoless mode, '
            'overriding behavior.privilege_mode; see `aivm host sudoless`).'
        ),
    )

    @classmethod
    def cli(cls, *args: Any, **kwargs: Any) -> Self:  # type: ignore
        parsed = cast(Self, super().cli(*args, **kwargs))
        cfg_verbosity = _resolve_cfg_verbosity(parsed.config)
        cfg_yes_sudo = _resolve_cfg_yes_sudo(parsed.config)
        cfg_auto_approve_readonly_sudo = (
            _resolve_cfg_auto_approve_readonly_sudo(parsed.config)
        )
        privilege_mode = (
            'sudoless'
            if parsed.never_sudo
            else _resolve_cfg_privilege_mode(parsed.config)
        )
        effective_yes_sudo = bool(parsed.yes_sudo or parsed.yes or cfg_yes_sudo)
        setattr(parsed, 'yes_sudo', effective_yes_sudo)
        _CURRENT_YES_SUDO.set(effective_yes_sudo)
        _CURRENT_AUTO_APPROVE_READONLY_SUDO.set(
            bool(cfg_auto_approve_readonly_sudo)
        )
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
        path = cfg_path(config_opt)
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
        path = cfg_path(config_opt)
        if path.exists():
            reg = load_store(path)
            cfg_yes_sudo = bool(reg.behavior.yes_sudo)
    except Exception:
        cfg_yes_sudo = False
    return cfg_yes_sudo


def _resolve_cfg_privilege_mode(config_opt: str | None) -> str:
    from ..privilege import normalize_privilege_mode

    try:
        path = cfg_path(config_opt)
        if path.exists():
            reg = load_store(path)
            return normalize_privilege_mode(reg.behavior.privilege_mode)
    except Exception:
        pass
    return 'auto'


def _resolve_cfg_auto_approve_readonly_sudo(config_opt: str | None) -> bool:
    auto_approve_readonly_sudo = True
    try:
        path = cfg_path(config_opt)
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
