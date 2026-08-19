"""Shared guest-side file/config transport for repository credentials.

This module contains no credential authority or key-lifecycle policy.  It
provides a neutral transport seam for credential subsystems that need to
install derived guest files through AIVM SSH/Git include points.
"""

from __future__ import annotations

import hashlib
import shlex
from pathlib import Path

from aivm.config_scopes import guest_transport_from_effective_cfg

from ..commands import CommandHandle, CommandManager, CommandResult
from ..config import AgentVMConfig
from ..runtime import require_ssh_identity, ssh_base_args

_SSH_INCLUDE = 'Include ~/.ssh/aivm.d/*.conf'


def guest_ssh_command(
    cfg: AgentVMConfig,
    ip: str,
    script: str,
    *,
    forward_agent_socket: Path | str | None = None,
) -> list[str]:
    """Build an SSH command to the guest, optionally forwarding one agent.

    ``ForwardAgent=<path>`` deliberately names the AIVM-owned dedicated agent
    socket instead of inheriting the caller's ordinary ``SSH_AUTH_SOCK``.
    """
    context = guest_transport_from_effective_cfg(cfg)
    ident = require_ssh_identity(context.ssh_identity_file)
    args = [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
            connect_timeout=15,
            batch_mode=True,
        ),
    ]
    if forward_agent_socket is not None:
        args.extend(['-o', f'ForwardAgent={forward_agent_socket}'])
    args.extend([context.ssh_target(ip), script])
    return args


def submit_guest(
    cfg: AgentVMConfig,
    ip: str,
    *,
    script: str,
    manager: CommandManager,
    role: str,
    summary: str,
    input_text: str | None = None,
    check: bool = True,
    forward_agent_socket: Path | str | None = None,
) -> CommandHandle:
    return manager.submit(
        guest_ssh_command(
            cfg,
            ip,
            script,
            forward_agent_socket=forward_agent_socket,
        ),
        sudo=False,
        role='read' if role == 'read' else 'modify',
        check=check,
        capture=True,
        input_text=input_text,
        summary=summary,
    )


def run_guest(
    cfg: AgentVMConfig,
    ip: str,
    *,
    script: str,
    manager: CommandManager,
    role: str,
    summary: str,
    input_text: str | None = None,
    check: bool = True,
    forward_agent_socket: Path | str | None = None,
) -> CommandResult:
    return submit_guest(
        cfg,
        ip,
        script=script,
        manager=manager,
        role=role,
        summary=summary,
        input_text=input_text,
        check=check,
        forward_agent_socket=forward_agent_socket,
    ).result()


def install_guest_file(
    cfg: AgentVMConfig,
    ip: str,
    *,
    relpath: str,
    text: str,
    mode: str,
    manager: CommandManager,
    label: str,
) -> None:
    rel_q = shlex.quote(relpath)
    mode_q = shlex.quote(mode)
    script = (
        'set -eu; umask 077; '
        f'target="$HOME"/{rel_q}; '
        'mkdir -p "$(dirname "$target")"; '
        'tmp="$(mktemp)"; '
        'cat > "$tmp"; '
        f'chmod {mode_q} "$tmp"; '
        'mv "$tmp" "$target"'
    )
    submit_guest(
        cfg,
        ip,
        script=script,
        manager=manager,
        role='modify',
        summary=f'Install guest {label}',
        input_text=text,
    )


def install_guest_file_if_changed(
    cfg: AgentVMConfig,
    ip: str,
    *,
    relpath: str,
    text: str,
    mode: str,
    manager: CommandManager,
    label: str,
) -> bool:
    """Install one derived guest file only when its content differs."""
    rel_q = shlex.quote(relpath)
    digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
    digest_q = shlex.quote(digest)
    check_script = (
        'set -eu; '
        f'target="$HOME"/{rel_q}; '
        '[ -f "$target" ] || exit 1; '
        f'printf "%s  %s\\n" {digest_q} "$target" '
        '| sha256sum --check --status -'
    )
    check = run_guest(
        cfg,
        ip,
        script=check_script,
        manager=manager,
        role='read',
        summary=f'Check guest {label} hash',
        check=False,
    )
    if check.code == 0:
        return False
    install_guest_file(
        cfg,
        ip,
        relpath=relpath,
        text=text,
        mode=mode,
        manager=manager,
        label=label,
    )
    return True


def ensure_guest_managed_includes(
    cfg: AgentVMConfig,
    ip: str,
    *,
    git_include: str,
    manager: CommandManager,
) -> None:
    """Ensure one credential system's managed SSH/Git config is included.

    SSH uses the shared ``~/.ssh/aivm.d/*.conf`` wildcard, while each
    credential subsystem owns a distinct Git include file.
    """
    ssh_include_q = shlex.quote(_SSH_INCLUDE)
    git_include_q = shlex.quote(git_include)
    check_script = (
        'set -eu; '
        'ssh_config="$HOME/.ssh/config"; '
        f'grep -Fqx {ssh_include_q} "$ssh_config" 2>/dev/null; '
        'git config --global --get-all include.path 2>/dev/null '
        f'| grep -Fqx {git_include_q}'
    )
    ready = run_guest(
        cfg,
        ip,
        script=check_script,
        manager=manager,
        role='read',
        summary='Check AIVM-managed SSH and Git credential includes',
        check=False,
    )
    if ready.code == 0:
        return
    script = (
        'set -eu; umask 077; '
        'mkdir -p "$HOME/.ssh/aivm.d" "$HOME/.config/aivm"; '
        'ssh_config="$HOME/.ssh/config"; '
        'if [ -L "$ssh_config" ]; then '
        f'if ! grep -Fqx {ssh_include_q} "$ssh_config" 2>/dev/null; then '
        'printf "%s\\n" '
        '"AIVM refuses to replace symlinked ~/.ssh/config; add the exact managed include to its target or replace the symlink." >&2; '
        'exit 78; fi; '
        'elif [ -e "$ssh_config" ] && [ ! -f "$ssh_config" ]; then '
        'printf "%s\\n" '
        '"AIVM requires ~/.ssh/config to be a regular file." >&2; '
        'exit 78; '
        'else '
        'touch "$ssh_config"; chmod 600 "$ssh_config"; '
        f'if ! grep -Fqx {ssh_include_q} "$ssh_config"; then '
        'tmp="$(mktemp)"; '
        f'printf "%s\\n" {ssh_include_q} > "$tmp"; '
        'cat "$ssh_config" >> "$tmp"; '
        'mv "$tmp" "$ssh_config"; chmod 600 "$ssh_config"; fi; '
        'fi; '
        'if ! git config --global --get-all include.path 2>/dev/null '
        f'| grep -Fqx {git_include_q}; then '
        f'git config --global --add include.path {git_include_q}; fi'
    )
    submit_guest(
        cfg,
        ip,
        script=script,
        manager=manager,
        role='modify',
        summary='Enable AIVM-managed SSH and Git credential includes',
    )
