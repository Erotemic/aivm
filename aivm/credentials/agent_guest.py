"""Derived guest routing for ssh-agent repository credentials.

Only public key material crosses the guest boundary.  The corresponding
private keys remain in the principal-scoped host ssh-agent and are reachable
from the guest only while an AIVM-managed SSH connection forwards that agent.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..config_store import AgentCredentialEntry
from ..errors import AIVMError
from .agent_schema import (
    AGENT_CREDENTIAL_STATE_ACTIVE,
    validate_agent_credential_id_format,
    validate_agent_credential_identity,
)
from .guest_config import (
    ensure_guest_managed_includes,
    install_guest_file_if_changed,
    run_guest,
    submit_guest,
)
from .models import GitRepository

_GUEST_ROOT = '.local/share/aivm/agent-credentials'
_SSH_MANAGED = '.ssh/aivm.d/agent-credentials.conf'
_GIT_MANAGED = '.config/aivm/gitconfig-agent-credentials'
_GIT_INCLUDE = '~/.config/aivm/gitconfig-agent-credentials'


class RepositoryVerificationNetworkError(AIVMError):
    """Repository probe could not reach the provider from the guest."""


_REPOSITORY_NETWORK_FAILURE_MARKERS = (
    'connection refused',
    'connection timed out',
    'network is unreachable',
    'no route to host',
    'could not resolve hostname',
    'temporary failure in name resolution',
    'name or service not known',
)


def _repository_probe_network_unavailable(detail: str) -> bool:
    """Return whether a failed SSH probe is clearly a guest network failure."""
    lowered = detail.lower()
    return any(marker in lowered for marker in _REPOSITORY_NETWORK_FAILURE_MARKERS)


def guest_public_key_relpath(cred_id: str) -> str:
    try:
        safe_id = validate_agent_credential_id_format(cred_id)
    except ValueError as ex:
        raise AIVMError(str(ex)) from ex
    return f'{_GUEST_ROOT}/{safe_id}/id_ed25519.pub'


def _validated_repository(entry: AgentCredentialEntry) -> GitRepository:
    try:
        return validate_agent_credential_identity(
            vm_name=entry.vm_name,
            cred_id=entry.id,
            provider_host=entry.provider_host,
            owner=entry.owner,
            repository=entry.repository,
            principal_id=entry.principal_id,
        )
    except ValueError as ex:
        raise AIVMError(str(ex)) from ex


def render_ssh_config(credentials: list[AgentCredentialEntry]) -> str:
    """Render repo aliases that select one forwarded-agent identity exactly."""
    lines = ['# Managed by aivm. Public selectors for ssh-agent credentials.']
    for entry in sorted(credentials, key=lambda item: item.id):
        repo = _validated_repository(entry)
        alias = f'aivm-agent-cred-{entry.id}'
        public_path = '~/' + guest_public_key_relpath(entry.id)
        lines.extend(
            [
                '',
                f'Host {alias}',
                f'    HostName {repo.host}',
                f'    HostKeyAlias {repo.host}',
                '    User git',
                f'    IdentityFile {public_path}',
                '    IdentitiesOnly yes',
                '    BatchMode yes',
                '    StrictHostKeyChecking accept-new',
            ]
        )
    return '\n'.join(lines).rstrip() + '\n'


def render_git_config(credentials: list[AgentCredentialEntry]) -> str:
    """Rewrite exact repository URLs to their public-key-selecting SSH alias."""
    lines = ['# Managed by aivm. SSH-agent repository routing.']
    for entry in sorted(credentials, key=lambda item: item.id):
        repo = _validated_repository(entry)
        alias = f'aivm-agent-cred-{entry.id}'
        repo_path = f'{repo.owner}/{repo.name}'
        target = f'git@{alias}:{repo_path}.git'
        source_urls = [
            f'git@{repo.host}:{repo_path}.git',
            f'ssh://git@{repo.host}/{repo_path}.git',
            f'https://{repo.host}/{repo_path}.git',
        ]
        lower = [url.lower() for url in source_urls]
        source_urls.extend(url for url in lower if url not in source_urls)
        lines.extend(['', f'[url "{target}"]'])
        lines.extend(f'    insteadOf = {url}' for url in source_urls)
    return '\n'.join(lines).rstrip() + '\n'


def _remove_stale_public_selectors(
    cfg: AgentVMConfig,
    ip: str,
    *,
    keep_ids: tuple[str, ...],
    manager: CommandManager,
) -> None:
    root_q = shlex.quote(_GUEST_ROOT)
    if keep_ids:
        cases = '|'.join(shlex.quote(item) for item in keep_ids)
        check_decision = f'case "$name" in {cases}) ;; *) exit 1 ;; esac'
        cleanup_decision = (
            f'case "$name" in {cases}) ;; *) rm -rf -- "$child" ;; esac'
        )
    else:
        check_decision = 'exit 1'
        cleanup_decision = 'rm -rf -- "$child"'
    check_script = (
        'set -eu; '
        f'root="$HOME"/{root_q}; '
        '[ -d "$root" ] || exit 0; '
        'for child in "$root"/*; do '
        '[ -d "$child" ] || continue; '
        'name=${child##*/}; '
        f'{check_decision}; '
        'done'
    )
    clean = run_guest(
        cfg,
        ip,
        script=check_script,
        manager=manager,
        role='read',
        summary='Check guest ssh-agent public selector set',
        check=False,
    )
    if clean.code == 0:
        return
    cleanup_script = (
        'set -eu; '
        f'root="$HOME"/{root_q}; '
        '[ -d "$root" ] || exit 0; '
        'for child in "$root"/*; do '
        '[ -d "$child" ] || continue; '
        'name=${child##*/}; '
        f'{cleanup_decision}; '
        'done'
    )
    submit_guest(
        cfg,
        ip,
        script=cleanup_script,
        manager=manager,
        role='modify',
        summary='Remove stale guest ssh-agent public selectors',
    )


def reconcile_guest_agent_credentials(
    cfg: AgentVMConfig,
    ip: str,
    *,
    credentials: tuple[AgentCredentialEntry, ...],
    public_keys: dict[str, str],
    manager: CommandManager,
) -> None:
    """Install only public selectors and regenerate agent-specific routing."""
    active = tuple(
        entry
        for entry in credentials
        if entry.state == AGENT_CREDENTIAL_STATE_ACTIVE
    )
    with manager.step(
        'Reconcile guest ssh-agent credential routing',
        why=(
            'Install public key selectors and repository aliases while all '
            'private deploy keys remain exclusively in the host ssh-agent.'
        ),
        approval_scope=f'agent-credential-routing:{cfg.vm.name}',
    ):
        ensure_guest_managed_includes(
            cfg,
            ip,
            git_include=_GIT_INCLUDE,
            manager=manager,
        )
        for entry in active:
            try:
                public_text = public_keys[entry.id]
            except KeyError as ex:
                raise AIVMError(
                    f'Missing validated public key for ssh-agent credential {entry.id}.'
                ) from ex
            install_guest_file_if_changed(
                cfg,
                ip,
                relpath=guest_public_key_relpath(entry.id),
                text=public_text.rstrip() + '\n',
                # OpenSSH applies IdentityFile permission checks even when
                # the selector contains only a public key.  Keep it private-mode
                # so IdentitiesOnly can use it to select the forwarded identity.
                mode='600',
                manager=manager,
                label=f'ssh-agent public selector {entry.id}',
            )
        install_guest_file_if_changed(
            cfg,
            ip,
            relpath=_SSH_MANAGED,
            text=render_ssh_config(list(active)),
            mode='600',
            manager=manager,
            label='ssh-agent SSH routing config',
        )
        install_guest_file_if_changed(
            cfg,
            ip,
            relpath=_GIT_MANAGED,
            text=render_git_config(list(active)),
            mode='600',
            manager=manager,
            label='ssh-agent Git routing config',
        )
        _remove_stale_public_selectors(
            cfg,
            ip,
            keep_ids=tuple(entry.id for entry in active),
            manager=manager,
        )


def probe_forwarded_agent(
    cfg: AgentVMConfig,
    ip: str,
    *,
    socket_path: Path,
    expected_fingerprints: tuple[str, ...],
    manager: CommandManager,
) -> None:
    """Prove the guest sees exactly the dedicated host agent over SSH."""
    probe_script = (
        'set -eu; '
        'if [ -z "${SSH_AUTH_SOCK:-}" ]; then '
        'echo "AIVM agent forwarding: SSH_AUTH_SOCK is unset in the guest session" >&2; '
        'exit 97; fi; '
        'if [ ! -S "$SSH_AUTH_SOCK" ]; then '
        'echo "AIVM agent forwarding: SSH_AUTH_SOCK does not name a socket: $SSH_AUTH_SOCK" >&2; '
        'exit 98; fi; '
        'ssh-add -l -E sha256'
    )
    result = run_guest(
        cfg,
        ip,
        script=probe_script,
        manager=manager,
        role='read',
        summary='Verify dedicated credential agent is forwarded into guest',
        check=False,
        forward_agent_socket=socket_path,
    )
    loaded = tuple(
        parts[1]
        for line in result.stdout.splitlines()
        if len(parts := line.split()) >= 2 and parts[1].startswith('SHA256:')
    )
    if result.code != 0 or len(loaded) != len(expected_fingerprints) or set(
        loaded
    ) != set(expected_fingerprints):
        detail = (result.stderr or result.stdout or '').strip()
        policy_result = run_guest(
            cfg,
            ip,
            script=(
                "sudo sshd -T 2>/dev/null | "
                "grep -E '^(allowagentforwarding|disableforwarding) ' || true"
            ),
            manager=manager,
            role='read',
            summary='Inspect guest sshd agent-forwarding policy',
            check=False,
        )
        policy = (policy_result.stdout or policy_result.stderr or '').strip()
        policy_detail = (
            f' Guest sshd policy: {policy}.'
            if policy
            else ' Guest sshd forwarding policy could not be determined.'
        )
        raise AIVMError(
            'Dedicated ssh-agent credential forwarding did not reach the '
            f'guest with the expected identities: expected={expected_fingerprints!r} '
            f'loaded={loaded!r}. {detail}{policy_detail}'.rstrip()
        )


def probe_repository_access(
    cfg: AgentVMConfig,
    ip: str,
    *,
    socket_path: Path,
    credential: AgentCredentialEntry,
    manager: CommandManager,
) -> None:
    """Prove managed Git routing authenticates with the forwarded identity."""
    repo = _validated_repository(credential)
    canonical = f'git@{repo.host}:{repo.owner}/{repo.name}.git'
    script = (
        'set -eu; '
        'export GIT_TERMINAL_PROMPT=0; '
        f'git ls-remote {shlex.quote(canonical)} HEAD >/dev/null'
    )
    result = run_guest(
        cfg,
        ip,
        script=script,
        manager=manager,
        role='read',
        summary=f'Verify repository authentication for {credential.id}',
        check=False,
        forward_agent_socket=socket_path,
    )
    if result.code != 0:
        detail = (result.stderr or result.stdout or '').strip()
        if detail and _repository_probe_network_unavailable(detail):
            raise RepositoryVerificationNetworkError(detail)
        suffix = f': {detail}' if detail else ''
        raise AIVMError(
            'Guest repository authentication failed for ssh-agent credential '
            f'{credential.id} after routing reconciliation{suffix}'
        )

