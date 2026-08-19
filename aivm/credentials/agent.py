"""Independent host-agent repository credentials.

This subsystem is intentionally separate from the existing guest-key credential
feature. It owns a distinct desired-state collection and deploy-key material. A key
created here is host-only: AIVM never installs its private half in a guest.

The runtime capability path is connection-scoped. Managed SSH/Remote-SSH
sessions forward only this dedicated agent into the selected guest, while
repo-specific public selectors choose the right loaded deploy key. Private
key material remains host-only throughout.
"""

from __future__ import annotations

import fcntl
import os
import re
import shutil
import socket
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Literal

from ..commands import CommandManager, CommandResult
from ..config_store.models import AgentCredentialEntry, Store
from ..config_store.mutate import remove_agent_credential, upsert_agent_credential
from ..errors import AIVMError
from ..scoped_store import resolve_store_scope, save_scope_store
from . import providers
from .agent_schema import (
    AGENT_CREDENTIAL_STATE_ACTIVE,
    AGENT_CREDENTIAL_STATE_PENDING,
    AGENT_CREDENTIAL_STATE_REVOCATION_PENDING,
    agent_credential_id,
)
from .agent_store import (
    _ensure_entry_dir,
    _ensure_private_dir,
    _ensure_scope_dirs,
    _remove_key_tree,
    _require_private_dir,
    _require_safe_file,
    agent_repository,
    agent_scope_dir,
    agent_scope_id,
    find_agent_credential,
    list_agent_credentials,
    private_key_path,
    public_key_path,
)
from .keys import normalized_public_key, public_key_fingerprint
from .models import GitRepository, ProviderDeployKey
from .schema import normalize_credential_access
from .setup import require_supported_gh
from .validation import validate_metadata_text

_AGENT_PID_RE = re.compile(r'(?:^|\n)SSH_AGENT_PID=(\d+);')
_AGENT_RUNTIME_PARENT = Path('/tmp') / f'aivm-agent-credentials-{os.getuid()}'
AgentRuntimeState = Literal['stopped', 'running', 'stale']


def _save_agent_store(store: Store, store_path: Path, *, reason: str) -> None:
    """Persist agent-credential metadata through the selected store scope."""
    scope = resolve_store_scope(str(store_path))
    save_scope_store(scope, store, reason=reason)

@dataclass(frozen=True)
class AgentProcessState:
    """Coordinates for one AIVM-owned ``ssh-agent`` process."""

    vm_name: str
    principal_id: str
    pid: int
    socket_path: Path


@dataclass(frozen=True)
class AgentStatus:
    """Observed dedicated-agent process and identities."""

    runtime_state: AgentRuntimeState
    pid: int | None
    socket_path: Path
    loaded_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class DoctorIssue:
    code: str
    detail: str
    fixable: bool


@dataclass(frozen=True)
class DoctorReport:
    vm_name: str
    principal_id: str
    records: tuple[AgentCredentialEntry, ...]
    agent: AgentStatus
    issues: tuple[DoctorIssue, ...]

    @property
    def healthy(self) -> bool:
        return not self.issues

    @property
    def fixable_count(self) -> int:
        return sum(issue.fixable for issue in self.issues)


class _ScopeLock:
    """Serialize record and agent mutations for one VM/principal scope."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd = -1

    def __enter__(self) -> '_ScopeLock':
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        self.fd = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise AIVMError(
                    f'Agent-credential lock is not a user-owned regular file: '
                    f'{self.path}'
                )
            os.fchmod(self.fd, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except Exception:
            os.close(self.fd)
            self.fd = -1
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.fd >= 0:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = -1


def agent_socket_path(vm_name: str, principal_id: str) -> Path:
    path = _AGENT_RUNTIME_PARENT / f'{agent_scope_id(vm_name, principal_id)}.sock'
    if len(os.fsencode(path)) >= 108:
        raise AIVMError(f'Agent-credential socket path is too long: {path}')
    return path


def _pid_path(vm_name: str, principal_id: str) -> Path:
    return agent_scope_dir(vm_name, principal_id) / 'agent.pid'


def _lock_path(vm_name: str, principal_id: str) -> Path:
    return agent_scope_dir(vm_name, principal_id) / 'lock'


def _ensure_runtime_dir() -> None:
    _ensure_private_dir(
        _AGENT_RUNTIME_PARENT,
        label='Agent-credential runtime directory',
    )


def _inspect_keypair(
    record: AgentCredentialEntry, *, manager: CommandManager
) -> tuple[str, str]:
    private = private_key_path(record)
    public = public_key_path(record)
    _require_private_dir(private.parent, label='Agent-credential entry directory')
    _require_safe_file(private, label='Agent credential private key', private=True)
    _require_safe_file(public, label='Agent credential public key', private=False)
    public_text = normalized_public_key(public.read_text(encoding='utf-8'))
    fingerprint = public_key_fingerprint(public_text)
    result = manager.run(
        ['ssh-keygen', '-y', '-f', str(private)],
        sudo=False,
        role='read',
        check=False,
        capture=True,
        input_text='',
        timeout=10,
        summary=f'Validate host-only deploy key {record.id}',
        detail=f'private={private} public={public}',
    )
    if result.code != 0:
        detail = (result.stderr or result.stdout or '').strip()
        raise AIVMError(
            f'Private key for agent credential {record.id} is invalid: '
            f'{detail or "ssh-keygen -y failed"}'
        )
    if normalized_public_key(result.stdout) != public_text:
        raise AIVMError(
            f'Private and public keys for agent credential {record.id} do not '
            'form a matching keypair.'
        )
    if record.key_fingerprint and record.key_fingerprint != fingerprint:
        raise AIVMError(
            f'Agent credential {record.id} key fingerprint drifted: '
            f'recorded={record.key_fingerprint} actual={fingerprint}.'
        )
    return public_text, fingerprint


def validated_agent_public_key(
    record: AgentCredentialEntry, *, manager: CommandManager
) -> tuple[str, str]:
    """Return validated public material for guest-side identity selection.

    This intentionally exposes only the public half and its fingerprint.  The
    private path remains an implementation detail of the host agent manager.
    """
    return _inspect_keypair(record, manager=manager)


def _ensure_keypair(
    record: AgentCredentialEntry, *, manager: CommandManager
) -> AgentCredentialEntry:
    private = private_key_path(record)
    public = public_key_path(record)
    directory = _ensure_entry_dir(record)
    private_exists = os.path.lexists(private)
    public_exists = os.path.lexists(public)
    if private_exists and public_exists:
        _, fingerprint = _inspect_keypair(record, manager=manager)
        return replace(record, key_fingerprint=fingerprint)
    if private_exists or public_exists:
        raise AIVMError(
            f'Agent credential keypair is incomplete under {directory}; '
            'doctor will not invent replacement key material.'
        )
    if record.key_fingerprint:
        raise AIVMError(
            f'Host-only key material for recorded agent credential {record.id} '
            'is missing. Refusing to generate a replacement while its provider '
            'identity may still exist.'
        )
    with manager.step(
        f'Generate host-only deploy key {record.id}',
        why=(
            'Create a unique repository key that remains on the AIVM host and '
            'is never installed into the guest.'
        ),
        approval_scope=f'agent-credential-key:{record.id}',
    ):
        manager.run(
            [
                'ssh-keygen',
                '-q',
                '-t',
                'ed25519',
                '-N',
                '',
                '-f',
                str(private),
                '-C',
                record.provider_key_title,
            ],
            sudo=False,
            role='modify',
            check=True,
            capture=True,
            summary='Generate host-only repository deploy key',
            detail=f'private={private} public={public}',
        )
        private.chmod(0o600)
        public.chmod(0o644)
    _, fingerprint = _inspect_keypair(record, manager=manager)
    return replace(record, key_fingerprint=fingerprint)


def _provider_fingerprint(remote: ProviderDeployKey) -> str:
    if not remote.key:
        raise AIVMError(
            f'Provider deploy key {remote.key_id or "<unknown>"} returned no '
            'public-key material.'
        )
    return public_key_fingerprint(remote.key)


def _find_remote(
    record: AgentCredentialEntry, *, manager: CommandManager
) -> ProviderDeployKey | None:
    remotes = providers.list_deploy_keys(record.kind, agent_repository(record), manager=manager)
    if record.provider_key_id:
        exact = [item for item in remotes if item.key_id == record.provider_key_id]
        if len(exact) > 1:
            raise AIVMError(
                f'Provider returned duplicate deploy-key id '
                f'{record.provider_key_id!r}.'
            )
        if exact:
            if _provider_fingerprint(exact[0]) != record.key_fingerprint:
                raise AIVMError(
                    f'Provider key id {record.provider_key_id} no longer '
                    f'matches agent credential {record.id}; refusing to use it.'
                )
            return exact[0]
    by_fingerprint = [
        item
        for item in remotes
        if _provider_fingerprint(item) == record.key_fingerprint
    ]
    if len(by_fingerprint) > 1:
        raise AIVMError(
            f'Multiple provider deploy keys match agent credential {record.id}.'
        )
    if by_fingerprint:
        return by_fingerprint[0]
    title_matches = [
        item for item in remotes if item.title == record.provider_key_title
    ]
    if title_matches:
        raise AIVMError(
            f'A provider deploy key uses title {record.provider_key_title!r} '
            'but has different key material.'
        )
    return None


def _require_agent_tools(kind: str, *, manager: CommandManager) -> None:
    names = ('ssh-keygen', 'ssh-agent', 'ssh-add', *providers.required_tools(kind))
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise AIVMError(
            'Missing host command(s) required for host-agent credentials: '
            + ', '.join(missing)
        )
    if 'gh' in providers.required_tools(kind):
        require_supported_gh(manager=manager)


def _credential_title(
    vm_name: str, repo: GitRepository, cred_id: str
) -> str:
    host = socket.gethostname().split('.')[0]
    return validate_metadata_text(
        'provider_key_title',
        f'aivm-agent:{host}:{vm_name}:{repo.owner}/{repo.name}:{cred_id}',
    )


def _active_records(
    records: Iterable[AgentCredentialEntry],
) -> tuple[AgentCredentialEntry, ...]:
    return tuple(
        record
        for record in records
        if record.state == AGENT_CREDENTIAL_STATE_ACTIVE
    )


def _pid_is_owned_ssh_agent(pid: int) -> bool:
    """Recognize a same-user ssh-agent without inspecting its key memory.

    OpenSSH deliberately makes ssh-agent non-dumpable.  Linux may therefore
    make /proc/<pid> appear root-owned and deny readlink(/proc/<pid>/exe) even
    though the process still runs entirely as the invoking user.  Read the
    process credentials and command name from /proc/<pid>/status instead.
    """
    proc = Path('/proc') / str(pid)
    try:
        status = (proc / 'status').read_text(encoding='utf-8')
    except (FileNotFoundError, PermissionError, OSError, UnicodeError):
        return False
    name = ''
    uids: tuple[int, ...] = ()
    for line in status.splitlines():
        if line.startswith('Name:'):
            name = line.partition(':')[2].strip()
        elif line.startswith('Uid:'):
            raw = line.partition(':')[2].split()
            try:
                uids = tuple(int(value) for value in raw[:4])
            except ValueError:
                return False
    return name == 'ssh-agent' and len(uids) == 4 and all(
        value == os.getuid() for value in uids
    )


def _require_safe_socket(path: Path, *, allow_missing: bool) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise AIVMError(f'Agent-credential socket is missing: {path}')
    if not stat.S_ISSOCK(info.st_mode):
        raise AIVMError(f'Agent-credential socket is not a Unix socket: {path}')
    if info.st_uid != os.getuid():
        raise AIVMError(
            f'Agent-credential socket is not owned by the current user: {path}'
        )


def _load_process_state(
    vm_name: str, principal_id: str
) -> AgentProcessState | None:
    path = _pid_path(vm_name, principal_id)
    try:
        _require_safe_file(path, label='Agent-credential PID file')
    except FileNotFoundError:
        return None
    try:
        pid = int(path.read_text(encoding='utf-8').strip())
    except (OSError, ValueError) as ex:
        raise AIVMError(f'Invalid agent-credential PID file {path}: {ex}') from ex
    if pid <= 0:
        raise AIVMError(f'Invalid ssh-agent pid {pid!r} in {path}.')
    return AgentProcessState(
        vm_name=vm_name,
        principal_id=principal_id,
        pid=pid,
        socket_path=agent_socket_path(vm_name, principal_id),
    )


def _write_pid(state: AgentProcessState) -> None:
    path = _pid_path(state.vm_name, state.principal_id)
    fd, tmp_name = tempfile.mkstemp(prefix='.pid-', dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            fd = -1
            file.write(f'{state.pid}\n')
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
        path.chmod(0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _remove_pid(vm_name: str, principal_id: str) -> None:
    path = _pid_path(vm_name, principal_id)
    try:
        _require_safe_file(path, label='Agent-credential PID file')
        path.unlink()
    except FileNotFoundError:
        pass


def _agent_env(state: AgentProcessState) -> dict[str, str]:
    env = os.environ.copy()
    env['SSH_AUTH_SOCK'] = str(state.socket_path)
    env['SSH_AGENT_PID'] = str(state.pid)
    return env


def _probe_agent(
    state: AgentProcessState, *, manager: CommandManager
) -> tuple[bool, CommandResult]:
    result = manager.run(
        ['ssh-add', '-l', '-E', 'sha256'],
        sudo=False,
        role='read',
        ownership='tool',
        check=False,
        capture=True,
        env=_agent_env(state),
        summary='Inspect host-agent credential identities',
        detail=f'socket={state.socket_path}',
    )
    combined = f'{result.stdout}\n{result.stderr}'.lower()
    live = result.code == 0 or (
        result.code == 1 and 'agent has no identities' in combined
    )
    return live, result


def _parse_loaded_fingerprints(result: CommandResult) -> tuple[str, ...]:
    if result.code != 0:
        return ()
    return tuple(
        parts[1]
        for line in result.stdout.splitlines()
        if len(parts := line.split()) >= 2 and parts[1].startswith('SHA256:')
    )


def inspect_agent(
    vm_name: str,
    principal_id: str,
    *,
    manager: CommandManager,
) -> AgentStatus:
    socket_path = agent_socket_path(vm_name, principal_id)
    state = _load_process_state(vm_name, principal_id)
    if state is None:
        runtime: AgentRuntimeState = 'stopped'
        if os.path.lexists(socket_path):
            _require_safe_socket(socket_path, allow_missing=False)
            runtime = 'stale'
        return AgentStatus(runtime, None, socket_path, ())
    live, result = _probe_agent(state, manager=manager)
    if not live:
        return AgentStatus('stale', state.pid, socket_path, ())
    if not _pid_is_owned_ssh_agent(state.pid):
        raise AIVMError(
            f'Agent-credential socket answers, but pid {state.pid} is not a '
            'user-owned ssh-agent process.'
        )
    return AgentStatus(
        'running',
        state.pid,
        socket_path,
        _parse_loaded_fingerprints(result),
    )


def _cleanup_stale(state: AgentProcessState) -> None:
    _require_safe_socket(state.socket_path, allow_missing=True)
    try:
        state.socket_path.unlink()
    except FileNotFoundError:
        pass
    _remove_pid(state.vm_name, state.principal_id)


def _start_agent_locked(
    vm_name: str, principal_id: str, *, manager: CommandManager
) -> AgentProcessState:
    _ensure_runtime_dir()
    socket_path = agent_socket_path(vm_name, principal_id)
    existing = _load_process_state(vm_name, principal_id)
    if existing is not None:
        live, _ = _probe_agent(existing, manager=manager)
        if live:
            if not _pid_is_owned_ssh_agent(existing.pid):
                raise AIVMError(
                    f'Agent-credential socket answers, but pid {existing.pid} '
                    'is not a user-owned ssh-agent process.'
                )
            return existing
        _cleanup_stale(existing)
    elif os.path.lexists(socket_path):
        _require_safe_socket(socket_path, allow_missing=False)
        raise AIVMError(
            f'Untracked host-agent credential socket exists: {socket_path}.'
        )
    result = manager.run(
        ['ssh-agent', '-a', str(socket_path), '-s'],
        sudo=False,
        role='modify',
        ownership='tool',
        check=True,
        capture=True,
        summary='Start dedicated host-agent credential process',
        detail=f'vm={vm_name} principal={principal_id or "legacy"}',
    )
    match = _AGENT_PID_RE.search(result.stdout)
    if match is None:
        raise AIVMError('ssh-agent returned an unrecognized startup response.')
    state = AgentProcessState(
        vm_name=vm_name,
        principal_id=principal_id,
        pid=int(match.group(1)),
        socket_path=socket_path,
    )
    try:
        _require_safe_socket(socket_path, allow_missing=False)
        _write_pid(state)
        live, _ = _probe_agent(state, manager=manager)
        if not live:
            raise AIVMError(
                f'New host-agent credential process did not answer at '
                f'{socket_path}.'
            )
        if not _pid_is_owned_ssh_agent(state.pid):
            raise AIVMError(
                f'New agent pid {state.pid} is not a user-owned ssh-agent.'
            )
    except Exception:
        manager.run(
            ['ssh-agent', '-k'],
            sudo=False,
            role='modify',
            ownership='tool',
            check=False,
            capture=True,
            env=_agent_env(state),
            summary='Clean up failed host-agent startup',
        )
        try:
            _cleanup_stale(state)
        except AIVMError:
            pass
        raise
    return state


def _stop_agent_locked(
    vm_name: str, principal_id: str, *, manager: CommandManager
) -> bool:
    state = _load_process_state(vm_name, principal_id)
    socket_path = agent_socket_path(vm_name, principal_id)
    if state is None:
        if os.path.lexists(socket_path):
            _require_safe_socket(socket_path, allow_missing=False)
            raise AIVMError(
                f'Cannot remove untracked host-agent socket: {socket_path}'
            )
        return False
    live, _ = _probe_agent(state, manager=manager)
    if not live:
        _cleanup_stale(state)
        return False
    if not _pid_is_owned_ssh_agent(state.pid):
        raise AIVMError(
            f'Host-agent socket is live but pid {state.pid} is not a '
            'user-owned ssh-agent; refusing to kill it.'
        )
    manager.run(
        ['ssh-add', '-D'],
        sudo=False,
        role='modify',
        ownership='tool',
        check=True,
        capture=True,
        env=_agent_env(state),
        summary='Unload host-agent credential identities',
    )
    manager.run(
        ['ssh-agent', '-k'],
        sudo=False,
        role='modify',
        ownership='tool',
        check=True,
        capture=True,
        env=_agent_env(state),
        summary='Stop dedicated host-agent credential process',
    )
    _cleanup_stale(state)
    return True


def _validated_active_key_paths(
    records: Iterable[AgentCredentialEntry], *, manager: CommandManager
) -> tuple[list[Path], tuple[str, ...]]:
    paths: list[Path] = []
    fingerprints: list[str] = []
    for record in _active_records(records):
        _, actual = _inspect_keypair(record, manager=manager)
        if not record.key_fingerprint:
            raise AIVMError(
                f'Active agent credential {record.id} has no fingerprint.'
            )
        if actual != record.key_fingerprint:
            raise AIVMError(
                f'Agent credential {record.id} fingerprint mismatch.'
            )
        paths.append(private_key_path(record))
        fingerprints.append(actual)
    return paths, tuple(fingerprints)


def ensure_agent_state(
    store: Store,
    vm_name: str,
    principal_id: str,
    *,
    manager: CommandManager,
) -> AgentStatus:
    """Make the dedicated agent exactly match active agent credentials.

    This is an internal convergence primitive, not a user-facing workflow.
    Existing guest-key credentials are never inputs.
    """
    scope = _ensure_scope_dirs(vm_name, principal_id)
    with _ScopeLock(scope / 'lock'):
        records = list_agent_credentials(store, vm_name, principal_id)
        paths, expected = _validated_active_key_paths(records, manager=manager)
        if not paths:
            _stop_agent_locked(vm_name, principal_id, manager=manager)
            return inspect_agent(vm_name, principal_id, manager=manager)
        state = _start_agent_locked(vm_name, principal_id, manager=manager)
        live, result = _probe_agent(state, manager=manager)
        loaded = _parse_loaded_fingerprints(result) if live else ()
        if live and len(loaded) == len(expected) and set(loaded) == set(expected):
            return AgentStatus('running', state.pid, state.socket_path, loaded)
        env = _agent_env(state)
        with manager.step(
            f'Repair host-agent credentials for {vm_name}',
            why=(
                'The dedicated agent may contain only fresh host-agent '
                'credentials owned by this VM principal.'
            ),
            approval_scope=(
                f'agent-credentials:{agent_scope_id(vm_name, principal_id)}'
            ),
        ):
            manager.run(
                ['ssh-add', '-D'],
                sudo=False,
                role='modify',
                ownership='tool',
                check=True,
                capture=True,
                env=env,
                summary='Clear dedicated host-agent identities',
            )
            manager.run(
                ['ssh-add', *(str(path) for path in paths)],
                sudo=False,
                role='modify',
                ownership='tool',
                check=True,
                capture=True,
                env=env,
                summary='Load host-only repository deploy keys',
                detail=f'identities={len(paths)}',
            )
        live, result = _probe_agent(state, manager=manager)
        loaded = _parse_loaded_fingerprints(result) if live else ()
        if not live or len(loaded) != len(expected) or set(loaded) != set(expected):
            raise AIVMError(
                'Dedicated host-agent did not converge exactly: '
                f'expected={expected!r} loaded={loaded!r}'
            )
        return AgentStatus('running', state.pid, state.socket_path, loaded)


def grant_agent_credential(
    store: Store,
    store_path: Path,
    vm_name: str,
    principal_id: str,
    repo: GitRepository,
    *,
    access: str,
    kind: str,
    manager: CommandManager,
) -> AgentCredentialEntry:
    """Create or resume one independent host-only deploy-key grant."""
    principal = str(principal_id or '').strip()
    access = normalize_credential_access(access)
    cred_id = agent_credential_id(vm_name, repo.canonical, principal)
    _require_agent_tools(kind, manager=manager)
    scope = _ensure_scope_dirs(vm_name, principal)
    with _ScopeLock(scope / 'lock'):
        existing = find_agent_credential(
            store,
            vm_name,
            principal,
            credential_id=cred_id,
        )
        if existing is not None:
            if existing.state == AGENT_CREDENTIAL_STATE_REVOCATION_PENDING:
                raise AIVMError(
                    f'Agent credential {cred_id} is already being revoked; '
                    'finish with aivm vm agent_creds revoke before granting '
                    'this repository again.'
                )
            if existing.access != access:
                raise AIVMError(
                    f'Agent credential {cred_id} already has '
                    f'access={existing.access}; revoke it before changing access.'
                )
            if existing.kind != kind:
                raise AIVMError(
                    f'Agent credential {cred_id} already uses kind={existing.kind}; '
                    'revoke it before changing providers.'
                )
            record = existing
        else:
            record = AgentCredentialEntry(
                id=cred_id,
                vm_name=vm_name,
                principal_id=principal,
                kind=kind,
                provider_host=repo.host,
                owner=repo.owner,
                repository=repo.name,
                access=access,
                provider_key_title=_credential_title(vm_name, repo, cred_id),
                state=AGENT_CREDENTIAL_STATE_PENDING,
            )
            upsert_agent_credential(store, record)
            _save_agent_store(
                store,
                store_path,
                reason=(
                    f'Record pending host-agent credential {record.id} for '
                    f'VM {vm_name}.'
                ),
            )

        record = _ensure_keypair(record, manager=manager)
        upsert_agent_credential(store, record)
        _save_agent_store(
            store,
            store_path,
            reason=f'Record host-only key fingerprint for {record.id}.',
        )

        reason = providers.automation_unavailable_reason(
            kind, repo, manager=manager
        )
        if reason:
            raise AIVMError(
                'Host-agent credentials currently require automatic provider '
                f'publication. Pending credential {record.id} and its '
                f'host-only key were kept for safe retry. {reason}'
            )
        remote = _find_remote(record, manager=manager)
        if remote is None:
            remote = providers.add_deploy_key(
                kind,
                repo,
                public_key_path=public_key_path(record),
                title=record.provider_key_title,
                write=access == 'write',
                manager=manager,
            )
        expected_read_only = access != 'write'
        if remote.read_only != expected_read_only:
            raise AIVMError(
                f'Provider deploy key {remote.key_id} has the wrong access '
                f'mode for agent credential {record.id}; expected {access}.'
            )
        if _provider_fingerprint(remote) != record.key_fingerprint:
            raise AIVMError(
                f'Provider returned key material that does not match agent '
                f'credential {record.id}.'
            )
        record = replace(
            record,
            provider_key_id=remote.key_id,
            state=AGENT_CREDENTIAL_STATE_ACTIVE,
        )
        upsert_agent_credential(store, record)
        _save_agent_store(
            store,
            store_path,
            reason=f'Activate host-agent credential {record.id}.',
        )
    ensure_agent_state(store, vm_name, principal, manager=manager)
    return record


def revoke_agent_credential(
    store: Store,
    store_path: Path,
    record: AgentCredentialEntry,
    *,
    manager: CommandManager,
) -> None:
    """Revoke provider authority before deleting host-only key material."""
    _require_agent_tools(record.kind, manager=manager)
    scope = _ensure_scope_dirs(record.vm_name, record.principal_id)
    with _ScopeLock(scope / 'lock'):
        current = find_agent_credential(
            store,
            record.vm_name,
            record.principal_id,
            credential_id=record.id,
        )
        if current is None:
            raise AIVMError(f'Agent credential not found: {record.id}')
        _, actual = _inspect_keypair(current, manager=manager)
        if actual != current.key_fingerprint:
            raise AIVMError(
                f'Agent credential {current.id} key material has drifted; '
                'refusing provider deletion.'
            )
        providers.check_auth(current.kind, agent_repository(current), manager=manager)
        remote = _find_remote(current, manager=manager)
        if remote is not None:
            providers.delete_deploy_key(
                current.kind,
                agent_repository(current),
                remote.key_id,
                manager=manager,
            )
            if _find_remote(current, manager=manager) is not None:
                raise AIVMError(
                    f'Provider still reports deploy key for {current.id} after '
                    'deletion; refusing local cleanup.'
                )
        current = replace(
            current,
            state=AGENT_CREDENTIAL_STATE_REVOCATION_PENDING,
        )
        upsert_agent_credential(store, current)
        _save_agent_store(
            store,
            store_path,
            reason=(
                f'Record provider revocation for host-agent credential '
                f'{current.id} before local cleanup.'
            ),
        )

    # Once provider authority is gone, make a best effort to remove the key
    # from the live agent before erasing its disk copy. A failure is safe to
    # retry because the provider no longer accepts the identity.
    ensure_agent_state(store, record.vm_name, record.principal_id, manager=manager)

    with _ScopeLock(scope / 'lock'):
        _remove_key_tree(current)
        remove_agent_credential(
            store,
            vm_name=current.vm_name,
            principal_id=current.principal_id,
            credential_id=current.id,
        )
        _save_agent_store(
            store,
            store_path,
            reason=f'Remove revoked host-agent credential {current.id}.',
        )
    ensure_agent_state(store, record.vm_name, record.principal_id, manager=manager)


def inspect_doctor(
    store: Store,
    vm_name: str,
    principal_id: str,
    *,
    guest_key_fingerprints: Iterable[str] = (),
    manager: CommandManager,
) -> DoctorReport:
    """Read-only local diagnostics for this independent credential system."""
    records = list_agent_credentials(store, vm_name, principal_id)
    issues: list[DoctorIssue] = []
    active_fingerprints: list[str] = []
    all_fingerprints: list[str] = []
    for record in records:
        if record.state == AGENT_CREDENTIAL_STATE_PENDING:
            issues.append(
                DoctorIssue(
                    'pending-grant',
                    f'{record.id} for {agent_repository(record).display} is pending; rerun '
                    '`aivm vm agent_creds add` to finish provider authority.',
                    False,
                )
            )
        elif record.state == AGENT_CREDENTIAL_STATE_REVOCATION_PENDING:
            issues.append(
                DoctorIssue(
                    'pending-revocation',
                    f'{record.id} for {agent_repository(record).display} is in a partial '
                    'revocation state; rerun `aivm vm agent_creds revoke`.',
                    False,
                )
            )
        try:
            _, actual = _inspect_keypair(record, manager=manager)
        except (AIVMError, FileNotFoundError, OSError) as ex:
            issues.append(DoctorIssue('key-material', str(ex), False))
            continue
        if record.key_fingerprint != actual:
            issues.append(
                DoctorIssue(
                    'fingerprint-drift',
                    f'{record.id} records {record.key_fingerprint!r} but host '
                    f'key material is {actual!r}.',
                    False,
                )
            )
            continue
        all_fingerprints.append(actual)
        if record.state == AGENT_CREDENTIAL_STATE_ACTIVE:
            active_fingerprints.append(actual)

    duplicates = sorted(
        fingerprint
        for fingerprint in set(all_fingerprints)
        if all_fingerprints.count(fingerprint) > 1
    )
    for fingerprint in duplicates:
        issues.append(
            DoctorIssue(
                'duplicate-agent-key',
                f'Multiple host-agent records use identity {fingerprint}; '
                'fresh grants must never share private key material.',
                False,
            )
        )

    collisions = sorted(set(all_fingerprints) & set(guest_key_fingerprints))
    for fingerprint in collisions:
        issues.append(
            DoctorIssue(
                'guest-key-collision',
                f'Host-agent identity {fingerprint} is also recorded by the '
                'guest-key subsystem. This violates the non-exportable-key '
                'invariant and requires explicit credential replacement.',
                False,
            )
        )

    agent_status = inspect_agent(vm_name, principal_id, manager=manager)
    expected = tuple(active_fingerprints)
    if expected:
        if agent_status.runtime_state != 'running':
            issues.append(
                DoctorIssue(
                    'agent-not-running',
                    f'Dedicated agent is {agent_status.runtime_state}; active '
                    'host-agent credentials exist.',
                    not (
                        agent_status.runtime_state == 'stale'
                        and agent_status.pid is None
                    ),
                )
            )
        elif (
            len(agent_status.loaded_fingerprints) != len(expected)
            or set(agent_status.loaded_fingerprints) != set(expected)
        ):
            issues.append(
                DoctorIssue(
                    'agent-identities',
                    'Dedicated agent identities do not exactly match active '
                    'host-agent credential records.',
                    True,
                )
            )
    elif agent_status.runtime_state != 'stopped':
        issues.append(
            DoctorIssue(
                'unused-agent',
                f'Dedicated agent is {agent_status.runtime_state} but this '
                'scope has no active host-agent credentials.',
                not (
                    agent_status.runtime_state == 'stale'
                    and agent_status.pid is None
                ),
            )
        )

    return DoctorReport(
        vm_name=vm_name,
        principal_id=principal_id,
        records=records,
        agent=agent_status,
        issues=tuple(issues),
    )


def fix_doctor(
    store: Store,
    vm_name: str,
    principal_id: str,
    *,
    guest_key_fingerprints: Iterable[str] = (),
    manager: CommandManager,
) -> DoctorReport:
    """Repair only derived local agent state; never change provider authority."""
    before = inspect_doctor(
        store,
        vm_name,
        principal_id,
        guest_key_fingerprints=guest_key_fingerprints,
        manager=manager,
    )
    blockers = [issue for issue in before.issues if not issue.fixable]
    if blockers:
        details = '\n'.join(f'  - {issue.detail}' for issue in blockers)
        raise AIVMError(
            'Host-agent credential doctor found issue(s) that --fix must not '
            f'change automatically:\n{details}'
        )
    ensure_agent_state(store, vm_name, principal_id, manager=manager)
    return inspect_doctor(
        store,
        vm_name,
        principal_id,
        guest_key_fingerprints=guest_key_fingerprints,
        manager=manager,
    )
