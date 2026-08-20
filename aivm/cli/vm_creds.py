"""Principal-scoped repository credential commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import kwconf

from ..commands import CommandManager
from ..config_scopes import ResolvedVMContext
from ..config_store import (
    AgentCredentialEntry,
    CredentialEntry,
    Store,
    find_credential,
    find_credentials_for_vm,
    set_vm_credential_backend,
)
from ..credentials import agent, providers
from ..credentials.agent_transport import (
    AgentGrantForwardingReadiness,
    prepare_agent_grant_forwarding,
)
from ..credential_backends import (
    CREDENTIAL_BACKEND_GUEST_KEY,
    CREDENTIAL_BACKEND_SSH_AGENT,
    DEFAULT_CREDENTIAL_BACKEND,
    CredentialBackend,
    CredentialBackendResolution,
    normalize_credential_backend,
    resolve_credential_backend,
)
from ..credentials.plan import (
    CredentialPlanEntry,
    discover_credential_candidates,
    parse_credential_plan_document,
    render_credential_plan,
    repository_root,
)
from ..credentials.gitlab import host_token_envvar
from ..credentials.models import GitRepository
from ..credentials.ownership import credential_principal_label
from ..credentials.resolve import resolve_repository
from ..credentials.schema import CredentialKind, normalize_credential_access
from ..credentials.service import (
    abandon_repository_credential,
    describe_unregistered_credential,
    entry_repository,
    grant_repository_credential,
    inspect_credential,
    revoke_repository_credential,
)
from ..credentials.setup import (
    CREDENTIAL_TOOLS,
    GITLAB_CREDENTIAL_TOOLS,
    CredentialSetupReport,
    GitLabCredentialSetupReport,
    authenticate_github,
    inspect_credential_setup,
    inspect_gitlab_credential_setup,
    install_missing_credential_tools,
)
from ..credentials.validation import (
    CredentialValidationError,
    credential_id,
    validate_provider_host,
)
from ..errors import AIVMError, CommandControlError
from ..scoped_store import (
    load_scope_profile,
    load_scope_store,
    resolve_store_scope,
    save_scope_store,
)
from ..services import load_vm_context_with_path
from ..profile_store import save_user_profile
from ._common import _BaseCommand


BackendOption = Literal['auto', 'guest-key', 'ssh-agent']


@dataclass(frozen=True)
class _SelectedCredential:
    backend: CredentialBackend
    entry: CredentialEntry | AgentCredentialEntry


def _load_credential_context(
    config_opt: str | None,
    *,
    vm_opt: str,
    persist_runtime_defaults: bool,
    host_src: Path | None = None,
) -> tuple[ResolvedVMContext, Store, Path, str]:
    """Load the caller context plus the matching physical credential store."""
    context, store_path = load_vm_context_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=host_src or Path.cwd(),
        persist_runtime_defaults=persist_runtime_defaults,
    )
    scope = resolve_store_scope(str(store_path))
    store = load_scope_store(scope)
    principal_id = context.principal.id if scope.is_machine else ''
    return context, store, store_path, principal_id


def _creation_backend(
    context: ResolvedVMContext,
    requested: object,
) -> CredentialBackendResolution:
    """Resolve one new grant through explicit, VM, user, then fallback policy."""
    return resolve_credential_backend(
        requested,
        vm_preference=context.machine.vm.credential_backend,
        user_preference=context.profile.credential_backend,
    )


def _guest_key_fingerprints(
    store: Store, *, vm_name: str, principal_id: str
) -> tuple[str, ...]:
    """Return guest-key fingerprints for ssh-agent collision diagnostics."""
    return tuple(
        entry.key_fingerprint
        for entry in find_credentials_for_vm(
            store,
            vm_name,
            principal_id=principal_id,
        )
        if entry.key_fingerprint
    )


def _agent_records(
    store: Store,
    *,
    vm_name: str,
    principal_id: str | None,
) -> list[AgentCredentialEntry]:
    records = [item for item in store.agent_credentials if item.vm_name == vm_name]
    if principal_id is not None:
        records = [item for item in records if item.principal_id == principal_id]
    return sorted(records, key=lambda item: (item.principal_id, item.id))


def _agent_matches(
    store: Store,
    *,
    vm_name: str,
    principal_id: str | None,
    credential_id_text: str = '',
    repo: GitRepository | None = None,
) -> list[AgentCredentialEntry]:
    records = _agent_records(
        store,
        vm_name=vm_name,
        principal_id=principal_id,
    )
    if credential_id_text:
        return [item for item in records if item.id == credential_id_text]
    if repo is None:
        return []
    return [
        item
        for item in records
        if item.provider_host.lower() == repo.host.lower()
        and item.owner.lower() == repo.owner.lower()
        and item.repository.lower() == repo.name.lower()
    ]


def _resolve_guest_selector(
    store: Store,
    *,
    vm_name: str,
    selector: str,
    repo: GitRepository | None,
    principal_id: str | None,
) -> CredentialEntry | None:
    exact = find_credential(
        store,
        vm_name=vm_name,
        credential_id=selector,
        principal_id=principal_id,
    )
    if exact is not None:
        return exact
    if repo is None:
        return None
    matches = [
        item
        for item in find_credentials_for_vm(
            store, vm_name, principal_id=principal_id
        )
        if item.provider_host.lower() == repo.host.lower()
        and item.owner.lower() == repo.owner.lower()
        and item.repository.lower() == repo.name.lower()
    ]
    if len(matches) > 1:
        owners = ', '.join(
            sorted(item.principal_id or 'legacy' for item in matches)
        )
        raise AIVMError(
            f'Multiple principal guest-key credentials match {repo.display!r} '
            f'on VM {vm_name!r}: {owners}. Use an exact credential id.'
        )
    return matches[0] if matches else None


def _resolve_existing_credential(
    store: Store,
    *,
    vm_name: str,
    selector: str,
    remote: str,
    manager: CommandManager,
    principal_id: str | None,
    backend: object = 'auto',
) -> _SelectedCredential:
    """Resolve an existing credential across both independent backend stores."""
    requested = normalize_credential_backend(backend)
    enabled = (
        (CREDENTIAL_BACKEND_GUEST_KEY, CREDENTIAL_BACKEND_SSH_AGENT)
        if requested == 'auto'
        else (requested,)
    )

    exact: list[_SelectedCredential] = []
    if CREDENTIAL_BACKEND_GUEST_KEY in enabled:
        guest = find_credential(
            store,
            vm_name=vm_name,
            credential_id=selector,
            principal_id=principal_id,
        )
        if guest is not None:
            exact.append(_SelectedCredential(CREDENTIAL_BACKEND_GUEST_KEY, guest))
    if CREDENTIAL_BACKEND_SSH_AGENT in enabled:
        exact.extend(
            _SelectedCredential(CREDENTIAL_BACKEND_SSH_AGENT, item)
            for item in _agent_matches(
                store,
                vm_name=vm_name,
                principal_id=principal_id,
                credential_id_text=selector,
            )
        )
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise AIVMError(
            f'Credential id {selector!r} is ambiguous across backends; '
            'specify --backend guest-key or --backend ssh-agent.'
        )

    repo = resolve_repository(selector, remote=remote, manager=manager)
    matches: list[_SelectedCredential] = []
    if CREDENTIAL_BACKEND_GUEST_KEY in enabled:
        guest = _resolve_guest_selector(
            store,
            vm_name=vm_name,
            selector=selector,
            repo=repo,
            principal_id=principal_id,
        )
        if guest is not None:
            matches.append(_SelectedCredential(CREDENTIAL_BACKEND_GUEST_KEY, guest))
    if CREDENTIAL_BACKEND_SSH_AGENT in enabled:
        matches.extend(
            _SelectedCredential(CREDENTIAL_BACKEND_SSH_AGENT, item)
            for item in _agent_matches(
                store,
                vm_name=vm_name,
                principal_id=principal_id,
                repo=repo,
            )
        )
    if not matches:
        requested_text = '' if requested == 'auto' else f' in backend {requested}'
        raise AIVMError(
            f'Credential not found for {repo.display} on VM {vm_name!r}'
            f'{requested_text}.'
        )
    if len(matches) > 1:
        choices = ', '.join(f'{item.backend}:{item.entry.id}' for item in matches)
        raise AIVMError(
            f'Multiple credentials match {repo.display}: {choices}. '
            'Select a credential id or specify --backend.'
        )
    return matches[0]


def _resolve_credential_selector(
    store: Store,
    *,
    vm_name: str,
    selector: str,
    remote: str,
    manager: CommandManager,
    principal_id: str | None = None,
) -> CredentialEntry:
    """Resolve one guest-key credential through the unified selector path.

    This helper predates the multi-backend frontend and remains as a narrow
    compatibility seam for callers that explicitly operate on the guest-key
    store.  New frontend code should use :func:`_resolve_existing_credential`
    so ``auto`` can inspect both independent backends.
    """
    selected = _resolve_existing_credential(
        store,
        vm_name=vm_name,
        selector=selector,
        remote=remote,
        manager=manager,
        principal_id=principal_id,
        backend=CREDENTIAL_BACKEND_GUEST_KEY,
    )
    entry = selected.entry
    if not isinstance(entry, CredentialEntry):
        raise AssertionError(
            'guest-key selector resolved a non-guest credential entry'
        )
    return entry


def _resolve_plan_entries(
    entries: list[CredentialPlanEntry],
    *,
    root: Path,
    manager: CommandManager,
) -> list[tuple[CredentialPlanEntry, GitRepository, CredentialKind]]:
    """Resolve every plan entry before any credential mutation begins."""
    resolved: list[tuple[CredentialPlanEntry, GitRepository, CredentialKind]] = []
    seen_repositories: dict[str, str] = {}
    for entry in entries:
        checkout = (root / entry.path).resolve()
        try:
            checkout.relative_to(root)
        except ValueError as ex:
            raise AIVMError(
                f'Credential plan path escapes repository root: {entry.path!r}'
            ) from ex
        if not checkout.is_dir():
            raise AIVMError(
                f'Credential plan checkout does not exist: {entry.path!r}'
            )
        repo = resolve_repository(
            checkout,
            remote=entry.remote,
            default_host=(
                'gitlab.com' if entry.provider == 'gitlab' else 'github.com'
            ),
            manager=manager,
        )
        prior_path = seen_repositories.get(repo.canonical)
        if prior_path is not None:
            raise AIVMError(
                f'Credential plan paths {prior_path!r} and {entry.path!r} '
                f'resolve to the same repository {repo.display}; keep one '
                'grant line for that repository.'
            )
        seen_repositories[repo.canonical] = entry.path
        resolved_provider = providers.resolve_provider(repo, entry.provider)
        kind = providers.kind_for_provider(resolved_provider)
        resolved.append((entry, repo, kind))
    return resolved


def _grant_repository(
    *,
    backend: CredentialBackend,
    context: ResolvedVMContext,
    store: Store,
    store_path: Path,
    principal_id: str,
    repo: GitRepository,
    access: str,
    kind: CredentialKind,
    manager: CommandManager,
) -> CredentialEntry | AgentCredentialEntry:
    if backend == CREDENTIAL_BACKEND_SSH_AGENT:
        return agent.grant_agent_credential(
            store,
            store_path,
            context.effective_cfg.vm.name,
            principal_id,
            repo,
            access=access,
            kind=kind,
            manager=manager,
        )
    return grant_repository_credential(
        context.effective_cfg,
        store,
        store_path,
        repo,
        access=access,
        kind=kind,
        principal_id=principal_id,
        manager=manager,
    )


def _agent_grant_activation_error(
    entry: AgentCredentialEntry, error: BaseException
) -> str:
    return (
        f'SSH-agent credential {entry.id} is active and its private key is '
        'loaded in the dedicated host agent, but AIVM could not verify guest '
        f'activation: {error} Existing guest sessions are unchanged. '
        'Reconnect with `aivm vm ssh` or `aivm vm code`; managed session '
        'preparation will retry public routing and agent-forwarding verification.'
    )


def _print_agent_grant_readiness(
    readiness: AgentGrantForwardingReadiness,
) -> None:
    print('Private key remains host-only in the dedicated AIVM ssh-agent.')
    if readiness.verified:
        assert readiness.forwarding is not None
        print(
            'Guest routing and dedicated-agent repository authentication '
            f'preflight passed on {readiness.ip} '
            f'({readiness.forwarding.credential_count} active credential(s)).'
        )
    else:
        print(f'Guest activation deferred: {readiness.deferred_reason}')
        print(
            'AIVM will reconcile guest routing and verify forwarding on the '
            'next managed SSH/Remote-SSH session.'
        )
    print('Existing guest sessions do not acquire new agent forwarding.')
    print('Reconnect with `aivm vm ssh` or `aivm vm code` to use this credential.')


class VMCredsPreferenceCLI(_BaseCommand):
    """Inspect or set the credential backend preference."""

    backend: str = kwconf.Value(
        '',
        position=1,
        help=(
            'Preference to set: auto, guest-key, or ssh-agent. Omit to show '
            'the current preference hierarchy without changing it.'
        ),
    )
    scope: Literal['vm', 'user'] = kwconf.Value(
        'vm',
        help='Preference scope to change when BACKEND is provided (default: vm).',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, _store_path, _principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=False,
        )
        physical_scope = resolve_store_scope(args.config)
        vm_name = context.effective_cfg.vm.name
        vm_preference = context.machine.vm.credential_backend
        user_preference = context.profile.credential_backend

        requested = str(args.backend or '').strip()
        if requested:
            preference = normalize_credential_backend(requested)
            if args.scope == 'user':
                if not physical_scope.is_machine:
                    raise AIVMError(
                        'User-level credential backend preferences require the '
                        'machine-store/profile architecture. Use a VM preference '
                        'or an explicit --backend with this legacy store.'
                    )
                profile = load_scope_profile(physical_scope)
                profile.credential_backend = preference
                save_user_profile(profile, physical_scope.profile_path)
                user_preference = preference
                print(
                    f'Set user credential backend preference to {preference}.'
                )
            else:
                set_vm_credential_backend(store, vm_name, preference)
                save_scope_store(
                    physical_scope,
                    store,
                    reason=(
                        f'Set credential backend preference for VM {vm_name} '
                        f'to {preference}.'
                    ),
                )
                vm_preference = preference
                print(
                    f'Set VM {vm_name} credential backend preference to '
                    f'{preference}.'
                )

        resolved = resolve_credential_backend(
            'auto',
            vm_preference=vm_preference,
            user_preference=user_preference,
        )
        print('Credential backend preference')
        print(f'  VM:        {vm_name}')
        print(f'  VM scope:  {vm_preference}')
        if physical_scope.is_machine:
            print(f'  User scope: {user_preference}')
        else:
            print('  User scope: unavailable (legacy store)')
        print(f'  Fallback:  {DEFAULT_CREDENTIAL_BACKEND}')
        print(f'  Effective: {resolved.backend} ({resolved.source})')
        return 0


class VMCredsPlanCLI(_BaseCommand):
    """Discover candidate checkout credentials and print an editable plan."""

    repository: str = kwconf.Value(
        '.',
        position=1,
        help='Checkout to crawl for initialized submodules (default: .).',
    )
    access: Literal['read', 'ro', 'write', 'rw'] = kwconf.Value(
        'read', help='Initial access written into every candidate line.'
    )
    provider: Literal['auto', 'github', 'gitlab'] = kwconf.Value(
        'auto', help='Initial provider written into every candidate line.'
    )
    backend: BackendOption = kwconf.Value(
        'auto',
        help='Credential backend written into each row: auto, guest-key, or ssh-agent.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        mgr = CommandManager.current()
        root, candidates = discover_credential_candidates(
            Path(args.repository).expanduser(),
            access=args.access,
            provider=args.provider,
            backend=args.backend,
            manager=mgr,
        )
        print(render_credential_plan(candidates, root=root), end='')
        return 0


class VMCredsApplyCLI(_BaseCommand):
    """Validate and apply an edited multi-repository credential plan."""

    plan_file: str = kwconf.Value(
        '', position=1, help='Credential plan file produced by `vm creds plan`.'
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Validate and print all grants without changing credentials.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.plan_file:
            raise AIVMError('Provide a credential plan file to apply.')
        plan_path = Path(args.plan_file).expanduser()
        try:
            text = plan_path.read_text(encoding='utf-8')
        except OSError as ex:
            raise AIVMError(f'Could not read credential plan {plan_path}: {ex}') from ex

        document = parse_credential_plan_document(text)
        entries = list(document.entries)
        mgr = CommandManager.current()
        root = repository_root(document.root, manager=mgr)
        resolved = _resolve_plan_entries(entries, root=root, manager=mgr)
        context, store, store_path, principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=not args.dry_run,
            host_src=root,
        )

        rows = [
            (entry, repo, kind, _creation_backend(context, entry.backend))
            for entry, repo, kind in resolved
        ]
        print(f'Credential plan: {len(rows)} repository grant(s)')
        for entry, repo, kind, choice in rows:
            print(
                f'  {entry.path}: {entry.access} {entry.remote} '
                f'{providers.provider_for_kind(kind)} {repo.display} '
                f'backend={choice.backend} ({choice.source})'
            )
        if args.dry_run:
            print('DRYRUN: no credential state was changed.')
            return 0

        for entry, repo, kind, choice in rows:
            with mgr.intent(
                f'Grant {context.effective_cfg.vm.name} access to {repo.display}',
                why=(
                    f'Apply one reviewed credential-plan row using the '
                    f'{choice.backend} backend.'
                ),
                role='modify',
            ):
                granted = _grant_repository(
                    backend=choice.backend,
                    context=context,
                    store=store,
                    store_path=store_path,
                    principal_id=principal_id,
                    repo=repo,
                    access=entry.access,
                    kind=kind,
                    manager=mgr,
                )
            if isinstance(granted, CredentialEntry) and not granted.provider_managed:
                print(describe_unregistered_credential(granted, repo))
            else:
                print(
                    f'Granted {granted.access} access: repository={repo.display} '
                    f'credential={granted.id} backend={choice.backend}'
                )
        return 0


class VMCredsAddCLI(_BaseCommand):
    """Grant a VM repository access for the current principal."""

    repository: str = kwconf.Value(
        '.',
        position=1,
        help='Local checkout, OWNER/REPO, or Git SSH/HTTPS URL (default: .).',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used when resolving a local checkout.'
    )
    provider: Literal['auto', 'github', 'gitlab'] = kwconf.Value(
        'auto',
        help=(
            'Deploy-key provider. auto selects GitLab for gitlab.com and '
            'GitHub otherwise; specify gitlab for a self-managed GitLab host.'
        ),
    )
    backend: BackendOption = kwconf.Value(
        'auto',
        help=(
            'Credential backend. auto resolves VM preference, then user '
            'preference, then the package fallback (currently guest-key).'
        ),
    )
    access: Literal['read', 'ro', 'write', 'rw'] = kwconf.Value(
        'read',
        help=(
            'Credential access: read (ro) or write (rw); default read. '
            'Changing access requires revoking that backend credential first.'
        ),
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Print the grant without creating or installing a key.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, store_path, principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=not args.dry_run,
        )
        cfg = context.effective_cfg
        choice = _creation_backend(context, args.backend)
        mgr = CommandManager.current()
        requested_provider = providers.normalize_provider(args.provider)
        default_host = 'gitlab.com' if requested_provider == 'gitlab' else 'github.com'
        repo = resolve_repository(
            args.repository,
            remote=args.remote,
            default_host=default_host,
            manager=mgr,
        )
        resolved_provider = providers.resolve_provider(repo, requested_provider)
        kind = providers.kind_for_provider(resolved_provider)
        access = normalize_credential_access(args.access)
        cred_id = (
            agent.agent_credential_id(cfg.vm.name, repo.canonical, principal_id)
            if choice.backend == CREDENTIAL_BACKEND_SSH_AGENT
            else credential_id(cfg.vm.name, repo.canonical, principal_id)
        )
        if args.dry_run:
            print('Repository credential grant')
            print(f'  VM:          {cfg.vm.name}')
            print(f'  Principal:   {principal_id or "legacy"}')
            print(f'  Repository:  {repo.display}')
            print(f'  Access:      {access}')
            print(f'  Provider:    {resolved_provider}')
            print(f'  Backend:     {choice.backend} ({choice.source})')
            print(f'  Credential:  {cred_id}')
            if choice.backend == CREDENTIAL_BACKEND_SSH_AGENT:
                print('  Private key: host-only; reached through a dedicated ssh-agent')
            else:
                print('  Private key: copied into the selected guest principal home')
            print('DRYRUN: no key, provider setting, guest file, or config was changed.')
            return 0

        agent_readiness: AgentGrantForwardingReadiness | None = None
        with mgr.intent(
            f'Grant {cfg.vm.name} access to {repo.display}',
            why=f'Create repository authority using the {choice.backend} backend.',
            role='modify',
        ):
            entry = _grant_repository(
                backend=choice.backend,
                context=context,
                store=store,
                store_path=store_path,
                principal_id=principal_id,
                repo=repo,
                access=access,
                kind=kind,
                manager=mgr,
            )
            if isinstance(entry, AgentCredentialEntry):
                try:
                    agent_readiness = prepare_agent_grant_forwarding(
                        context,
                        store_path,
                        credential_id=entry.id,
                        manager=mgr,
                    )
                except CommandControlError as ex:
                    raise type(ex)(_agent_grant_activation_error(entry, ex)) from ex
                except AIVMError as ex:
                    raise AIVMError(_agent_grant_activation_error(entry, ex)) from ex
        if isinstance(entry, CredentialEntry) and not entry.provider_managed:
            print(describe_unregistered_credential(entry, repo))
            return 0
        print(
            f'Granted {entry.access} access: vm={entry.vm_name} '
            f'principal={entry.principal_id or "legacy"} repository={repo.display} '
            f'credential={entry.id} backend={choice.backend}'
        )
        if choice.backend == CREDENTIAL_BACKEND_SSH_AGENT:
            assert agent_readiness is not None
            _print_agent_grant_readiness(agent_readiness)
        return 0


def _print_setup_report(report: CredentialSetupReport) -> None:
    """Render GitHub host readiness without exposing command internals."""
    print('GitHub credential setup')
    print(f'  GitHub host:       {report.hostname}')
    for name in CREDENTIAL_TOOLS:
        path = report.tool_paths.get(name)
        print(f'  {name:<18} {"ready" if path else "missing"}')
    if report.tool_paths.get('gh'):
        print(f'  gh version:        {report.gh_detail}')
    auth = 'ready' if report.auth_ok else 'not ready'
    print(f'  Authentication:    {auth}')
    if report.auth_detail and not report.auth_ok:
        print(f'  Auth detail:       {report.auth_detail}')
    if report.repository is not None:
        if report.repository_ok is True:
            repo_state = 'ready'
        elif report.repository_ok is False:
            repo_state = 'not ready'
        else:
            repo_state = 'not checked'
        print(f'  Repository:        {report.repository.display}')
        print(f'  Repository admin:  {repo_state}')
        if report.repository_detail and report.repository_ok is not True:
            print(f'  Repository detail: {report.repository_detail}')


def _print_gitlab_setup_report(report: GitLabCredentialSetupReport) -> None:
    """Render GitLab host readiness without exposing the API token."""
    print('GitLab credential setup')
    print(f'  GitLab host:       {report.hostname}')
    for name in GITLAB_CREDENTIAL_TOOLS:
        path = report.tool_paths.get(name)
        print(f'  {name:<18} {"ready" if path else "missing"}')
    auth = 'ready' if report.auth_ok else 'not ready'
    print(f'  Authentication:    {auth}')
    if report.identity:
        print(f'  Identity:          {report.identity}')
    if report.auth_detail and not report.auth_ok:
        print(f'  Auth detail:       {report.auth_detail}')
    if report.repository is not None:
        if report.repository_ok is True:
            repo_state = 'ready'
        elif report.repository_ok is False:
            repo_state = 'not ready'
        else:
            repo_state = 'not checked'
        print(f'  Repository:        {report.repository.display}')
        print(f'  Deploy-key API:    {repo_state}')
        if report.repository_detail and report.repository_ok is not True:
            print(f'  Repository detail: {report.repository_detail}')


def _gitlab_token_hint(hostname: str) -> str:
    """Name the token variables that actually apply to this host.

    A GitLab token only works on the server that issued it, so telling
    everyone to ``set GITLAB_TOKEN`` is wrong advice for a second instance.
    """
    scoped = host_token_envvar(hostname)
    if scoped == 'GITLAB_TOKEN':
        return 'GITLAB_TOKEN'
    return f'{scoped} (or GITLAB_TOKEN)'


def _run_gitlab_setup(
    *,
    args: Any,
    hostname: str,
    repo: Any,
    manager: CommandManager,
) -> int:
    report = inspect_gitlab_credential_setup(
        hostname=hostname,
        repository=repo,
        manager=manager,
    )
    _print_gitlab_setup_report(report)
    if args.check:
        if not report.ready:
            print(
                f'  Remedy:            set {_gitlab_token_hint(hostname)} and '
                'run `aivm vm creds setup --provider gitlab`'
            )
        return 0 if report.ready else 2

    if args.dry_run:
        if report.missing_tools:
            print(
                'DRYRUN: would install missing host command(s): '
                + ', '.join(report.missing_tools)
            )
        if not report.auth_ok:
            print(
                'DRYRUN: would require a valid '
                f'{_gitlab_token_hint(hostname)} on the AIVM host.'
            )
        if repo is not None:
            print(
                'DRYRUN: would verify deploy-key API access for '
                f'{repo.display}.'
            )
        if report.ready:
            print('DRYRUN: no setup changes are needed.')
        return 0

    if report.ready:
        print('Host credential prerequisites are ready; no changes needed.')
        return 0

    if report.missing_tools:
        install_missing_credential_tools(
            report.missing_tools,
            provider_label='GitLab',
            manager=manager,
        )

    final = inspect_gitlab_credential_setup(
        hostname=hostname,
        repository=repo,
        manager=manager,
    )
    print()
    _print_gitlab_setup_report(final)
    if not final.ready:
        if not final.auth_ok:
            print(
                '  Remedy:            export '
                f'{host_token_envvar(hostname)}=<api-token>; for a custom API '
                'endpoint also set GITLAB_API_URL (https only).'
            )
        else:
            print(
                '  Remedy:            grant the token owner sufficient project '
                'access and rerun setup.'
            )
        return 2
    print('Host credential prerequisites are ready.')
    return 0


class VMCredsSetupCLI(_BaseCommand):
    """Prepare host tools and forge authentication for repository credentials."""

    repository: str = kwconf.Value(
        '',
        position=1,
        help=(
            'Optional local checkout, repository path, or Git URL whose '
            'deploy-key administration should also be checked.'
        ),
    )
    hostname: str = kwconf.Value(
        'github.com',
        help=(
            'Forge hostname when no repository is given. With '
            '--provider=gitlab, the unchanged default becomes gitlab.com.'
        ),
    )
    provider: Literal['auto', 'github', 'gitlab'] = kwconf.Value(
        'auto',
        help=(
            'Credential provider. auto selects GitLab for gitlab.com and '
            'GitHub otherwise.'
        ),
    )
    remote: str = kwconf.Value(
        'origin', help='Git remote used when resolving a local checkout.'
    )
    check: bool = kwconf.Flag(
        False,
        help='Only check readiness; do not install tools or authenticate.',
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Print the setup actions without changing the host.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.check and args.dry_run:
            raise AIVMError('Use either --check or --dry_run, not both.')
        mgr = CommandManager.current()
        repo = None
        requested_provider = providers.normalize_provider(args.provider)
        default_host = (
            'gitlab.com' if requested_provider == 'gitlab' else 'github.com'
        )
        if args.repository:
            repo = resolve_repository(
                args.repository,
                remote=args.remote,
                default_host=default_host,
                manager=mgr,
            )
        raw_hostname = args.hostname or 'github.com'
        if repo is not None:
            raw_hostname = repo.host
        elif requested_provider == 'gitlab' and raw_hostname == 'github.com':
            raw_hostname = 'gitlab.com'
        try:
            hostname = validate_provider_host(raw_hostname)
        except CredentialValidationError as ex:
            raise AIVMError(str(ex)) from ex
        resolved_provider = providers.resolve_provider(
            repo,
            requested_provider,
            hostname=hostname,
        )

        if resolved_provider == 'gitlab':
            return _run_gitlab_setup(
                args=args,
                hostname=hostname,
                repo=repo,
                manager=mgr,
            )

        report = inspect_credential_setup(
            hostname=hostname,
            repository=repo,
            manager=mgr,
        )
        _print_setup_report(report)
        if args.check:
            if not report.ready:
                print('  Remedy:            aivm vm creds setup')
            return 0 if report.ready else 2

        if args.dry_run:
            if report.missing_tools:
                print(
                    'DRYRUN: would install missing host command(s): '
                    + ', '.join(report.missing_tools)
                )
            if report.tool_paths.get('gh') and not report.gh_supported:
                print(
                    'DRYRUN: would replace the installed GitHub CLI '
                    f'({report.gh_detail}) from its official repository.'
                )
            if not report.auth_ok:
                print(f'DRYRUN: would authenticate gh for {hostname}.')
            if repo is not None:
                print(
                    'DRYRUN: would verify deploy-key administration for '
                    f'{repo.display}.'
                )
            if report.ready:
                print('DRYRUN: no setup changes are needed.')
            return 0

        if report.ready:
            print('Host credential prerequisites are ready; no changes needed.')
            return 0
        if (
            not report.missing_tools
            and report.auth_ok
            and report.repository_ok is False
        ):
            print(
                '  Remedy:            grant repository administration access.'
            )
            return 2

        needs_gh_upgrade = bool(
            report.tool_paths.get('gh') and not report.gh_supported
        )
        if report.missing_tools or needs_gh_upgrade:
            install_missing_credential_tools(
                report.missing_tools,
                upgrade_gh=needs_gh_upgrade,
                manager=mgr,
            )
        refreshed = inspect_credential_setup(
            hostname=hostname,
            repository=None,
            manager=mgr,
        )
        if refreshed.missing_tools:
            raise AIVMError(
                'Credential tool installation completed, but command(s) are '
                'still unavailable: ' + ', '.join(refreshed.missing_tools)
            )
        if not refreshed.gh_supported:
            raise AIVMError(refreshed.auth_detail)
        if not refreshed.auth_ok:
            authenticate_github(
                hostname, manager=mgr, version=refreshed.gh_version
            )

        final = inspect_credential_setup(
            hostname=hostname,
            repository=repo,
            manager=mgr,
        )
        print()
        _print_setup_report(final)
        if not final.ready:
            print(
                '  Remedy:            resolve the item above and rerun setup.'
            )
            return 2
        print('Host credential prerequisites are ready.')
        return 0


class VMCredsListCLI(_BaseCommand):
    """List repository credentials visible to the current principal."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    all_principals: bool = kwconf.Flag(
        False,
        help=(
            'Show machine-wide credential metadata for every principal. '
            'Private key material remains accessible only to its owner.'
        ),
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, _store_path, principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=False,
        )
        vm_name = context.effective_cfg.vm.name
        selected_principal = None if args.all_principals else principal_id
        guest_entries = find_credentials_for_vm(
            store, vm_name, principal_id=selected_principal
        )
        ssh_agent_entries = _agent_records(
            store,
            vm_name=vm_name,
            principal_id=selected_principal,
        )
        rows = [
            _SelectedCredential(CREDENTIAL_BACKEND_GUEST_KEY, item)
            for item in guest_entries
        ] + [
            _SelectedCredential(CREDENTIAL_BACKEND_SSH_AGENT, item)
            for item in ssh_agent_entries
        ]
        rows.sort(key=lambda item: (item.entry.principal_id, item.entry.id))
        view = 'machine-wide metadata' if args.all_principals else (principal_id or 'legacy')
        print(f'Credentials for VM {vm_name} ({view})')
        if not rows:
            print('  (none)')
            return 0
        print(
            '  ID                       BACKEND    OWNER                         '
            'ACCESS  STATE                 SCOPE'
        )
        unregistered = False
        for selected in rows:
            entry = selected.entry
            scope_text = f'{entry.provider_host}/{entry.owner}/{entry.repository}'
            state = str(entry.state)
            if isinstance(entry, CredentialEntry) and not entry.provider_managed:
                state = f'{state} (unregistered)'
                unregistered = True
            owner = credential_principal_label(store, entry.principal_id)
            print(
                f'  {entry.id:<24} {selected.backend:<10} {owner:<29.29} '
                f'{entry.access:<7} {state:<21} {scope_text}'
            )
        if unregistered:
            print(
                '\n  unregistered: AIVM could not add a guest-key deploy key; '
                'an admin must. Run `aivm vm creds status <id>` as its owner.'
            )
        return 0


def _print_guest_key_status(
    *,
    cfg: Any,
    store: Store,
    entry: CredentialEntry,
    principal_id: str,
    owner_label: str,
    manager: CommandManager,
) -> int:
    foreign = bool(entry.principal_id and entry.principal_id != principal_id)
    print(f'Credential {entry.id}')
    print(f'  Backend:      {CREDENTIAL_BACKEND_GUEST_KEY}')
    print(f'  VM:           {entry.vm_name}')
    print(f'  Principal:    {owner_label}')
    print(f'  Scope:        {entry.provider_host}/{entry.owner}/{entry.repository}')
    print(f'  Access:       {entry.access}')
    print(f'  State:        {entry.state}')
    print(f'  Fingerprint:  {entry.key_fingerprint}')
    print(f'  Provider ID:  {entry.provider_key_id or "(unrecorded)"}')
    if foreign:
        print('  Observation:  metadata only; detailed checks require the owning host user.')
        return 0
    with manager.intent(
        f'Inspect credential {entry.id}',
        why="Compare the owner's host key, provider deploy key, and guest installation.",
        role='read',
    ):
        report = inspect_credential(
            cfg,
            entry,
            store=store,
            current_principal_id=principal_id,
            manager=manager,
        )
    remote_key = report['remote']
    remote_text = 'missing'
    if remote_key is not None:
        remote_text = (
            f'active id={remote_key.key_id} '
            f'access={"read" if remote_key.read_only else "write"}'
        )
    elif report['remote_error']:
        remote_text = f'unavailable: {report["remote_error"]}'
    print('  Host key:     ' + ('healthy' if report['host_ok'] else 'invalid or unavailable'))
    print('  Fingerprint:  ' + ('matches' if report['fingerprint_ok'] else 'mismatch'))
    if report['host_detail']:
        print(f'  Host detail:  {report["host_detail"]}')
    label = providers.provider_label(entry.kind)
    print(f'  {label + " key:":<15}{remote_text}')
    print(f'  Guest:        {report["guest"]}')
    if report['guest_detail']:
        print(f'  Guest detail: {report["guest_detail"]}')
    if not entry.provider_managed:
        print(describe_unregistered_credential(entry, entry_repository(entry)))
    return 0


def _print_ssh_agent_status(
    *,
    store: Store,
    entry: AgentCredentialEntry,
    principal_id: str,
    owner_label: str,
    manager: CommandManager,
) -> int:
    foreign = bool(entry.principal_id and entry.principal_id != principal_id)
    print(f'Credential {entry.id}')
    print(f'  Backend:      {CREDENTIAL_BACKEND_SSH_AGENT}')
    print(f'  VM:           {entry.vm_name}')
    print(f'  Principal:    {owner_label}')
    print(f'  Scope:        {entry.provider_host}/{entry.owner}/{entry.repository}')
    print(f'  Access:       {entry.access}')
    print(f'  State:        {entry.state}')
    print(f'  Fingerprint:  {entry.key_fingerprint}')
    print(f'  Provider ID:  {entry.provider_key_id or "(unrecorded)"}')
    if foreign:
        print('  Observation:  metadata only; host key and ssh-agent checks require the owner.')
        return 0
    report = agent.inspect_doctor(
        store,
        entry.vm_name,
        principal_id,
        guest_key_fingerprints=_guest_key_fingerprints(
            store,
            vm_name=entry.vm_name,
            principal_id=principal_id,
        ),
        manager=manager,
    )
    print(f'  SSH agent:    {report.agent.runtime_state}')
    print(f'  Agent socket: {report.agent.socket_path}')
    print(f'  Loaded keys:  {len(report.agent.loaded_fingerprints)}')
    relevant = [issue for issue in report.issues if entry.id in issue.detail]
    shared = [
        issue
        for issue in report.issues
        if issue.code in {'agent-not-running', 'agent-identities', 'unused-agent'}
    ]
    issues = relevant + [item for item in shared if item not in relevant]
    if issues:
        for issue in issues:
            print(f'  Issue:        {issue.code}: {issue.detail}')
        return 1
    print('  Health:       healthy')
    return 0


class VMCredsStatusCLI(_BaseCommand):
    """Inspect one repository credential or machine-wide metadata."""

    selector: str = kwconf.Value('', position=1, help='Credential ID or repository selector.')
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value('origin', help='Git remote used for a local repository selector.')
    backend: BackendOption = kwconf.Value(
        'auto',
        help='Restrict lookup to auto/both, guest-key, or ssh-agent.',
    )
    all_principals: bool = kwconf.Flag(
        False,
        help='Allow selecting any principal record; foreign records show metadata only.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.selector:
            raise AIVMError('Provide a credential ID or repository selector.')
        context, store, _store_path, principal_id = _load_credential_context(
            args.config, vm_opt=args.vm, persist_runtime_defaults=False
        )
        selected = _resolve_existing_credential(
            store,
            vm_name=context.effective_cfg.vm.name,
            selector=args.selector,
            remote=args.remote,
            manager=CommandManager.current(),
            principal_id=None if args.all_principals else principal_id,
            backend=args.backend,
        )
        owner_label = credential_principal_label(store, selected.entry.principal_id)
        mgr = CommandManager.current()
        if selected.backend == CREDENTIAL_BACKEND_SSH_AGENT:
            assert isinstance(selected.entry, AgentCredentialEntry)
            return _print_ssh_agent_status(
                store=store,
                entry=selected.entry,
                principal_id=principal_id,
                owner_label=owner_label,
                manager=mgr,
            )
        assert isinstance(selected.entry, CredentialEntry)
        return _print_guest_key_status(
            cfg=context.effective_cfg,
            store=store,
            entry=selected.entry,
            principal_id=principal_id,
            owner_label=owner_label,
            manager=mgr,
        )


class VMCredsRevokeCLI(_BaseCommand):
    """Revoke one repository credential owned by the current principal."""

    selector: str = kwconf.Value('', position=1, help='Credential ID or repository selector.')
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value('origin', help='Git remote used for a local repository selector.')
    backend: BackendOption = kwconf.Value(
        'auto', help='Restrict lookup to auto/both, guest-key, or ssh-agent.'
    )
    dry_run: bool = kwconf.Flag(False, short_alias=['n'], help='Print the revocation without changing anything.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.selector:
            raise AIVMError('Provide a credential ID or repository selector.')
        context, store, store_path, principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=not args.dry_run,
        )
        selected = _resolve_existing_credential(
            store,
            vm_name=context.effective_cfg.vm.name,
            selector=args.selector,
            remote=args.remote,
            manager=CommandManager.current(),
            principal_id=principal_id,
            backend=args.backend,
        )
        entry = selected.entry
        repo = (
            agent.agent_repository(entry)
            if isinstance(entry, AgentCredentialEntry)
            else entry_repository(entry)
        )
        if args.dry_run:
            print(f'DRYRUN: would revoke credential {entry.id}')
            print(f'  Backend:    {selected.backend}')
            print(f'  Repository: {repo.display}')
            print(f'  Access:     {entry.access}')
            if selected.backend == CREDENTIAL_BACKEND_SSH_AGENT:
                print('  Order: provider deploy key, ssh-agent identity, host-only key, config record')
            else:
                print('  Order: provider deploy key, guest copy, host copy, config record')
            return 0
        mgr = CommandManager.current()
        with mgr.intent(
            f'Revoke {selected.backend} credential {entry.id}',
            why='Remove provider authority before removing backend-owned local state.',
            role='modify',
        ):
            if selected.backend == CREDENTIAL_BACKEND_SSH_AGENT:
                assert isinstance(entry, AgentCredentialEntry)
                agent.revoke_agent_credential(store, store_path, entry, manager=mgr)
            else:
                assert isinstance(entry, CredentialEntry)
                revoke_repository_credential(
                    context.effective_cfg,
                    store,
                    store_path,
                    entry,
                    current_principal_id=principal_id,
                    manager=mgr,
                )
        print(f'Revoked credential {entry.id} (backend={selected.backend}).')
        return 0


class VMCredsAbandonCLI(_BaseCommand):
    """Forget an inaccessible provider grant owned by this principal."""

    selector: str = kwconf.Value('', position=1, help='Credential ID or repository selector.')
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value('origin', help='Git remote used for a local repository selector.')
    provider_unverified: bool = kwconf.Flag(
        False,
        help=(
            'Required acknowledgement that AIVM cannot prove provider-side '
            'revocation and the copied key may remain usable.'
        ),
    )
    dry_run: bool = kwconf.Flag(False, short_alias=['n'], help='Print the abandonment without changing anything.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.selector:
            raise AIVMError('Provide a credential ID or repository selector.')
        if not args.provider_unverified:
            raise AIVMError(
                'Abandonment requires --provider_unverified because AIVM '
                'will not prove that the provider deploy key was revoked.'
            )
        context, store, store_path, principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=not args.dry_run,
        )
        selected = _resolve_existing_credential(
            store,
            vm_name=context.effective_cfg.vm.name,
            selector=args.selector,
            remote=args.remote,
            manager=CommandManager.current(),
            principal_id=principal_id,
            backend='auto',
        )
        if selected.backend != CREDENTIAL_BACKEND_GUEST_KEY:
            raise AIVMError(
                'The ssh-agent backend does not support provider-unverified '
                'abandonment; use `aivm vm creds revoke`.'
            )
        entry = selected.entry
        assert isinstance(entry, CredentialEntry)
        if args.dry_run:
            print(f'DRYRUN: would abandon credential {entry.id}')
            print(f'  Backend: {CREDENTIAL_BACKEND_GUEST_KEY}')
            print(f'  Principal: {principal_id or "legacy"}')
            print(
                '  WARNING: provider revocation would remain unverified for '
                f'{entry.provider_host}/{entry.owner}/{entry.repository}'
            )
            print('  Local guest and host copies would be removed.')
            print('  A non-secret audit tombstone would be retained.')
            return 0
        mgr = CommandManager.current()
        with mgr.intent(
            f'Abandon provider-unverified credential {entry.id}',
            why=(
                "Remove the owning principal's guest-key copies and retain an "
                'audit tombstone when the provider cannot be administered.'
            ),
            role='modify',
        ):
            tombstone = abandon_repository_credential(
                context.effective_cfg,
                store,
                store_path,
                entry,
                current_principal_id=principal_id,
                manager=mgr,
            )
        print(
            f'Abandoned credential {entry.id}; provider revocation was not '
            f'verified. Audit tombstone: {tombstone}'
        )
        return 0


def _print_ssh_agent_doctor(report: agent.DoctorReport) -> None:
    print(f'  ssh-agent credentials: {len(report.records)}')
    print(f'  ssh-agent runtime:     {report.agent.runtime_state}')
    print(f'  ssh-agent socket:      {report.agent.socket_path}')
    print(f'  ssh-agent loaded keys: {len(report.agent.loaded_fingerprints)}')
    if report.issues:
        print('  ssh-agent issues:')
        for issue in report.issues:
            action = 'fixable' if issue.fixable else 'manual'
            print(f'    {action:7} {issue.code}: {issue.detail}')
    else:
        print('  ssh-agent issues:      none')


class VMCredsDoctorCLI(_BaseCommand):
    """Diagnose credential health; --fix repairs derived runtime state."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    fix: bool = kwconf.Flag(
        False,
        help=(
            'Repair derived ssh-agent runtime state only. Provider grants and '
            'credential authority remain explicit add/revoke operations.'
        ),
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, _store_path, principal_id = _load_credential_context(
            args.config, vm_opt=args.vm, persist_runtime_defaults=False
        )
        vm_name = context.effective_cfg.vm.name
        guest_records = find_credentials_for_vm(store, vm_name, principal_id=principal_id)
        fingerprints = _guest_key_fingerprints(
            store, vm_name=vm_name, principal_id=principal_id
        )
        mgr = CommandManager.current()
        if args.fix:
            with mgr.intent(
                f'Repair ssh-agent credential runtime for {vm_name}',
                why='Repair only derived local ssh-agent state.',
                role='modify',
            ):
                report = agent.fix_doctor(
                    store,
                    vm_name,
                    principal_id,
                    guest_key_fingerprints=fingerprints,
                    manager=mgr,
                )
        else:
            report = agent.inspect_doctor(
                store,
                vm_name,
                principal_id,
                guest_key_fingerprints=fingerprints,
                manager=mgr,
            )
        print('Credential doctor')
        print(f'  VM:                    {vm_name}')
        print(f'  Principal:             {principal_id or "legacy"}')
        print(f'  guest-key credentials: {len(guest_records)}')
        print('  guest-key repair:      explicit status/revoke lifecycle')
        _print_ssh_agent_doctor(report)
        return 0 if report.healthy else 1


class VMCredsModalCLI(kwconf.ModalCLI):
    """Manage scoped repository credentials for a VM."""

    setup = VMCredsSetupCLI
    preference = VMCredsPreferenceCLI
    plan = VMCredsPlanCLI
    apply = VMCredsApplyCLI
    add = VMCredsAddCLI
    list = VMCredsListCLI
    status = VMCredsStatusCLI
    revoke = VMCredsRevokeCLI
    abandon = VMCredsAbandonCLI
    doctor = VMCredsDoctorCLI
