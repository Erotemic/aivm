"""Principal-scoped repository credential commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import kwconf

from ..commands import CommandManager
from ..config_scopes import ResolvedVMContext
from ..config_store import (
    CredentialEntry,
    Store,
    find_credential,
    find_credentials_for_vm,
)
from ..credentials import providers
from ..credentials.gitlab import host_token_envvar
from ..credentials.ownership import credential_principal_label
from ..credentials.resolve import resolve_repository
from ..credentials.schema import normalize_credential_access
from ..credentials.service import (
    abandon_repository_credential,
    describe_unregistered_credential,
    entry_repository,
    grant_repository_credential,
    inspect_credential,
    revoke_repository_credential,
    select_credential,
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
from ..errors import AIVMError
from ..scoped_store import load_scope_store, resolve_store_scope
from ..services import load_vm_context_with_path
from ._common import _BaseCommand


def _load_credential_context(
    config_opt: str | None,
    *,
    vm_opt: str,
    persist_runtime_defaults: bool,
) -> tuple[ResolvedVMContext, Store, Path, str]:
    """Load the caller context plus the matching physical credential store."""
    context, store_path = load_vm_context_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
        persist_runtime_defaults=persist_runtime_defaults,
    )
    scope = resolve_store_scope(str(store_path))
    store = load_scope_store(scope)
    principal_id = context.principal.id if scope.is_machine else ''
    return context, store, store_path, principal_id


def _resolve_credential_selector(
    store: Store,
    *,
    vm_name: str,
    selector: str,
    remote: str,
    manager: CommandManager,
    principal_id: str | None = None,
) -> CredentialEntry:
    """Resolve an id or repository selector within one principal scope."""
    exact = find_credential(
        store,
        vm_name=vm_name,
        credential_id=selector,
        principal_id=principal_id,
    )
    if exact is not None:
        return exact
    repo = resolve_repository(selector, remote=remote, manager=manager)
    return select_credential(
        store,
        vm_name=vm_name,
        selector=selector,
        repo=repo,
        principal_id=principal_id,
    )


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
    # argparse builds its choice list from this annotation and rejects
    # anything outside it before normalize_credential_access() runs, so the
    # accepted spellings have to be declared here, not only in the normalizer.
    access: Literal['read', 'ro', 'write', 'rw'] = kwconf.Value(
        'read',
        help=(
            'Credential access: read (ro) or write (rw); default read. '
            'write means read+write -- deploy keys have no write-only '
            'mode. Changing the access of an existing credential requires '
            'revoking it first.'
        ),
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Print the grant without creating or installing a key.'
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
        mgr = CommandManager.current()
        requested_provider = providers.normalize_provider(args.provider)
        default_host = (
            'gitlab.com' if requested_provider == 'gitlab' else 'github.com'
        )
        repo = resolve_repository(
            args.repository,
            remote=args.remote,
            default_host=default_host,
            manager=mgr,
        )
        resolved_provider = providers.resolve_provider(repo, requested_provider)
        kind = providers.kind_for_provider(resolved_provider)
        access = normalize_credential_access(args.access)
        cred_id = credential_id(cfg.vm.name, repo.canonical, principal_id)
        if args.dry_run:
            print('Repository credential grant')
            print(f'  VM:          {cfg.vm.name}')
            print(f'  Principal:   {principal_id or "legacy"}')
            print(f'  Repository:  {repo.display}')
            print(f'  Access:      {access}')
            print(f'  Provider:    {resolved_provider}')
            print(f'  Type:        {kind}')
            print(f'  Credential:  {cred_id}')
            print('  Branches:    not managed by AIVM')
            print(
                'DRYRUN: no key, provider setting, guest file, or config '
                'was changed.'
            )
            return 0

        with mgr.intent(
            f'Grant {cfg.vm.name} access to {repo.display}',
            why=(
                'Create a principal-owned deploy key on the host, register '
                'its public half, and install the private half only in the '
                "selected principal's guest home."
            ),
            role='modify',
        ):
            entry = grant_repository_credential(
                cfg,
                store,
                store_path,
                repo,
                access=access,
                kind=kind,
                principal_id=principal_id,
                manager=mgr,
            )
        if not entry.provider_managed:
            print(describe_unregistered_credential(entry, repo))
            return 0
        print(
            f'Granted {entry.access} access: vm={entry.vm_name} '
            f'principal={entry.principal_id or "legacy"} '
            f'repository={repo.display} credential={entry.id}'
        )
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
        help='Print the setup actions without changing the host.'
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
        cfg = context.effective_cfg
        selected_principal = None if args.all_principals else principal_id
        entries = find_credentials_for_vm(
            store, cfg.vm.name, principal_id=selected_principal
        )
        view = (
            'machine-wide metadata'
            if args.all_principals
            else (principal_id or 'legacy')
        )
        print(f'Credentials for VM {cfg.vm.name} ({view})')
        if not entries:
            print('  (none)')
            return 0
        print(
            '  ID                OWNER                         ACCESS  STATE                 SCOPE'
        )
        unregistered = False
        for entry in entries:
            scope_text = (
                f'{entry.provider_host}/{entry.owner}/{entry.repository}'
            )
            state = str(entry.state)
            if not entry.provider_managed:
                state = f'{state} (unregistered)'
                unregistered = True
            owner = credential_principal_label(store, entry.principal_id)
            print(
                f'  {entry.id:<17} {owner:<29.29} {entry.access:<7} '
                f'{state:<21} {scope_text}'
            )
        if unregistered:
            print(
                '\n  unregistered: AIVM could not add the deploy key; an '
                'admin must. Run `aivm vm creds status <id>` as the owning '
                'host user for the public-key handoff.'
            )
        return 0


class VMCredsStatusCLI(_BaseCommand):
    """Inspect one principal credential or machine-wide metadata."""

    selector: str = kwconf.Value(
        '',
        position=1,
        help='Credential ID or repository selector.',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used for a local repository selector.'
    )
    all_principals: bool = kwconf.Flag(
        False,
        help=(
            'Allow selecting any principal record. Records owned by another '
            'host user are shown as metadata only.'
        ),
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.selector:
            raise AIVMError('Provide a credential ID or repository selector.')
        context, store, _store_path, principal_id = _load_credential_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=False,
        )
        cfg = context.effective_cfg
        selector_principal = None if args.all_principals else principal_id
        entry = _resolve_credential_selector(
            store,
            vm_name=cfg.vm.name,
            selector=args.selector,
            remote=args.remote,
            manager=CommandManager.current(),
            principal_id=selector_principal,
        )
        owner_label = credential_principal_label(store, entry.principal_id)
        foreign = bool(
            entry.principal_id and entry.principal_id != principal_id
        )
        if foreign:
            print(f'Credential {entry.id}')
            print(f'  VM:           {entry.vm_name}')
            print(f'  Principal:    {owner_label}')
            print(
                f'  Scope:        {entry.provider_host}/{entry.owner}/'
                f'{entry.repository}'
            )
            print(f'  Access:       {entry.access}')
            print(f'  State:        {entry.state}')
            print(f'  Fingerprint:  {entry.key_fingerprint}')
            print(f'  Provider ID:  {entry.provider_key_id or "(unrecorded)"}')
            print(
                '  Observation:  metadata only; host key, provider auth, and '
                'guest-home checks require the owning host user.'
            )
            return 0

        with CommandManager.current().intent(
            f'Inspect credential {entry.id}',
            why=(
                "Compare the owning principal's host key, provider deploy "
                'key, and guest installation.'
            ),
            role='read',
        ):
            report = inspect_credential(
                cfg,
                entry,
                store=store,
                current_principal_id=principal_id,
                manager=CommandManager.current(),
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
        print(f'Credential {entry.id}')
        print(f'  VM:           {entry.vm_name}')
        print(f'  Principal:    {owner_label}')
        print(
            f'  Scope:        {entry.provider_host}/{entry.owner}/{entry.repository}'
        )
        print(f'  Access:       {entry.access}')
        print(f'  State:        {entry.state}')
        if not entry.provider_managed:
            print(
                '  Registered:   no -- AIVM could not administer this '
                'repository'
            )
            print(
                '                an admin must add the public key; it grants '
                'nothing until then'
            )
        print(
            '  Host key:     '
            + ('healthy' if report['host_ok'] else 'invalid or unavailable')
        )
        print(
            '  Fingerprint:  '
            + ('matches' if report['fingerprint_ok'] else 'mismatch')
        )
        if report['host_detail']:
            print(f'  Host detail:  {report["host_detail"]}')
        label = providers.provider_label(entry.kind)
        print(f'  {label + " key:":<15}{remote_text}')
        print(f'  Guest:        {report["guest"]}')
        if report['guest_detail']:
            print(f'  Guest detail: {report["guest_detail"]}')
        print('  Branch rules: not managed by AIVM')
        if not entry.provider_managed:
            print(
                describe_unregistered_credential(entry, entry_repository(entry))
            )
        return 0


class VMCredsRevokeCLI(_BaseCommand):
    """Revoke one credential owned by the current VM principal."""

    selector: str = kwconf.Value(
        '', position=1, help='Credential ID or repository selector.'
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used for a local repository selector.'
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Print the revocation without changing anything.'
    )

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
        cfg = context.effective_cfg
        entry = _resolve_credential_selector(
            store,
            vm_name=cfg.vm.name,
            selector=args.selector,
            remote=args.remote,
            manager=CommandManager.current(),
            principal_id=principal_id,
        )
        if args.dry_run:
            print(f'DRYRUN: would revoke credential {entry.id}')
            print(f'  Principal: {principal_id or "legacy"}')
            print(
                '  Scope: '
                f'{entry.provider_host}/{entry.owner}/{entry.repository}'
            )
            print(
                '  Order: provider deploy key, guest copy, host copy, '
                'config record'
            )
            return 0
        mgr = CommandManager.current()
        with mgr.intent(
            f'Revoke credential {entry.id}',
            why=(
                'Invalidate the repository permission using the owning host '
                "principal's provider authentication before removing copies."
            ),
            role='modify',
        ):
            revoke_repository_credential(
                cfg,
                store,
                store_path,
                entry,
                current_principal_id=principal_id,
                manager=mgr,
            )
        print(f'Revoked credential {entry.id}.')
        return 0


class VMCredsAbandonCLI(_BaseCommand):
    """Forget an inaccessible provider grant owned by this principal."""

    selector: str = kwconf.Value(
        '', position=1, help='Credential ID or repository selector.'
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used for a local repository selector.'
    )
    provider_unverified: bool = kwconf.Flag(
        False,
        help=(
            'Required acknowledgement that AIVM cannot prove provider-side '
            'revocation and the copied key may remain usable.'
        ),
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Print the abandonment without changing anything.'
    )

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
        cfg = context.effective_cfg
        entry = _resolve_credential_selector(
            store,
            vm_name=cfg.vm.name,
            selector=args.selector,
            remote=args.remote,
            manager=CommandManager.current(),
            principal_id=principal_id,
        )
        if args.dry_run:
            print(f'DRYRUN: would abandon credential {entry.id}')
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
                "Remove the owning principal's local copies and retain an "
                'audit tombstone when the provider cannot be administered.'
            ),
            role='modify',
        ):
            tombstone = abandon_repository_credential(
                cfg,
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


class VMCredsModalCLI(kwconf.ModalCLI):
    """Manage scoped credentials installed in a VM."""

    setup = VMCredsSetupCLI
    add = VMCredsAddCLI
    list = VMCredsListCLI
    status = VMCredsStatusCLI
    revoke = VMCredsRevokeCLI
    abandon = VMCredsAbandonCLI
