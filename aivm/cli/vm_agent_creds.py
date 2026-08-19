"""Independent host-agent repository credential commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import kwconf

from ..commands import CommandManager
from ..config_scopes import ResolvedVMContext
from ..config_store import AgentCredentialEntry, Store, find_credentials_for_vm
from ..credentials import agent, providers
from ..credentials.models import GitRepository
from ..credentials.resolve import resolve_repository
from ..credentials.schema import normalize_credential_access
from ..errors import AIVMError
from ..scoped_store import load_scope_store, resolve_store_scope
from ..services import load_vm_context_with_path
from ._common import _BaseCommand


def _load_context(
    config_opt: str | None,
    *,
    vm_opt: str,
    persist_runtime_defaults: bool,
) -> tuple[ResolvedVMContext, Store, Path, str]:
    context, store_path = load_vm_context_with_path(
        config_opt,
        vm_opt=vm_opt,
        host_src=Path.cwd(),
        persist_runtime_defaults=persist_runtime_defaults,
    )
    scope = resolve_store_scope(str(store_path))
    store = load_scope_store(scope)
    principal_id = context.principal.id if scope.is_machine else ''
    return context, store, Path(store_path), principal_id


def _guest_key_fingerprints(
    store: Store, *, vm_name: str, principal_id: str
) -> tuple[str, ...]:
    """Read-only cross-check; guest-key records are never agent inputs."""
    return tuple(
        entry.key_fingerprint
        for entry in find_credentials_for_vm(
            store,
            vm_name,
            principal_id=principal_id,
        )
        if entry.key_fingerprint
    )


def _resolve_selector(
    vm_name: str,
    principal_id: str,
    selector: str,
    *,
    remote: str,
    manager: CommandManager,
    store: Store,
) -> AgentCredentialEntry:
    exact = agent.find_agent_credential(
        store,
        vm_name,
        principal_id,
        credential_id=selector,
    )
    if exact is not None:
        return exact
    repo = resolve_repository(selector, remote=remote, manager=manager)
    record = agent.find_agent_credential(
        store,
        vm_name,
        principal_id,
        repo=repo,
    )
    if record is None:
        raise AIVMError(
            f'Host-agent credential not found for {repo.display} on VM '
            f'{vm_name!r}.'
        )
    return record


def _print_record(record: AgentCredentialEntry) -> None:
    print(
        f'{record.id}  {record.access:5}  {record.state:18}  '
        f'{agent.agent_repository(record).display}'
    )


def _print_doctor(report: agent.DoctorReport) -> None:
    print('Host-agent credential doctor')
    print(f'  VM:              {report.vm_name}')
    print(f'  Principal:       {report.principal_id or "legacy"}')
    print(f'  Credentials:     {len(report.records)}')
    print(f'  Agent:           {report.agent.runtime_state}')
    print(f'  Agent socket:    {report.agent.socket_path}')
    print(
        '  Loaded keys:     '
        f'{len(report.agent.loaded_fingerprints)}'
    )
    if report.issues:
        print('  Issues:')
        for issue in report.issues:
            action = 'fixable' if issue.fixable else 'manual'
            print(f'    {action:7} {issue.code}: {issue.detail}')
    else:
        print('  Issues:          none')
    if report.fixable_count:
        print(
            f'Run `aivm vm agent_creds doctor --fix` to repair '
            f'{report.fixable_count} local issue(s).'
        )


class VMAgentCredsAddCLI(_BaseCommand):
    """Create a new deploy key whose private half remains host-only."""

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
        help='Deploy-key provider; auto infers it from the repository host.',
    )
    access: Literal['read', 'ro', 'write', 'rw'] = kwconf.Value(
        'read',
        help='Repository access: read (ro) or write (rw); default read.',
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Show the independent grant without creating key material.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, store_path, principal_id = _load_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=not args.dry_run,
        )
        vm_name = context.effective_cfg.vm.name
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
        cred_id = agent.agent_credential_id(
            vm_name, repo.canonical, principal_id
        )
        if args.dry_run:
            print('Host-agent credential grant')
            print(f'  VM:          {vm_name}')
            print(f'  Principal:   {principal_id or "legacy"}')
            print(f'  Repository:  {repo.display}')
            print(f'  Access:      {access}')
            print(f'  Provider:    {resolved_provider}')
            print(f'  Credential:  {cred_id}')
            print('  Private key: host-only; never installed into the guest')
            print('DRYRUN: no key, provider setting, or agent state changed.')
            return 0
        with mgr.intent(
            f'Create host-agent access to {repo.display}',
            why=(
                'Create an independent deploy key whose private half remains '
                'on the AIVM host and load it only into this principal-scoped '
                'dedicated ssh-agent.'
            ),
            role='modify',
        ):
            record = agent.grant_agent_credential(
                store,
                store_path,
                vm_name,
                principal_id,
                repo,
                access=access,
                kind=kind,
                manager=mgr,
            )
        print(
            f'Created host-agent {record.access} grant: '
            f'{agent.agent_repository(record).display} ({record.id})'
        )
        print('Private key remains host-only.')
        print(
            'Managed `aivm ssh` / Remote-SSH sessions forward only this '
            'principal-scoped AIVM agent into the guest.'
        )
        return 0


class VMAgentCredsListCLI(_BaseCommand):
    """List host-agent credentials for the selected VM principal."""

    vm: str = kwconf.Value('', help='Optional VM name override.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, store_path, principal_id = _load_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=False,
        )
        vm_name = context.effective_cfg.vm.name
        records = agent.list_agent_credentials(store, vm_name, principal_id)
        if not records:
            print('No host-agent credentials.')
            return 0
        for record in records:
            _print_record(record)
        return 0


class VMAgentCredsStatusCLI(_BaseCommand):
    """Show host-agent grants and current dedicated-agent health."""

    vm: str = kwconf.Value('', help='Optional VM name override.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, store_path, principal_id = _load_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=False,
        )
        vm_name = context.effective_cfg.vm.name
        records = agent.list_agent_credentials(store, vm_name, principal_id)
        if records:
            print('Host-agent credentials:')
            for record in records:
                _print_record(record)
        else:
            print('Host-agent credentials: none')
        report = agent.inspect_doctor(
            store,
            vm_name,
            principal_id,
            guest_key_fingerprints=_guest_key_fingerprints(
                store,
                vm_name=vm_name,
                principal_id=principal_id,
            ),
            manager=CommandManager.current(),
        )
        print(
            f'Dedicated agent: {report.agent.runtime_state}; '
            f'loaded={len(report.agent.loaded_fingerprints)}; '
            f'issues={len(report.issues)}'
        )
        return 0 if report.healthy else 1


class VMAgentCredsRevokeCLI(_BaseCommand):
    """Revoke one host-agent deploy key and remove its host-only material."""

    selector: str = kwconf.Value(
        '.',
        position=1,
        help='Agent credential id, checkout, OWNER/REPO, or repository URL.',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used when resolving a local checkout.'
    )
    dry_run: bool = kwconf.Flag(
        False,
        short_alias=['n'],
        help='Show the revocation without changing provider or host state.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, store_path, principal_id = _load_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=not args.dry_run,
        )
        vm_name = context.effective_cfg.vm.name
        mgr = CommandManager.current()
        record = _resolve_selector(
            vm_name,
            principal_id,
            args.selector,
            remote=args.remote,
            manager=mgr,
            store=store,
        )
        if args.dry_run:
            print(f'DRYRUN: would revoke host-agent credential {record.id}')
            print(f'  Repository: {agent.agent_repository(record).display}')
            print(f'  Access:     {record.access}')
            print('  Provider deploy key would be removed first.')
            print('  Host-only key material would then be deleted.')
            return 0
        with mgr.intent(
            f'Revoke host-agent access to {agent.agent_repository(record).display}',
            why=(
                'Remove provider authority before deleting the host-only key '
                'and removing it from the dedicated agent.'
            ),
            role='modify',
        ):
            agent.revoke_agent_credential(
                store, store_path, record, manager=mgr
            )
        print(f'Revoked host-agent credential {record.id}.')
        return 0


class VMAgentCredsDoctorCLI(_BaseCommand):
    """Diagnose host-agent credential state; --fix repairs local derivations."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    fix: bool = kwconf.Flag(
        False,
        help=(
            'Repair derived local ssh-agent state. Never creates, revokes, or '
            'changes provider authority.'
        ),
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        context, store, store_path, principal_id = _load_context(
            args.config,
            vm_opt=args.vm,
            persist_runtime_defaults=False,
        )
        vm_name = context.effective_cfg.vm.name
        fingerprints = _guest_key_fingerprints(
            store,
            vm_name=vm_name,
            principal_id=principal_id,
        )
        mgr = CommandManager.current()
        if args.fix:
            with mgr.intent(
                f'Repair host-agent credential runtime for {vm_name}',
                why=(
                    'Repair only derived local agent state; provider grants '
                    'and key authority remain explicit add/revoke operations.'
                ),
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
        _print_doctor(report)
        return 0 if report.healthy else 1


class VMAgentCredsModalCLI(kwconf.ModalCLI):
    """Manage independent host-only repository credentials."""

    add = VMAgentCredsAddCLI
    list = VMAgentCredsListCLI
    status = VMAgentCredsStatusCLI
    revoke = VMAgentCredsRevokeCLI
    doctor = VMAgentCredsDoctorCLI
