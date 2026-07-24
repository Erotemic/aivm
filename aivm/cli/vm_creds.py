"""VM-scoped credential commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import kwconf

from ..commands import CommandManager
from ..config_store import find_credentials_for_vm, load_store
from ..credentials.keys import credential_id
from ..credentials.resolve import resolve_repository
from ..credentials.service import (
    grant_repository_credential,
    inspect_credential,
    revoke_repository_credential,
    select_credential,
)
from ..errors import AIVMError
from ..services import load_cfg_with_path
from ._common import _BaseCommand


class VMCredsAddCLI(_BaseCommand):
    """Grant a VM repository access with a scoped GitHub deploy key."""

    repository: str = kwconf.Value(
        '.',
        position=1,
        help='Local checkout, OWNER/REPO, or Git SSH/HTTPS URL (default: .).',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used when resolving a local checkout.'
    )
    write: bool = kwconf.Flag(
        False, help='Allow pushes. The default credential is read-only.'
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print the grant without creating or installing a key.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, store_path = load_cfg_with_path(
            args.config,
            vm_opt=args.vm,
            host_src=Path.cwd(),
            persist_runtime_defaults=not bool(args.dry_run),
        )
        mgr = CommandManager.current()
        repo = resolve_repository(
            args.repository, remote=args.remote, manager=mgr
        )
        access = 'write' if args.write else 'read'
        cred_id = credential_id(cfg.vm.name, repo.canonical)
        if args.dry_run:
            print('Repository credential grant')
            print(f'  VM:          {cfg.vm.name}')
            print(f'  Repository:  {repo.display}')
            print(f'  Access:      {access}')
            print(f'  Type:        github-deploy-key')
            print(f'  Credential:  {cred_id}')
            print('  Branches:    not managed by AIVM')
            print('DRYRUN: no key, GitHub setting, guest file, or config was changed.')
            return 0

        store = load_store(store_path)
        with mgr.intent(
            f'Grant {cfg.vm.name} access to {repo.display}',
            why=(
                'Create a repository-scoped deploy key on the host, register '
                'its public key with GitHub, and install its private key in '
                'the selected VM.'
            ),
            role='modify',
        ):
            entry = grant_repository_credential(
                cfg,
                store,
                store_path,
                repo,
                write=bool(args.write),
                manager=mgr,
            )
        print(
            f'Granted {entry.access} access: vm={entry.vm_name} '
            f'repository={repo.display} credential={entry.id}'
        )
        return 0


class VMCredsListCLI(_BaseCommand):
    """List repository credentials owned by a VM."""

    vm: str = kwconf.Value('', help='Optional VM name override.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, store_path = load_cfg_with_path(
            args.config,
            vm_opt=args.vm,
            host_src=Path.cwd(),
            persist_runtime_defaults=False,
        )
        entries = find_credentials_for_vm(load_store(store_path), cfg.vm.name)
        print(f'Credentials for VM {cfg.vm.name}')
        if not entries:
            print('  (none)')
            return 0
        print('  ID                ACCESS  STATE                 SCOPE')
        for entry in entries:
            scope = (
                f'{entry.provider_host}/{entry.owner}/{entry.repository}'
            )
            print(
                f'  {entry.id:<17} {entry.access:<7} '
                f'{entry.state:<21} {scope}'
            )
        return 0


class VMCredsStatusCLI(_BaseCommand):
    """Inspect one VM repository credential and detect remote or guest drift."""

    selector: str = kwconf.Value(
        '',
        position=1,
        help='Credential ID or repository selector.',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used for a local repository selector.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.selector:
            raise AIVMError('Provide a credential ID or repository selector.')
        cfg, store_path = load_cfg_with_path(
            args.config,
            vm_opt=args.vm,
            host_src=Path.cwd(),
            persist_runtime_defaults=False,
        )
        store = load_store(store_path)
        repo = None
        if not any(
            entry.id == args.selector
            for entry in find_credentials_for_vm(store, cfg.vm.name)
        ):
            repo = resolve_repository(
                args.selector,
                remote=args.remote,
                manager=CommandManager.current(),
            )
        entry = select_credential(
            store,
            vm_name=cfg.vm.name,
            selector=args.selector,
            repo=repo,
        )
        with CommandManager.current().intent(
            f'Inspect credential {entry.id}',
            why=(
                'Compare AIVM state with the host key, GitHub deploy key, '
                'and guest installation.'
            ),
            role='read',
        ):
            report = inspect_credential(
                cfg, entry, manager=CommandManager.current()
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
        print(
            f'  Scope:        {entry.provider_host}/{entry.owner}/{entry.repository}'
        )
        print(f'  Access:       {entry.access}')
        print(f'  State:        {entry.state}')
        print(
            '  Host key:     '
            + ('present' if report['host_ok'] else 'missing or incomplete')
        )
        print(
            '  Fingerprint:  '
            + ('matches' if report['fingerprint_ok'] else 'mismatch')
        )
        if report['host_detail']:
            print(f'  Host detail:  {report["host_detail"]}')
        print(f'  GitHub key:   {remote_text}')
        print(f'  Guest:        {report["guest"]}')
        if report['guest_detail']:
            print(f'  Guest detail: {report["guest_detail"]}')
        print('  Branch rules: not managed by AIVM')
        return 0


class VMCredsRevokeCLI(_BaseCommand):
    """Revoke a deploy key, then remove its host and guest copies."""

    selector: str = kwconf.Value(
        '',
        position=1,
        help='Credential ID or repository selector.',
    )
    vm: str = kwconf.Value('', help='Optional VM name override.')
    remote: str = kwconf.Value(
        'origin', help='Git remote used for a local repository selector.'
    )
    dry_run: bool = kwconf.Flag(
        False, help='Print the revocation without changing anything.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if not args.selector:
            raise AIVMError('Provide a credential ID or repository selector.')
        cfg, store_path = load_cfg_with_path(
            args.config,
            vm_opt=args.vm,
            host_src=Path.cwd(),
            persist_runtime_defaults=not bool(args.dry_run),
        )
        store = load_store(store_path)
        repo = None
        entries = find_credentials_for_vm(store, cfg.vm.name)
        if not any(entry.id == args.selector for entry in entries):
            repo = resolve_repository(
                args.selector,
                remote=args.remote,
                manager=CommandManager.current(),
            )
        entry = select_credential(
            store,
            vm_name=cfg.vm.name,
            selector=args.selector,
            repo=repo,
        )
        if args.dry_run:
            print(f'DRYRUN: would revoke credential {entry.id}')
            print(
                '  Scope: '
                f'{entry.provider_host}/{entry.owner}/{entry.repository}'
            )
            print('  Order: GitHub deploy key, guest copy, host copy, config record')
            return 0
        mgr = CommandManager.current()
        with mgr.intent(
            f'Revoke credential {entry.id}',
            why=(
                'Invalidate the repository permission at GitHub before '
                'removing copies of the private key.'
            ),
            role='modify',
        ):
            revoke_repository_credential(
                cfg,
                store,
                store_path,
                entry,
                manager=mgr,
            )
        print(f'Revoked credential {entry.id}.')
        return 0


class VMCredsModalCLI(kwconf.ModalCLI):
    """Manage scoped credentials installed in a VM."""

    add = VMCredsAddCLI
    list = VMCredsListCLI
    status = VMCredsStatusCLI
    revoke = VMCredsRevokeCLI
