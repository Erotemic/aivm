"""One live, read-only guest inspection for the requested foreground path."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

from ...commands import CommandManager, CommandResult
from ...config import AgentVMConfig
from ...persistent_replay import (
    GUEST_SESSION_INSPECT_BIN,
    GUEST_SYMLINK_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    attachment_symlink_python,
    persistent_replay_python,
    persistent_replay_service_unit,
    session_inspect_python,
)
from . import transport

SymlinkCheck = tuple[str, str, bool]  # link, target, remove rather than create


@dataclass(frozen=True)
class GuestInspection:
    files: dict[str, bool]
    manifest_directory: bool
    symlinks: list[tuple[SymlinkCheck, CommandResult | None]]
    replay: CommandResult | None


def _result(value: object) -> CommandResult | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {'code', 'stderr'}:
        raise ValueError('malformed guest inspection result')
    if type(value['code']) is not int or not isinstance(value['stderr'], str):
        raise ValueError('invalid guest inspection exit status')
    return CommandResult(value['code'], '', value['stderr'])


def _decode(
    text: str, files: dict[str, str], symlinks: list[SymlinkCheck]
) -> GuestInspection:
    value = json.loads(text)
    if not isinstance(value, dict) or set(value) != {
        'version',
        'files',
        'manifest_directory',
        'symlinks',
        'replay',
    }:
        raise ValueError('malformed guest inspection response')
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('unsupported guest inspection version')
    found = value['files']
    if (
        not isinstance(found, dict)
        or set(found) != set(files)
        or any(type(v) is not bool for v in found.values())
    ):
        raise ValueError('guest inspection did not check the expected helpers')
    if type(value['manifest_directory']) is not bool or not isinstance(
        value['symlinks'], list
    ):
        raise ValueError('malformed guest inspection state')
    links = []
    for entry in value['symlinks']:
        if not isinstance(entry, dict) or set(entry) != {
            'link',
            'target',
            'remove',
            'result',
        }:
            raise ValueError('malformed guest symlink inspection')
        if (
            not isinstance(entry['link'], str)
            or not isinstance(entry['target'], str)
            or type(entry['remove']) is not bool
        ):
            raise ValueError('invalid guest symlink inspection paths')
        links.append(
            (
                (entry['link'], entry['target'], entry['remove']),
                _result(entry['result']),
            )
        )
    if sorted(check for check, _ in links) != sorted(symlinks):
        raise ValueError(
            'guest inspection did not check the requested symlinks'
        )
    return GuestInspection(
        found, value['manifest_directory'], links, _result(value['replay'])
    )


def inspect_foreground(
    cfg: AgentVMConfig,
    ip: str,
    guest_dst: str,
    symlinks: list[SymlinkCheck],
) -> GuestInspection:
    source = session_inspect_python()
    files = {
        PERSISTENT_ATTACHMENT_REPLAY_BIN: persistent_replay_python(),
        f'/etc/systemd/system/{PERSISTENT_ATTACHMENT_REPLAY_SERVICE}': persistent_replay_service_unit(),
    }
    if any(not remove for _, _, remove in symlinks):
        files[GUEST_SYMLINK_BIN] = attachment_symlink_python()
    argv = ['sudo', '-n', GUEST_SESSION_INSPECT_BIN, '--guest-dst', guest_dst]
    for path, content in files.items():
        argv.extend(['--file', path, transport._guest_text_sha256(content)])
    for link, target, remove in symlinks:
        argv.extend(
            ['--remove-symlink' if remove else '--symlink', link, target]
        )
    # OpenSSH joins remote arguments. Quoting data individually keeps long
    # invocations readable without an anonymous program or omitted payload.
    command = [
        transport._guest_text_hash_check_script(
            GUEST_SESSION_INSPECT_BIN,
            transport._guest_text_sha256(source),
        )
        + ' &&',
        *(shlex.quote(arg) for arg in argv),
    ]

    def probe():
        with CommandManager.current().step(
            'Inspect guest workspace',
            why='Check helper versions, requested symlinks, and live mount identity together without changing guest state.',
        ):
            return transport._run_guest_root_script(
                cfg,
                ip,
                script=command,
                summary='Inspect requested guest workspace',
                detail=f'target={guest_dst}',
                dry_run=False,
                role='read',
                allowed_exit_codes=(0, 1),
            )

    result = probe()
    assert result is not None
    if result.code == 1:
        changed = transport._install_guest_text_if_changed(
            cfg,
            ip,
            target=GUEST_SESSION_INSPECT_BIN,
            text=source,
            mode='0755',
            label='guest session inspection helper',
            dry_run=False,
        )
        if not changed:
            raise RuntimeError(result.stderr or 'guest inspection failed')
        result = probe()
        assert result is not None
    if result.code:
        raise RuntimeError(
            result.stderr or 'guest inspection failed after helper install'
        )
    return _decode(result.stdout, files, symlinks)


def apply_symlink_repairs(
    cfg: AgentVMConfig, ip: str, inspection: GuestInspection
) -> bool:
    # Import at execution time: guest attachment dispatch also imports replay.
    from ..guest import (
        _ensure_guest_symlink,
        _remove_guest_symlink_if_target,
        log,
    )

    attempted = False
    for (link, target, remove), result in inspection.symlinks:
        if result is not None and result.code == 0:
            continue
        if result is not None and result.code in (3, 4, 5):
            log.warning('{}', result.stderr.replace('aivm-symlink-warn: ', ''))
            continue
        if result is not None and result.code != 10:
            raise RuntimeError(
                result.stderr or 'guest symlink inspection failed'
            )
        repair = (
            _remove_guest_symlink_if_target if remove else _ensure_guest_symlink
        )
        repair(cfg, ip, symlink_path=link, target_path=target)
        attempted = True
    return attempted
