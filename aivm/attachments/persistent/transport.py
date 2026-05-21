"""Low-level guest/host transport helpers for persistent attachments.

This module owns the SSH/rsync retry machinery and the "install a text file
on the host or guest if its content changed" primitives. Higher layers
(``manifest``, ``host_bind``, ``replay``) call into here through the module
reference (e.g. ``transport._run_guest_root_script(...)``) so tests can
patch the lookup site uniformly.
"""

from __future__ import annotations

import hashlib
import shlex
import tempfile
import textwrap
import time
from pathlib import Path

from loguru import logger as log

from ...commands import (
    CommandError,
    CommandManager,
    CommandResult,
    CommandRole,
)
from ...config import AgentVMConfig
from ...runtime import require_ssh_identity, ssh_base_args


def _install_host_text_if_changed(
    target: Path,
    text: str,
    mode: str,
    *,
    label: str,
    dry_run: bool,
) -> bool:
    new_bytes = text.encode('utf-8')
    if target.exists() and target.read_bytes() == new_bytes:
        return False
    if dry_run:
        print(f'DRYRUN: would install {label} to {target}')
        return True
    with tempfile.NamedTemporaryFile('wb', delete=False) as file:
        file.write(new_bytes)
        tmp_name = file.name
    mgr = CommandManager.current()
    try:
        with mgr.step(
            f'Install {label}',
            why=f'Install updated host-side {label} content for persistent attachment replay.',
            approval_scope=f'{label.replace(" ", "-")}:host:{target}',
        ):
            mgr.submit(
                ['mkdir', '-p', str(target.parent)],
                sudo=True,
                role='modify',
                summary=f'Create parent directory for {label}',
                detail=f'target={target.parent}',
            )
            mgr.submit(
                ['install', '-m', mode, tmp_name, str(target)],
                sudo=True,
                role='modify',
                summary=f'Install {label}',
                detail=f'target={target}',
            )
    finally:
        Path(tmp_name).unlink(missing_ok=True)
    return True


def _write_text_if_changed(path: Path, text: str) -> bool:
    import os

    new_bytes = text.encode('utf-8')
    if path.exists() and path.read_bytes() == new_bytes:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        'wb',
        dir=str(path.parent),
        delete=False,
    ) as file:
        file.write(new_bytes)
        tmp_name = file.name
    os.replace(tmp_name, path)
    return True


def _run_guest_root_script(
    cfg: AgentVMConfig,
    ip: str,
    *,
    script: str,
    summary: str,
    detail: str,
    dry_run: bool,
    role: CommandRole | None = None,
    check: bool = True,
) -> CommandResult | None:
    result = _run_guest_ssh_script_with_retry(
        cfg,
        ip,
        script=script,
        summary=summary,
        detail=detail,
        dry_run=dry_run,
        role=role,
        check=check,
        connect_timeout_s=15,
        retries=3,
    )
    if not check:
        code = int(getattr(result, 'code', getattr(result, 'returncode', 0)))
        if code != 0:
            stderr = str(getattr(result, 'stderr', '') or '').strip()
            stdout = str(getattr(result, 'stdout', '') or '').strip()
            raise RuntimeError(
                stderr or stdout or f'guest command failed code={code}'
            )
    return result


def _guest_text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _guest_text_stats(text: str) -> tuple[str, int]:
    payload = text.encode('utf-8')
    return hashlib.sha256(payload).hexdigest(), len(payload)


def _guest_text_hash_check_script(target: str, expected_sha256: str) -> str:
    target_q = shlex.quote(target)
    expected_q = shlex.quote(expected_sha256)
    return textwrap.dedent(
        f"""\
        set -euo pipefail
        if [ ! -f {target_q} ]; then
            printf '%s\\n' MISSING
            exit 0
        fi
        actual="$(sudo -n sha256sum {target_q} | cut -d ' ' -f1)"
        if [ "$actual" = {expected_q} ]; then
            printf '%s\\n' MATCH
        else
            printf '%s\\n' MISMATCH
        fi
        """
    ).strip()


def _guest_text_install_script(target: str, text: str, mode: str) -> str:
    target_dir = shlex.quote(str(Path(target).parent))
    target_q = shlex.quote(target)
    text_q = shlex.quote(text)
    return '\n'.join(
        [
            'set -euo pipefail',
            'tmp="$(mktemp)"',
            f"printf '%s' {text_q} > \"$tmp\"",
            f'sudo -n mkdir -p {target_dir}',
            f'sudo -n install -m {mode} "$tmp" {target_q}',
            'rm -f "$tmp"',
        ]
    )


def _is_transient_ssh_transport_failure(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            'connection timed out during banner exchange',
            'connection timed out',
            'connection refused',
            'connection reset by peer',
            'connection closed by remote host',
            'broken pipe',
            'kex_exchange_identification',
            'no route to host',
        )
    )


def _run_guest_ssh_script_with_retry(
    cfg: AgentVMConfig,
    ip: str,
    *,
    script: str,
    summary: str,
    detail: str,
    dry_run: bool,
    role: CommandRole | None = None,
    check: bool = True,
    connect_timeout_s: int = 15,
    retries: int = 3,
) -> CommandResult | None:
    ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    cmd = [
        'ssh',
        *ssh_base_args(
            ident,
            strict_host_key_checking='accept-new',
            connect_timeout=connect_timeout_s,
            batch_mode=True,
        ),
        f'{cfg.vm.user}@{ip}',
        script,
    ]
    if dry_run:
        print(
            f'DRYRUN: would run guest reconcile command: {" ".join(shlex.quote(c) for c in cmd)}'
        )
        return None
    mgr = CommandManager.current()
    last_result: object | None = None
    for attempt in range(retries + 1):
        result = mgr.run(
            cmd,
            sudo=False,
            role=role,
            check=False,
            capture=True,
            summary=summary,
            detail=detail,
        )
        last_result = result
        code = int(getattr(result, 'code', getattr(result, 'returncode', 0)))
        if code == 0:
            return result
        stderr = str(getattr(result, 'stderr', '') or '').strip()
        stdout = str(getattr(result, 'stdout', '') or '').strip()
        transport_error = '\n'.join(
            part for part in (stderr, stdout, f'code={code}') if part
        )
        if attempt < retries and _is_transient_ssh_transport_failure(
            transport_error
        ):
            log.warning(
                (
                    'Transient SSH failure while {} (attempt {}/{}): {}'
                ),
                summary,
                attempt + 1,
                retries + 1,
                stderr or stdout or f'code={code}',
            )
            time.sleep(min(2 * (attempt + 1), 6))
            continue
        if check:
            raise CommandError(cmd, CommandResult(code, stdout, stderr))
        return result
    return last_result


def _run_rsync_with_retry(
    cmd: list[str],
    *,
    summary: str,
    detail: str,
    dry_run: bool,
    check: bool = True,
    retries: int = 3,
) -> CommandResult | None:
    if dry_run:
        print(
            f'DRYRUN: would run rsync command: {" ".join(shlex.quote(c) for c in cmd)}'
        )
        return None
    mgr = CommandManager.current()
    last_result: object | None = None
    for attempt in range(retries + 1):
        result = mgr.run(
            cmd,
            sudo=False,
            role='modify',
            check=False,
            capture=True,
            summary=summary,
            detail=detail,
        )
        last_result = result
        code = int(getattr(result, 'code', getattr(result, 'returncode', 0)))
        if code == 0:
            return result
        stderr = str(getattr(result, 'stderr', '') or '').strip()
        stdout = str(getattr(result, 'stdout', '') or '').strip()
        transport_error = '\n'.join(
            part for part in (stderr, stdout, f'code={code}') if part
        )
        if attempt < retries and _is_transient_ssh_transport_failure(
            transport_error
        ):
            log.warning(
                (
                    'Transient rsync failure while {} (attempt {}/{}): {}'
                ),
                summary,
                attempt + 1,
                retries + 1,
                stderr or stdout or f'code={code}',
            )
            time.sleep(min(2 * (attempt + 1), 6))
            continue
        if check:
            raise CommandError(cmd, CommandResult(code, stdout, stderr))
        return result
    return last_result


def _diagnose_guest_text_mismatch(
    cfg: AgentVMConfig,
    ip: str,
    *,
    target: str,
    text: str,
    label: str,
    dry_run: bool,
) -> None:
    if dry_run:
        return
    expected_sha256, expected_len = _guest_text_stats(text)
    expected_bytes = text.encode('utf-8')
    target_q = shlex.quote(target)
    stats = _run_guest_root_script(
        cfg,
        ip,
        script=(
            'set -euo pipefail; '
            f'if [ ! -f {target_q} ]; then printf "%s\\n" MISSING; exit 0; fi; '
            f'printf "%s\\n" "$(sudo -n sha256sum {target_q} | cut -d " " -f1)"; '
            f'printf "%s\\n" "$(sudo -n wc -c < {target_q})"'
        ),
        summary=f'Inspect {label} hash mismatch details',
        detail=f'target={target}',
        dry_run=dry_run,
        role='read',
        check=False,
    )
    actual_sha256 = ''
    actual_len = -1
    if stats is not None:
        lines = [line.strip() for line in str(getattr(stats, 'stdout', '') or '').splitlines()]
        if lines:
            actual_sha256 = lines[0]
        if len(lines) > 1:
            try:
                actual_len = int(lines[1])
            except ValueError:
                actual_len = -1
    content = _run_guest_root_script(
        cfg,
        ip,
        script=f'sudo -n cat {target_q}',
        summary=f'Fetch {label} content for verification',
        detail=f'target={target}',
        dry_run=dry_run,
        role='read',
        check=False,
    )
    assert content is not None
    actual_bytes = (content.stdout or '').encode('utf-8')
    actual_sha_calc = hashlib.sha256(actual_bytes).hexdigest()
    actual_len_calc = len(actual_bytes)
    host_file = None
    with tempfile.NamedTemporaryFile('wb', delete=False) as file:
        file.write(expected_bytes)
        host_file = Path(file.name)
    try:
        host_bytes = host_file.read_bytes()
        same_bytes = host_bytes == actual_bytes
    finally:
        host_file.unlink(missing_ok=True)
    log.warning(
        (
            '{} mismatch after install: expected_sha256={} actual_sha256={} '
            'expected_bytes={} actual_bytes={} byte_for_byte_match={}'
        ),
        label,
        expected_sha256,
        actual_sha256 or actual_sha_calc,
        expected_len,
        actual_len if actual_len >= 0 else actual_len_calc,
        same_bytes,
    )


def _install_guest_text_if_changed(
    cfg: AgentVMConfig,
    ip: str,
    *,
    target: str,
    text: str,
    mode: str,
    label: str,
    dry_run: bool,
    check: bool = True,
) -> bool:
    label = str(label).strip() or 'guest text'
    label_title = label[0].upper() + label[1:]
    expected_sha256 = _guest_text_sha256(text)
    check_script = _guest_text_hash_check_script(target, expected_sha256)
    mgr = CommandManager.current()
    with mgr.step(
        f'Check {label} hash',
        why=(
            'Compare the host-rendered helper content against the guest copy '
            'using a checksum so unchanged files stay untouched.'
        ),
        approval_scope=f'{label.replace(" ", "-")}:check:{cfg.vm.name}:{target}',
    ):
        check_result = _run_guest_root_script(
            cfg,
            ip,
            script=check_script,
            summary=f'Check {label} hash',
            detail=f'target={target} expected_sha256={expected_sha256}',
            dry_run=dry_run,
            role='read',
            check=check,
        )
    if dry_run or check_result is None:
        return False
    status = str(getattr(check_result, 'stdout', '') or '').strip().splitlines()
    status = status[-1].strip().upper() if status else ''
    if status not in {'MATCH', 'MISSING', 'MISMATCH'}:
        raise RuntimeError(
            f'Unexpected guest file hash check result for {target}: {status or "<empty>"}'
        )
    log.info('{} hash check result: {}', label_title, status)
    if status == 'MATCH':
        return False
    with mgr.step(
        f'{label_title} differs, installing updated content',
        why=(
            'The guest file hash did not match the host-rendered content, so '
            'the updated file must be written explicitly.'
        ),
        approval_scope=f'{label.replace(" ", "-")}:{cfg.vm.name}:{target}',
    ):
        write_script = _guest_text_install_script(target, text, mode)
        _run_guest_root_script(
            cfg,
            ip,
            script=write_script,
            summary=f'Install {label}',
            detail=f'target={target} expected_sha256={expected_sha256}',
            dry_run=dry_run,
            role='modify',
            check=check,
        )
        verify_result = _run_guest_root_script(
            cfg,
            ip,
            script=check_script,
            summary=f'Verify {label} hash after install',
            detail=f'target={target} expected_sha256={expected_sha256}',
            dry_run=dry_run,
            role='read',
            check=False,
        )
        if verify_result is not None:
            verify_status = (
                str(getattr(verify_result, 'stdout', '') or '')
                .strip()
                .splitlines()
            )
            verify_status = verify_status[-1].strip().upper() if verify_status else ''
            if verify_status != 'MATCH':
                _diagnose_guest_text_mismatch(
                    cfg,
                    ip,
                    target=target,
                    text=text,
                    label=label_title,
                    dry_run=dry_run,
                )
                raise RuntimeError(
                    f'{label_title} still mismatched after install: '
                    f'target={target} status={verify_status or "<empty>"} '
                    f'expected_sha256={expected_sha256}'
                )
    return True
