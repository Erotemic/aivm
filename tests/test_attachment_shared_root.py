"""Tests for shared-root host/guest bind mechanics."""

from __future__ import annotations

import builtins
import os
from pathlib import Path
from typing import Any

import pytest

from aivm.attachments.shared_root import (
    _ensure_shared_root_guest_bind,
    _ensure_shared_root_host_bind,
    _target_is_bind_of,
)
from aivm.config import AgentVMConfig
from aivm.status import ProbeOutcome
from aivm.vm.share import AttachmentAccess, AttachmentMode, ResolvedAttachment
from tests.helpers import (
    FakeLog,
    FakeProc,
    activate_manager,
    command_recorder,
)


def _shared_root_attachment(
    tmp_path: Path,
    *,
    name: str = 'vm-shared-root',
    tag: str = 'hostcode-source',
    source_name: str = 'source',
    guest_dst: str = '/workspace/source',
    access: AttachmentAccess = AttachmentAccess.RW,
    base_dir: bool = True,
    make_source: bool = True,
    resolve_source: bool = True,
    user: str | None = None,
    ssh_identity_file: str | None = None,
) -> tuple[AgentVMConfig, Path, ResolvedAttachment]:
    """Build the ``cfg`` + ``source_dir`` + ``ResolvedAttachment`` trio.

    Every shared-root test opens with the same scaffolding; the keyword
    arguments cover the handful of axes that actually differ between
    tests (the VM name, whether the source directory is created, whether
    a base storage dir and SSH identity are configured, and the access
    mode).
    """
    cfg = AgentVMConfig()
    cfg.vm.name = name
    if base_dir:
        cfg.paths.base_dir = str(tmp_path / 'base')
    if user is not None:
        cfg.vm.user = user
    if ssh_identity_file is not None:
        cfg.paths.ssh_identity_file = ssh_identity_file
    source_dir = tmp_path / source_name
    if make_source:
        source_dir.mkdir()
    src = str(source_dir.resolve()) if resolve_source else str(source_dir)
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED_ROOT,
        access=access,
        source_dir=src,
        guest_dst=guest_dst,
        tag=tag,
    )
    return cfg, source_dir, attachment


def _capture_command_logs(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    # The command manager calls ``log.opt(...)`` at runtime, so the patched
    # attribute must stay callable; the shared ``capture_logs`` helper (which
    # patches the target with a bare recorder) is not a drop-in here.
    messages: list[str] = []
    fake = FakeLog(messages, levels=('info', 'warning', 'error'))
    monkeypatch.setattr('aivm.commands.log.opt', lambda **kwargs: fake)
    return messages


def test_vm_attach_shared_root_running_ensures_guest_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from aivm.cli.vm_attach import VMAttachCLI

    cfg, host_src, attachment = _shared_root_attachment(
        tmp_path,
        source_name='proj',
        guest_dst='/workspace/proj',
        tag='hostcode-proj',
        base_dir=False,
    )
    cfg_path = tmp_path / 'config.toml'

    monkeypatch.setattr(
        'aivm.cli.vm_attach.load_cfg_with_path',
        lambda *a, **k: (cfg, cfg_path),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.record_vm', lambda *a, **k: cfg_path
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_attachment',
        lambda *a, **k: attachment,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach.probe_vm_state',
        lambda *a, **k: (
            ProbeOutcome(True, 'vm-shared-root state=running'),
            True,
        ),
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._record_attachment', lambda *a, **k: cfg_path
    )

    host_bind_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._ensure_shared_root_host_bind',
        lambda *a, **k: host_bind_calls.append((a, k)) or Path('/tmp/token'),
    )
    vm_mapping_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._ensure_shared_root_vm_mapping',
        lambda *a, **k: vm_mapping_calls.append((a, k)) or None,
    )
    monkeypatch.setattr(
        'aivm.cli.vm_attach._resolve_ip_for_ssh_ops',
        lambda *a, **k: '10.77.0.99',
    )
    guest_ready_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.cli.vm_attach._ensure_attachment_available_in_guest',
        lambda *a, **k: guest_ready_calls.append((a, k)) or None,
    )

    rc = VMAttachCLI.main(
        argv=False,
        config=str(cfg_path),
        host_src=str(host_src),
        mode='shared-root',
        yes=True,
    )

    assert rc == 0
    assert len(host_bind_calls) == 0
    assert len(vm_mapping_calls) == 0
    assert len(guest_ready_calls) == 1
    _, guest_kwargs = guest_ready_calls[0]
    assert guest_kwargs['ensure_shared_root_host_side'] is True


def test_shared_root_host_bind_does_not_unmount_when_target_not_mountpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-bind'
    )

    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            'mkdir -p': FakeProc(0),
            'findmnt -P -n': FakeProc(1),
            'mount --bind': FakeProc(0),
            'bash -c': FakeProc(0),
        },
    )

    _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=True,
        dry_run=False,
    )

    assert rec.ran(
        'findmnt', '-P', '-n', '-o', 'SOURCE,FSROOT,FSTYPE,OPTIONS', '--mountpoint'
    )
    assert rec.ran('mount', '--bind')
    assert not rec.ran('umount')


def test_shared_root_host_bind_accepts_findmnt_bind_subpath_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-bind-existing'
    )

    activate_manager(monkeypatch)
    # An unhandled command raises, so an unexpected umount/mount is caught
    # by the recorder itself rather than by a hand-written branch.
    rec = command_recorder(
        monkeypatch,
        {
            'findmnt -P -n': FakeProc(
                0, f'SOURCE="{source_dir}[/sub]" FSROOT="" FSTYPE="" OPTIONS="rw"'
            ),
        },
    )

    _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=True,
        dry_run=False,
    )

    assert rec.ran(
        'findmnt', '-P', '-n', '-o', 'SOURCE,FSROOT,FSTYPE,OPTIONS', '--mountpoint'
    )
    assert not rec.ran('umount')
    assert not rec.ran('mount', '--bind')


def test_shared_root_host_bind_accepts_findmnt_device_subpath_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-bind-device-subpath'
    )

    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            'findmnt -P -n': FakeProc(
                0,
                f'SOURCE="/dev/vda1[{source_dir}]" FSROOT="" FSTYPE="" OPTIONS="rw"',
            ),
        },
    )

    _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=True,
        dry_run=False,
    )

    assert rec.ran(
        'findmnt', '-P', '-n', '-o', 'SOURCE,FSROOT,FSTYPE,OPTIONS', '--mountpoint'
    )
    assert not rec.ran('umount')
    assert not rec.ran('mount', '--bind')


def test_shared_root_host_bind_lazy_unmounts_busy_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-bind-busy'
    )

    activate_manager(monkeypatch)
    target = (
        Path(cfg.paths.base_dir) / cfg.vm.name / 'shared-root' / attachment.tag
    )
    rec = command_recorder(
        monkeypatch,
        {
            'mkdir -p': FakeProc(0),
            'findmnt -P -n': FakeProc(
                0, 'SOURCE="/other/source" FSROOT="" FSTYPE=""'
            ),
            'bash -c': FakeProc(0),
        },
    )

    _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=True,
        dry_run=False,
    )

    repair_cmd = rec.only('bash', '-c')[2]
    assert f'umount {target}' in repair_cmd
    assert f'umount -l {target}' in repair_cmd
    assert f'mount --bind {source_dir}' in repair_cmd


def test_shared_root_host_bind_refuses_disruptive_rebind_when_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-safe-restore'
    )

    activate_manager(monkeypatch)
    # No umount/mount route: if the non-disruptive path issued one, the
    # recorder would raise on the unexpected command.
    rec = command_recorder(
        monkeypatch,
        {
            'findmnt -P -n': FakeProc(
                0, 'SOURCE="/other/source" FSROOT="" FSTYPE=""'
            ),
        },
    )

    with pytest.raises(RuntimeError, match='Refusing to replace existing'):
        _ensure_shared_root_host_bind(
            cfg,
            attachment,
            yes=True,
            dry_run=False,
            allow_disruptive_rebind=False,
        )

    assert rec.ran(
        'findmnt', '-P', '-n', '-o', 'SOURCE,FSROOT,FSTYPE,OPTIONS', '--mountpoint'
    )
    assert not rec.ran('umount')
    assert not rec.ran('mount', '--bind')


def test_shared_root_host_bind_tolerates_not_mounted_during_repair(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-not-mounted'
    )

    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {
            'findmnt -P -n': FakeProc(
                0, 'SOURCE="/dev/nvme0n1p1" FSROOT="" FSTYPE=""'
            ),
            'mkdir -p': FakeProc(0),
            'bash -c': FakeProc(0),
        },
    )

    target = _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=True,
        dry_run=False,
    )

    assert target.name == attachment.tag
    script = rec.only('bash', '-c')[2]
    assert '"not mounted"' in script
    assert 'mount --bind' in script


def test_shared_root_guest_bind_read_only_sets_bind_remount_ro(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path,
        name='vm-shared-root-ro',
        tag='token-source',
        access=AttachmentAccess.RO,
        base_dir=False,
        make_source=False,
        user='agent',
        ssh_identity_file='/tmp/id_ed25519',
    )

    activate_manager(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.shared_root.require_ssh_identity',
        lambda p: p or '/tmp/id_ed25519',
    )
    monkeypatch.setattr(
        'aivm.attachments.shared_root.ssh_base_args',
        lambda *a, **k: ['-i', '/tmp/id_ed25519'],
    )
    cmds: list[list[str]] = []
    run_kwargs: list[dict] = []

    # A hand fake here (rather than command_recorder) because the test
    # asserts on the per-call ``timeout`` kwarg, which the recorder drops.
    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        cmds.append([str(c) for c in cmd])
        run_kwargs.append(dict(kwargs))
        return FakeProc(0, '', '')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_subprocess_run)

    _ensure_shared_root_guest_bind(
        cfg,
        '10.0.0.2',
        attachment,
        dry_run=False,
    )

    assert len(cmds) == 2
    mount_script = cmds[0][-1]
    remote_script = cmds[1][-1]
    assert run_kwargs[0]['timeout'] == 20
    assert 'sudo -n mount -t virtiofs -o ro' not in mount_script
    assert 'sudo -n mount -t virtiofs aivm-shared-root' in mount_script
    assert 'sudo -n mount --bind' in remote_script
    assert 'mount -o remount,bind,ro' in remote_script
    assert 'umount -l' in remote_script
    assert 'findmnt -n -o ROOT --target' in remote_script
    assert 'stat -Lc %d:%i' in remote_script
    assert '[ "$cur" = \'aivm-shared-root[/token-source]\' ]' in remote_script
    assert (
        '[ "$final_src" = \'aivm-shared-root[/token-source]\' ]'
        in remote_script
    )
    assert (
        'shared-root bind verification failed: unexpected source'
        in remote_script
    )
    assert (
        'shared-root bind verification failed: unexpected mount options'
        in remote_script
    )


def test_shared_root_host_bind_prompts_once_per_privileged_step(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-plan'
    )

    activate_manager(monkeypatch, yes_sudo=False)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: True)
    messages = _capture_command_logs(monkeypatch)
    prompts: list[str] = []
    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or 'y',
    )

    # Hand fake retained: this test drives the interactive approval flow
    # (sudo auth probe + ``sudo -v``), which command_recorder deliberately
    # stubs out via ``confirm_sudo_scope``.
    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        parts = [str(part) for part in cmd]
        if parts[:3] == ['sudo', '-n', 'true']:
            return FakeProc(1, '', 'sudo: a password is required')
        if parts[:2] == ['sudo', '-v']:
            return FakeProc(0, '', '')
        normalized = parts[1:] if parts[:1] == ['sudo'] else parts
        if normalized[:3] == ['findmnt', '-P', '-n']:
            return FakeProc(1, '', '')
        if normalized[:2] == ['mkdir', '-p']:
            return FakeProc(0, '', '')
        if normalized[:2] == ['mount', '--bind']:
            return FakeProc(0, '', '')
        if normalized[:2] == ['bash', '-c']:
            return FakeProc(0, '', '')
        raise AssertionError(f'unexpected command: {cmd}')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_subprocess_run)

    _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=False,
        dry_run=False,
    )

    assert prompts == ['Approve this step? [y]es/[a]ll/[s]how/[N]o: ']
    assert 'Step: Inspect shared-root host bind state' in messages
    assert 'Step: Prepare host bind targets' in messages
    assert '  1. Create shared-root parent directory' in messages
    assert '  2. Create project-specific host bind target' in messages
    assert '  3. Bind requested host folder to shared-root target' in messages
    # base_dir is user-owned here, so creating the export directories needs no
    # privileges. Only `mount --bind`, which has no unprivileged form, does.
    assert any(msg.startswith('     command: mkdir -p ') for msg in messages)
    assert not any(
        msg.startswith('     command: sudo mkdir -p ') for msg in messages
    )
    assert any(
        msg.startswith('     command: sudo mount --bind ') for msg in messages
    )


def test_shared_root_host_bind_creates_export_dirs_without_sudo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A user-owned storage tree needs no privileges to create export dirs.

    This is what `privilege_mode = as-needed` buys after `aivm host permissions
    setup`: only `mount --bind` escalates.
    """
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-userowned'
    )

    activate_manager(monkeypatch, yes_sudo=True, yes=True)
    rec = command_recorder(
        monkeypatch,
        {'findmnt -P -n': FakeProc(1)},
        default=FakeProc(0),
    )

    _ensure_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)

    raw = rec.calls

    def _program_of(parts: list[str]) -> str:
        rest = parts[2:] if parts[:2] == ['sudo', '-n'] else parts
        rest = rest[1:] if rest[:1] == ['sudo'] else rest
        return rest[0] if rest else ''

    # `sudo -n true` is the auth probe, not a privileged operation.
    escalated = [p for p in raw if p[:1] == ['sudo'] and p[-1:] != ['true']]
    sudoed = {_program_of(p) for p in escalated}
    plain = {_program_of(p) for p in raw if p[:1] != ['sudo']}
    # mkdir and findmnt ran unprivileged; only the bind mount escalated.
    assert 'mkdir' in plain, raw
    assert 'findmnt' in plain, raw
    assert 'mkdir' not in sudoed, raw
    assert sudoed == {'mount'}, raw


def test_shared_root_host_bind_escalates_into_a_legacy_root_owned_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pre-existing root-owned export root still escalates the child mkdir.

    Hosts created before storage moved under the user keep a root-owned
    ``<base_dir>/<vm>/shared-root``. The decision is per-path, so the export
    root is skipped (it exists) and the per-project target below it still
    escalates. Simulated with a directory the invoking user owns but cannot
    write, which is what ``os.access(W_OK)`` reports for a root-owned one.
    """
    if os.geteuid() == 0:
        pytest.skip('root can write through any mode bits')

    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-legacy'
    )
    export_root = Path(cfg.paths.base_dir) / cfg.vm.name / 'shared-root'
    export_root.mkdir(parents=True)
    export_root.chmod(0o555)

    activate_manager(monkeypatch, yes_sudo=True, yes=True)
    rec = command_recorder(
        monkeypatch,
        {'findmnt -P -n': FakeProc(1)},
        default=FakeProc(0),
    )
    try:
        _ensure_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)
    finally:
        export_root.chmod(0o755)

    joined = [' '.join(p) for p in rec.calls]
    # The export root already exists, so no mkdir is issued for it at all.
    assert not any(
        line.endswith(str(export_root)) for line in joined if 'mkdir' in line
    )
    # The project target below it is unwritable, so its mkdir escalates.
    assert any(
        line.startswith('sudo')
        and 'mkdir -p' in line
        and 'hostcode-source' in line
        for line in joined
    ), rec.calls


def test_shared_root_host_bind_escalates_mkdir_when_base_dir_needs_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A root-owned storage tree still escalates the mkdir.

    The decision is per-path, so a host that never ran `aivm host permissions setup`
    behaves exactly as before.
    """
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-rootowned'
    )

    activate_manager(monkeypatch, yes_sudo=True, yes=True)
    monkeypatch.setattr(
        'aivm.attachments.shared_root.path_needs_sudo', lambda p: True
    )
    rec = command_recorder(
        monkeypatch,
        {'findmnt -P -n': FakeProc(1)},
        default=FakeProc(0),
    )

    _ensure_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)

    def _ran_with_sudo(program: str) -> bool:
        return any(
            parts[:1] == ['sudo'] and program in parts for parts in rec.calls
        )

    assert _ran_with_sudo('mkdir'), rec.calls
    assert _ran_with_sudo('mount'), rec.calls


def test_shared_root_host_bind_autoapproves_readonly_findmnt_when_auth_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-shared-root-readonly'
    )

    activate_manager(monkeypatch, yes_sudo=False)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: True)
    # The findmnt probe only escalates when the bind target is unreadable
    # without privileges, which is what a root-owned storage tree means.
    monkeypatch.setattr(
        'aivm.attachments.shared_root.path_needs_sudo', lambda p: True
    )
    messages = _capture_command_logs(monkeypatch)
    prompts: list[str] = []
    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or 'y',
    )

    # Hand fake retained: this test drives the interactive approval flow,
    # which command_recorder stubs out via ``confirm_sudo_scope``.
    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        parts = [str(part) for part in cmd]
        if parts[:3] == ['sudo', '-n', 'true']:
            return FakeProc(0, '', '')
        normalized = parts[1:] if parts[:1] == ['sudo'] else parts
        if normalized[:3] == ['findmnt', '-P', '-n']:
            return FakeProc(1, '', '')
        if normalized[:2] == ['mkdir', '-p']:
            return FakeProc(0, '', '')
        if normalized[:2] == ['mount', '--bind']:
            return FakeProc(0, '', '')
        if normalized[:2] == ['bash', '-c']:
            return FakeProc(0, '', '')
        raise AssertionError(f'unexpected command: {cmd}')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_subprocess_run)

    _ensure_shared_root_host_bind(
        cfg,
        attachment,
        yes=False,
        dry_run=False,
    )

    assert prompts == ['Approve this step? [y]es/[a]ll/[s]how/[N]o: ']
    assert 'Step: Inspect shared-root host bind state' in messages
    assert any(
        msg.startswith(
            '     command (read-only): sudo findmnt -P -n -o SOURCE,FSROOT,FSTYPE,OPTIONS --mountpoint '
        )
        for msg in messages
    )
    assert 'Step: Prepare host bind targets' in messages


def test_shared_root_vm_mapping_uses_named_steps_and_per_step_prompts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-shared-root-map'
    cfg.paths.base_dir = str(tmp_path / 'base')

    activate_manager(monkeypatch, yes_sudo=False)
    monkeypatch.setattr('aivm.commands.sys.stdin.isatty', lambda: True)
    messages = _capture_command_logs(monkeypatch)
    prompts: list[str] = []
    monkeypatch.setattr(
        builtins,
        'input',
        lambda prompt: prompts.append(prompt) or 'y',
    )

    # Hand fake retained: drives the interactive approval flow and the
    # virsh dumpxml/attach-device dispatch, which command_recorder does
    # not model.
    def fake_subprocess_run(cmd: list[str], **kwargs: Any) -> FakeProc:
        del kwargs
        parts = [str(part) for part in cmd]
        if parts[:3] == ['sudo', '-n', 'true']:
            return FakeProc(1, '', 'sudo: a password is required')
        if parts[:2] == ['sudo', '-v']:
            return FakeProc(0, '', '')
        normalized = parts[1:] if parts[:1] == ['sudo'] else parts
        if normalized[:3] == ['virsh', '-c', 'qemu:///system']:
            normalized = ['virsh'] + normalized[3:]
        if normalized[:2] == ['virsh', 'dumpxml']:
            return FakeProc(1, '', 'domain not visible')
        if normalized[:2] == ['virsh', 'attach-device']:
            return FakeProc(0, '', '')
        raise AssertionError(f'unexpected command: {cmd}')

    monkeypatch.setattr('aivm.commands.subprocess.run', fake_subprocess_run)

    from aivm.attachments.shared_root import _ensure_shared_root_vm_mapping

    _ensure_shared_root_vm_mapping(
        cfg,
        yes=False,
        dry_run=False,
        vm_running=True,
    )

    assert prompts == ['Approve this step? [y]es/[a]ll/[s]how/[N]o: ']
    # One inspect step covers both the unprivileged read and its internal
    # sudo escalation; the old separate privileged-inspect step is gone.
    assert 'Step: Inspect shared-root VM mapping' in messages
    assert 'Step: Ensure VM virtiofs mapping' in messages
    assert (
        '  1. Attach virtiofs device to running VM vm-shared-root-map'
        in messages
    )
    assert any(
        msg.startswith(
            '     command: sudo virsh -c qemu:///system attach-device '
        )
        for msg in messages
    )


def test_shared_root_guest_bind_preview_uses_semantic_summaries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path,
        name='vm-shared-root-preview',
        tag='token-source',
        access=AttachmentAccess.RW,
        base_dir=False,
        make_source=False,
        user='agent',
        ssh_identity_file='/tmp/id_ed25519',
    )

    activate_manager(monkeypatch)
    messages = _capture_command_logs(monkeypatch)
    monkeypatch.setattr(
        'aivm.attachments.shared_root.require_ssh_identity',
        lambda p: p or '/tmp/id_ed25519',
    )
    monkeypatch.setattr(
        'aivm.attachments.shared_root.ssh_base_args',
        lambda *a, **k: ['-i', '/tmp/id_ed25519'],
    )
    command_recorder(monkeypatch, default=FakeProc(0))

    _ensure_shared_root_guest_bind(
        cfg,
        '10.0.0.2',
        attachment,
        dry_run=False,
    )

    assert 'Step: Mount and verify inside guest' in messages
    assert '  1. Mount shared-root inside guest' in messages
    assert (
        '  2. Bind guest destination to shared source and verify source/options'
        in messages
    )
    assert any(
        msg.startswith('     command: ssh -i /tmp/id_ed25519 agent@10.0.0.2 ')
        for msg in messages
    )
    assert all('set -euo pipefail; if [ ! -d' not in msg for msg in messages)


def test_target_is_bind_of_detects_same_filesystem_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Same-fs bind mounts must be detected by stat equality alone.

    Bind mounts within a single filesystem leave the target's st_dev equal to
    its parent's, so an `os.path.ismount`-based check would return False even
    when the bind is healthy. The detector must rely on (st_dev, st_ino)
    equality between source and target instead. This regression test fakes
    that exact situation: ``target.stat()`` returns the same dev+ino as
    ``source.stat()`` while target's parent has its own dev+ino unchanged.
    """
    import os

    source = tmp_path / 'source'
    target = tmp_path / 'export' / 'tgt'
    source.mkdir()
    target.parent.mkdir()
    target.mkdir()

    real_stat = os.stat

    def fake_stat(path: Any, *, follow_symlinks: bool = True) -> os.stat_result:
        # Pretend `target` was bind-mounted from `source`: same dev+ino.
        path_str = os.fspath(path)
        if path_str == str(target):
            return real_stat(source, follow_symlinks=follow_symlinks)
        return real_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, 'stat', fake_stat)

    assert _target_is_bind_of(source, target) is True


def test_target_is_bind_of_returns_false_for_unrelated_dirs(
    tmp_path: Path,
) -> None:
    source = tmp_path / 'source'
    target = tmp_path / 'target'
    source.mkdir()
    target.mkdir()
    assert _target_is_bind_of(source, target) is False


def test_target_is_bind_of_returns_false_on_missing_target(
    tmp_path: Path,
) -> None:
    source = tmp_path / 'source'
    source.mkdir()
    target = tmp_path / 'does-not-exist'
    assert _target_is_bind_of(source, target) is False


def test_shared_root_detach_escalates_only_for_the_umount(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Detach on a user-owned tree escalates only for `umount`.

    `mountpoint` reads state and `rmdir` removes an entry from a directory
    the user owns, so neither needs privileges.
    """
    from aivm.attachments.shared_root import _detach_shared_root_host_bind

    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path,
        name='vm-detach',
        tag='proj',
        make_source=False,
        resolve_source=False,
    )
    # The export root exists and is user-owned, as after a successful attach.
    (Path(cfg.paths.base_dir) / cfg.vm.name / 'shared-root' / 'proj').mkdir(
        parents=True
    )

    activate_manager(monkeypatch, yes_sudo=True, yes=True)
    rec = command_recorder(monkeypatch, default=FakeProc(0))

    _detach_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)

    def program(parts: list[str]) -> str:
        rest = parts[2:] if parts[:2] == ['sudo', '-n'] else parts
        rest = rest[1:] if rest[:1] == ['sudo'] else rest
        return rest[0] if rest else ''

    real = [p for p in rec.calls if p[-1:] != ['true']]
    escalated = {program(p) for p in real if p[:1] == ['sudo']}
    plain = {program(p) for p in real if p[:1] != ['sudo']}
    assert 'mountpoint' in plain, rec.calls
    assert 'rmdir' in plain, rec.calls
    assert escalated == {'umount'}, rec.calls


def test_shared_root_read_only_is_enforced_on_host_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A read-only attachment remounts the new host bind ``ro``."""
    cfg, source_dir, attachment = _shared_root_attachment(
        tmp_path, name='vm-host-ro', access=AttachmentAccess.RO
    )

    activate_manager(monkeypatch)
    rec = command_recorder(
        monkeypatch,
        {'findmnt -P -n': FakeProc(1)},
        default=FakeProc(0),
    )

    _ensure_shared_root_host_bind(cfg, attachment, yes=True, dry_run=False)

    assert rec.ran('mount', '--bind')
    assert rec.ran('mount', '-o', 'remount,bind,ro')
