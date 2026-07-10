"""Tests for guest-side symlink creation, git helpers, and apply_guest_derived_symlinks."""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aivm.attachments.guest import (
    _apply_guest_derived_symlinks,
    _ensure_guest_symlink,
    _git_attachment_remote_name,
    _upsert_host_git_remote,
)
from aivm.config import AgentVMConfig
from aivm.vm.share import AttachmentMode, ResolvedAttachment
from tests.helpers import (
    CommandRecorder,
    FakeProc,
    activate_manager,
    capture_logs,
    command_recorder,
)


def _ssh_scripts(recorder: CommandRecorder) -> list[str]:
    """The trailing script argument of every recorded guest ssh command."""
    return [cmd[-1] for cmd in recorder.normalized if cmd[:1] == ['ssh']]


def _assert_every_ln_is_symbolic(script: str) -> None:
    """Fail if the script links anything with a bare ``ln``.

    ``_ensure_guest_symlink`` emits ``ln -s`` from two different branches
    -- the empty-directory branch and the nothing-there branch. A check
    that merely finds *an* ``ln -s`` somewhere in the script cannot see
    one branch degrade to a hard link, because the other branch's
    ``ln -s`` still matches. Reject every ``ln`` that is not ``ln -s``.
    """
    bare = re.findall(r'\bln\b(?! -s\b)', script)
    assert not bare, f'script hard-links instead of symlinking: {script}'


def _recorded_symlinks(recorder: CommandRecorder) -> list[dict[str, str]]:
    """Extract every guest symlink the recorded ssh scripts would create.

    The real ``_ensure_guest_symlink`` emits one ssh command per symlink
    whose script contains ``ln -s <target> <link>``. Reading the pair back
    out of the recorded script is a stronger artifact than trusting a stub
    to report the arguments it was handed, and it pins the ``target``/
    ``link`` order so a swapped-argument regression is observable.

    Every ``ln -s`` in one script must agree on the pair, so that a single
    corrupted branch cannot hide behind a correct sibling branch.
    """
    out: list[dict[str, str]] = []
    for script in _ssh_scripts(recorder):
        _assert_every_ln_is_symbolic(script)
        pairs = re.findall(r'ln -s ([^\s;]+) ([^\s;]+)', script)
        assert pairs, f'no `ln -s` in recorded script: {script}'
        assert len(set(pairs)) == 1, f'inconsistent `ln -s` pairs: {pairs}'
        target, link = pairs[0]
        out.append({'target_path': target, 'symlink_path': link})
    return out


def _ran_guest_symlink(
    recorder: CommandRecorder, *, symlink_path: str, target_path: str
) -> bool:
    """True when a recorded ssh script links ``symlink_path`` -> ``target_path``.

    Matches the helper's ``ln -s <target> <link>`` argument order, and
    holds every branch of the script to it (see
    :func:`_assert_every_ln_is_symbolic`).
    """
    needle = f'ln -s {shlex.quote(target_path)} {shlex.quote(symlink_path)}'
    for script in _ssh_scripts(recorder):
        if needle in script:
            _assert_every_ln_is_symbolic(script)
            return True
    return False


@pytest.fixture
def guest_ssh_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Activate a command manager for the guest ``_ensure_*`` helpers.

    Every ``_ensure_guest_*`` test opens by activating a command manager.
    The real ``require_ssh_identity``/``ssh_base_args`` are left in place so
    the recorded ssh argv carries the production base args
    (``StrictHostKeyChecking``, ``IdentitiesOnly``, ``-i <identity>``); each
    test supplies a non-empty ``ssh_identity_file`` so the identity check
    passes.
    """
    activate_manager(monkeypatch)


def test_upsert_host_git_remote_adds_remote(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
    subprocess.run(
        ['git', '-C', str(repo), 'config', 'user.email', 'test@example.com'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', '-C', str(repo), 'config', 'user.name', 'Test User'],
        check=True,
        capture_output=True,
    )
    (repo / 'README').write_text('hello\n', encoding='utf-8')
    subprocess.run(
        ['git', '-C', str(repo), 'add', 'README'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', '-C', str(repo), 'commit', '-m', 'init'],
        check=True,
        capture_output=True,
    )

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    remote_name = _git_attachment_remote_name(cfg, repo)
    prompts: list[str] = []

    def _capture_prompt(**kwargs: Any) -> None:
        prompts.append(kwargs['purpose'])

    monkeypatch.setattr(
        'aivm.attachments.guest.CommandManager.confirm_file_update',
        lambda self, **kwargs: _capture_prompt(**kwargs),
    )
    _, updated = _upsert_host_git_remote(
        repo,
        remote_name=remote_name,
        remote_url='vm-git:/workspace/repo',
        yes=True,
    )

    assert updated is True
    assert prompts == [
        f"Register Git remote '{remote_name}' with URL 'vm-git:/workspace/repo'."
    ]
    probe = subprocess.run(
        ['git', '-C', str(repo), 'remote', 'get-url', remote_name],
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.strip() == 'vm-git:/workspace/repo'


def test_upsert_host_git_remote_updates_remote_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
    subprocess.run(
        ['git', '-C', str(repo), 'config', 'user.email', 'test@example.com'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', '-C', str(repo), 'config', 'user.name', 'Test User'],
        check=True,
        capture_output=True,
    )
    (repo / 'README').write_text('hello\n', encoding='utf-8')
    subprocess.run(
        ['git', '-C', str(repo), 'add', 'README'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', '-C', str(repo), 'commit', '-m', 'init'],
        check=True,
        capture_output=True,
    )

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git'
    remote_name = _git_attachment_remote_name(cfg, repo)
    subprocess.run(
        [
            'git',
            '-C',
            str(repo),
            'remote',
            'add',
            remote_name,
            'vm-git:/old/path',
        ],
        check=True,
        capture_output=True,
    )
    prompts: list[str] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.CommandManager.confirm_file_update',
        lambda self, **kwargs: prompts.append(kwargs['purpose']),
    )
    _, updated = _upsert_host_git_remote(
        repo,
        remote_name=remote_name,
        remote_url='vm-git:/workspace/repo',
        yes=True,
    )

    assert updated is True
    assert prompts == [
        (
            f"Update Git remote '{remote_name}' URL from 'vm-git:/old/path' "
            "to 'vm-git:/workspace/repo'."
        )
    ]
    probe = subprocess.run(
        ['git', '-C', str(repo), 'remote', 'get-url', remote_name],
        check=True,
        capture_output=True,
        text=True,
    )
    assert probe.stdout.strip() == 'vm-git:/workspace/repo'


def test_upsert_host_git_remote_raises_on_invalid_repo(tmp_path: Path) -> None:
    repo = tmp_path / 'not-a-repo'
    repo.mkdir()

    with pytest.raises(RuntimeError, match='Could not locate Git config'):
        _upsert_host_git_remote(
            repo,
            remote_name='aivm-test',
            remote_url='vm-git:/workspace/repo',
            yes=True,
        )


def test_ensure_guest_symlink_creates_new_symlink(
    monkeypatch: pytest.MonkeyPatch, guest_ssh_env: None
) -> None:
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-symlink'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'

    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _ensure_guest_symlink(
        cfg,
        '10.0.0.1',
        symlink_path='/home/joncrall/code/repo',
        target_path='/home/joncrall/code/repo',
    )

    cmd = recorder.only('ssh')
    # The real ssh_base_args ran, so the identity and hardening flags are
    # part of the recorded argv (not stubbed away).
    assert cmd[0] == 'ssh'
    assert 'StrictHostKeyChecking=accept-new' in cmd
    assert '/tmp/id_ed25519' in cmd
    assert cmd[-2] == 'agent@10.0.0.1'
    script = cmd[-1]
    assert 'ln -s' in script
    assert '/home/joncrall/code/repo' in script


@pytest.mark.parametrize(
    ('exit_code', 'stderr', 'expected_message'),
    [
        pytest.param(0, '', None, id='noop_on_correct_existing_symlink'),
        pytest.param(
            3,
            'aivm-symlink-warn: /link is a symlink to /other; skipping',
            '/link is a symlink to /other; skipping',
            id='warns_on_wrong_existing_symlink',
        ),
        pytest.param(
            4,
            'aivm-symlink-warn: /link is a non-empty directory; skipping',
            '/link is a non-empty directory; skipping',
            id='warns_on_nonempty_dir',
        ),
        pytest.param(
            5,
            'aivm-symlink-warn: /link is a regular file; skipping',
            '/link is a regular file; skipping',
            id='warns_on_regular_file',
        ),
    ],
)
def test_ensure_guest_symlink_exit_code_handling(
    monkeypatch: pytest.MonkeyPatch,
    guest_ssh_env: None,
    exit_code: int,
    stderr: str,
    expected_message: str | None,
) -> None:
    """The guest symlink helper warns per exit code and is silent on 0.

    Assert the *exact* warning, not a substring of it. Each of these exit
    codes is a recognized safety refusal, which the helper reports by
    stripping the ``aivm-symlink-warn:`` marker off the guest's stderr.
    An unrecognized code instead falls through to the transport-failure
    branch, which logs the raw stderr inside a ``Guest symlink setup
    failed ...`` sentence -- and that sentence still *contains* the
    guest's wording. Matching a substring therefore cannot tell the two
    branches apart; matching the whole message can.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-symlink-exit'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id_ed25519'
    messages = capture_logs(
        monkeypatch, 'aivm.attachments.guest.log', levels=('warning',)
    )
    command_recorder(monkeypatch, {'ssh': FakeProc(exit_code, '', stderr)})
    _ensure_guest_symlink(
        cfg, '10.0.0.1', symlink_path='/link', target_path='/tgt'
    )
    if expected_message is None:
        assert not messages
    else:
        assert messages == [expected_message]


def test_ensure_attachment_creates_mirror_home_symlink_when_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When mirror_home=True and conditions met, companion symlink is created."""
    from aivm.attachments.guest import _ensure_attachment_available_in_guest

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-mirror'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    host_src = tmp_path / 'code' / 'foobar'
    host_src.mkdir(parents=True)
    guest_dst = str(host_src.expanduser().absolute())
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=guest_dst,
        guest_dst=guest_dst,
        tag='hostcode-foobar-abc12345',
    )

    # The virtiofs mount is incidental here: it lives in aivm.vm and has its
    # own tests. Stubbing it keeps the recorded ssh log to just the symlink
    # scripts this test is about, while the real _ensure_guest_symlink runs.
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted', lambda *a, **k: None
    )

    # Patch Path.home to something known so mirror can be computed
    host_home = tmp_path
    monkeypatch.setattr('aivm.attachments.resolve.Path.home', lambda: host_home)

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _ensure_attachment_available_in_guest(
        cfg,
        host_src,
        attachment,
        '10.0.0.1',
        yes=True,
        dry_run=False,
        ensure_shared_root_host_side=False,
        mirror_home=True,
    )

    # Mirror symlink should have been created for /home/agent/code/foobar -> guest_dst
    expected_mirror = '/home/agent/code/foobar'
    assert _ran_guest_symlink(
        recorder, symlink_path=expected_mirror, target_path=guest_dst
    ), _recorded_symlinks(recorder)


def test_ensure_attachment_no_mirror_when_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When mirror_home=False, no companion symlink call happens."""
    from aivm.attachments.guest import _ensure_attachment_available_in_guest

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-no-mirror'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    host_src = tmp_path / 'code' / 'foobar'
    host_src.mkdir(parents=True)
    guest_dst = str(host_src.expanduser().absolute())
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=guest_dst,
        guest_dst=guest_dst,
        tag='hostcode-foobar-abc12345',
    )

    # Mount stubbed for the same reason as the mirror-enabled case: this test
    # asserts on the symlink decision, not the virtiofs mount.
    monkeypatch.setattr(
        'aivm.attachments.guest.ensure_share_mounted', lambda *a, **k: None
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _ensure_attachment_available_in_guest(
        cfg,
        host_src,
        attachment,
        '10.0.0.1',
        yes=True,
        dry_run=False,
        ensure_shared_root_host_side=False,
        mirror_home=False,
    )

    # No mirror flag and a non-symlink host_src whose lexical form already
    # equals guest_dst: no guest symlink command is emitted at all.
    assert _recorded_symlinks(recorder) == []


def test_ensure_guest_git_repo_uses_sudo_for_parent_creation(
    monkeypatch: pytest.MonkeyPatch, guest_ssh_env: None
) -> None:
    """_ensure_guest_git_repo script includes sudo mkdir for parent dirs."""
    from aivm.attachments.guest import _ensure_guest_git_repo

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git-exact'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _ensure_guest_git_repo(cfg, '/home/joncrall/code/myrepo')

    cmd = recorder.only('ssh')
    assert 'StrictHostKeyChecking=accept-new' in cmd
    script = cmd[-1]
    assert 'sudo -n mkdir -p' in script
    assert 'sudo -n chown' in script
    assert '/home/joncrall/code/myrepo' in script
    assert 'git init' in script
    # `updateInstead` is what lets a host-side `git push` move the guest's
    # checked-out branch; with the default `refuse` the push is rejected and
    # git-mode silently stops syncing. Pin the value, not just the key.
    assert 'receive.denyCurrentBranch updateInstead' in script
    assert 'symbolic-ref' not in script
    assert 'working tree' not in script


def test_ensure_guest_symlink_uses_sudo_for_ln(
    monkeypatch: pytest.MonkeyPatch, guest_ssh_env: None
) -> None:
    """symlink creation and dir removal must use sudo -n so non-writable parents work.

    The script is assembled before the ssh command runs, so an ssh
    *transport* failure (a code outside the ``0/3/4/5`` safety set) is
    orthogonal to how the script is built. Driving code 255 lets this case
    cover both the sudo-quoting of the script and the distinct
    transport-failure report the helper emits.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-sudo-ln'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    messages = capture_logs(
        monkeypatch, 'aivm.attachments.guest.log', levels=('warning',)
    )
    recorder = command_recorder(
        monkeypatch,
        {'ssh': FakeProc(255, '', 'ssh: connect to host 10.0.0.1: timed out')},
    )

    _ensure_guest_symlink(
        cfg,
        '10.0.0.1',
        symlink_path='/home/joncrall/code/repo',
        target_path='/home/joncrall/code/repo',
    )

    scripts = _ssh_scripts(recorder)
    assert scripts, 'expected SSH command'
    script = scripts[0]
    assert 'sudo -n ln -s' in script
    assert 'sudo -n mkdir -p' in script
    # plain ln -s (without sudo) must NOT appear
    assert '\nln -s' not in script
    assert '; ln -s' not in script
    # A non-safety exit code is reported as a transport failure.
    assert any('Guest symlink setup failed' in m for m in messages)


def test_ensure_guest_git_repo_uses_sudo_mkdir_for_full_path(
    monkeypatch: pytest.MonkeyPatch, guest_ssh_env: None
) -> None:
    """Exact-path git repo creation must sudo-mkdir the full root, not just the parent."""
    from aivm.attachments.guest import _ensure_guest_git_repo

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git-sudo'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _ensure_guest_git_repo(cfg, '/home/joncrall/code/myrepo')

    scripts = _ssh_scripts(recorder)
    assert scripts
    script = scripts[0]
    # Must sudo the full path, not just the parent
    assert 'sudo -n mkdir -p' in script
    assert '/home/joncrall/code/myrepo' in script
    assert 'sudo -n chown' in script
    # Confirm no stale parent_q variable reference (parent-only mkdir)
    assert 'sudo -n mkdir -p /home/joncrall/code\n' not in script
    assert 'symbolic-ref' not in script


def test_ensure_guest_git_repo_allows_existing_dirty_tree(
    monkeypatch: pytest.MonkeyPatch, guest_ssh_env: None
) -> None:
    from aivm.attachments.guest import _ensure_guest_git_repo

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git-dirty-guest'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _ensure_guest_git_repo(cfg, '/home/joncrall/code/dirty-repo')

    script = _ssh_scripts(recorder)[0]
    assert 'git init' in script
    assert 'is not empty and is not a git repo' not in script
    assert 'symbolic-ref' not in script


def test_ensure_git_clone_attachment_skips_push_and_dirty_warning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    guest_ssh_env: None,
) -> None:
    from aivm.attachments.guest import _ensure_git_clone_attachment

    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init'], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ['git', '-C', str(repo), 'config', 'user.email', 'test@example.com'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', '-C', str(repo), 'config', 'user.name', 'Test User'],
        check=True,
        capture_output=True,
    )
    (repo / 'tracked.txt').write_text('tracked\n', encoding='utf-8')
    subprocess.run(
        ['git', '-C', str(repo), 'add', 'tracked.txt'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['git', '-C', str(repo), 'commit', '-m', 'init'],
        check=True,
        capture_output=True,
    )
    (repo / 'dirty.txt').write_text('dirty\n', encoding='utf-8')

    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-git-light'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.GIT,
        source_dir=str(repo.resolve()),
        guest_dst='/workspace/repo',
        tag='',
    )

    monkeypatch.setattr(
        'aivm.attachments.guest._upsert_ssh_config_entry',
        lambda *a, **k: (tmp_path / 'ssh-config', False),
    )
    monkeypatch.setattr(
        'aivm.attachments.guest._upsert_host_git_remote',
        lambda *a, **k: (tmp_path / 'git-config', False),
    )
    guest_repo_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        'aivm.attachments.guest._ensure_guest_git_repo',
        lambda *a, **k: guest_repo_calls.append((a, k)) or None,
    )

    warnings: list[str] = []
    monkeypatch.setattr(
        'aivm.attachments.guest.log.warning',
        lambda fmt, *args: warnings.append(fmt.format(*args)),
    )

    repo_root, ssh_cfg, git_cfg = _ensure_git_clone_attachment(
        cfg,
        repo,
        attachment,
        '10.0.0.5',
        yes=True,
        dry_run=False,
    )

    assert repo_root == repo.resolve()
    assert ssh_cfg == str(tmp_path / 'ssh-config')
    assert git_cfg == str(tmp_path / 'git-config')
    assert guest_repo_calls
    assert warnings == []


def test_apply_guest_derived_symlinks_companion_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Companion symlink created when host_src is a symlink; no mirror without flag."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-deriv'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    real_dir = tmp_path / 'real'
    real_dir.mkdir()
    link_dir = tmp_path / 'link'
    link_dir.symlink_to(real_dir)

    resolved_dst = str(real_dir)
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=resolved_dst,
        guest_dst=resolved_dst,
        tag='tag1',
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _apply_guest_derived_symlinks(
        cfg, '10.0.0.1', link_dir, attachment, mirror_home=False
    )

    calls = _recorded_symlinks(recorder)
    assert len(calls) == 1
    assert calls[0]['symlink_path'] == str(link_dir.expanduser().absolute())
    assert calls[0]['target_path'] == resolved_dst


def test_apply_guest_derived_symlinks_dual_mirror_for_symlink_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When host_src is a symlink, mirror-home applies to both lexical and resolved paths."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-dual-mirror'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    # Set up: host_home = tmp_path
    # lexical = tmp_path/code/link  (symlink to tmp_path/real/code)
    # resolved = tmp_path/real/code
    host_home = tmp_path
    real_dir = tmp_path / 'real' / 'code'
    real_dir.mkdir(parents=True)
    code_dir = tmp_path / 'code'
    code_dir.mkdir()
    link_dir = code_dir / 'link'
    link_dir.symlink_to(real_dir)

    resolved_dst = str(real_dir)
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=resolved_dst,
        guest_dst=resolved_dst,
        tag='tag2',
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})
    monkeypatch.setattr('aivm.attachments.resolve.Path.home', lambda: host_home)

    _apply_guest_derived_symlinks(
        cfg, '10.0.0.1', link_dir, attachment, mirror_home=True
    )

    calls = _recorded_symlinks(recorder)
    symlink_paths = [c['symlink_path'] for c in calls]
    # Companion symlink at lexical guest path
    assert str(link_dir.expanduser().absolute()) in symlink_paths
    # Mirror for lexical host path (tmp_path/code/link -> guest home /home/agent/code/link)
    assert '/home/agent/code/link' in symlink_paths
    # Mirror for resolved host path (tmp_path/real/code -> guest home /home/agent/real/code)
    assert '/home/agent/real/code' in symlink_paths


def test_apply_guest_derived_symlinks_no_dup_mirror_when_same(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If both lexical and resolved mirrors compute to the same path, only one symlink is created."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-nodup'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    # host_home = tmp_path/home/joncrall
    # symlink: tmp_path/home/joncrall/proj -> tmp_path/home/joncrall/proj_real
    # lexical relative to home = proj; resolved relative to home = proj_real
    # They differ, so two distinct mirrors. This test verifies deduplication
    # when lexical == resolved (not a symlink - just sanity check no duplicate).
    real_dir = tmp_path / 'code'
    real_dir.mkdir()

    resolved_dst = str(real_dir)
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=resolved_dst,
        guest_dst=resolved_dst,
        tag='tag3',
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})
    monkeypatch.setattr('aivm.attachments.resolve.Path.home', lambda: tmp_path)

    # Not a symlink — no companion, only one mirror
    _apply_guest_derived_symlinks(
        cfg, '10.0.0.1', real_dir, attachment, mirror_home=True
    )

    calls = _recorded_symlinks(recorder)
    # Only one mirror call (for the non-symlink host, resolved branch is skipped)
    mirror_calls = [c for c in calls if '/home/agent' in c['symlink_path']]
    symlink_paths = [c['symlink_path'] for c in mirror_calls]
    # No duplicates
    assert len(symlink_paths) == len(set(symlink_paths))


def test_apply_guest_derived_symlinks_custom_dst_suppresses_all_mirrors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Custom guest_dst suppresses both lexical and resolved mirror-home creation."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-custom-dst'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    host_home = tmp_path
    real_dir = tmp_path / 'code' / 'proj'
    real_dir.mkdir(parents=True)
    link_dir = tmp_path / 'link' / 'proj'
    (tmp_path / 'link').mkdir()
    link_dir.symlink_to(real_dir)

    resolved_dst = str(real_dir)
    custom_dst = '/custom/guest/path'  # explicit non-default destination

    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.SHARED,
        source_dir=resolved_dst,
        guest_dst=custom_dst,
        tag='tag-custom',
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})
    monkeypatch.setattr('aivm.attachments.resolve.Path.home', lambda: host_home)

    _apply_guest_derived_symlinks(
        cfg, '10.0.0.1', link_dir, attachment, mirror_home=True
    )

    calls = _recorded_symlinks(recorder)
    # Companion symlink (lexical -> custom_dst) is allowed
    companion_calls = [
        c for c in calls if '/home/agent' not in c['symlink_path']
    ]
    mirror_calls = [c for c in calls if '/home/agent' in c['symlink_path']]

    # The companion symlink at the lexical path is expected (it points to custom_dst)
    assert len(companion_calls) == 1
    assert companion_calls[0]['symlink_path'] == str(
        link_dir.expanduser().absolute()
    )
    # No mirror-home symlinks should be created when guest_dst is custom
    assert mirror_calls == [], f'Expected no mirror calls, got: {mirror_calls}'


def test_apply_guest_derived_symlinks_multi_aliases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Every alias in extra_lexical_paths becomes a guest symlink.

    Regression for the intermediate-symlink case: the user attaches
    /data/proj (where /data is a symlink to /media/raid) and later attaches
    /old/data/proj (also resolving to the same canonical dir). Both lexical
    paths should be materialized in the guest as symlinks to the canonical
    guest_dst.
    """
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-multi-alias'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    real = tmp_path / 'real'
    real.mkdir()
    link_a = tmp_path / 'link-a'
    link_a.symlink_to(real)
    link_b = tmp_path / 'link-b'
    link_b.symlink_to(real)

    resolved_dst = str(real)
    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=resolved_dst,
        guest_dst=resolved_dst,
        tag='tag-multi',
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _apply_guest_derived_symlinks(
        cfg,
        '10.0.0.1',
        real,  # canonical host_src; aliases come from extra
        attachment,
        mirror_home=False,
        extra_lexical_paths=[str(link_a), str(link_b)],
    )

    calls = _recorded_symlinks(recorder)
    symlink_paths = [c['symlink_path'] for c in calls]
    assert str(link_a) in symlink_paths
    assert str(link_b) in symlink_paths
    # All point at the canonical guest_dst
    for c in calls:
        assert c['target_path'] == resolved_dst


def test_apply_guest_derived_symlinks_warns_on_stale_alias(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Stale alias (resolves elsewhere now) still creates symlink but warns."""
    cfg = AgentVMConfig()
    cfg.vm.name = 'vm-stale'
    cfg.vm.user = 'agent'
    cfg.paths.ssh_identity_file = '/tmp/id'

    real = tmp_path / 'real'
    real.mkdir()
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    stale_link = tmp_path / 'stale'
    stale_link.symlink_to(elsewhere)  # points away from `real`

    attachment = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=AttachmentMode.PERSISTENT,
        source_dir=str(real),
        guest_dst=str(real),
        tag='tag-stale',
    )

    warnings = capture_logs(
        monkeypatch, 'aivm.attachments.guest.log', levels=('warning',)
    )

    activate_manager(monkeypatch)
    recorder = command_recorder(monkeypatch, {'ssh': FakeProc(0)})

    _apply_guest_derived_symlinks(
        cfg,
        '10.0.0.1',
        real,
        attachment,
        mirror_home=False,
        extra_lexical_paths=[str(stale_link)],
    )

    # Symlink IS still created (mount is at canonical; we mirror the typed path)
    calls = _recorded_symlinks(recorder)
    assert any(c['symlink_path'] == str(stale_link) for c in calls)
    # And a drift warning was emitted
    assert any('no longer resolves to canonical' in w for w in warnings)
