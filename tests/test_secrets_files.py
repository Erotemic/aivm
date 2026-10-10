"""Whole-path checks for the host files a session depends on."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host import files
from aivm_secrets.host.files import (
    outside,
    private_directory,
    read_owned,
    verify_program,
    write_new,
)
from tests.secrets_helpers import write_private


def unsafe(call, *args, **kwargs) -> str:
    with pytest.raises(SecretsError) as caught:
        call(*args, **kwargs)
    assert caught.value.code == 'unsafe_file'
    # The public text never names a path; the operator detail does.
    assert (
        str(caught.value)
        == 'Host file ownership, permissions, or type is unsafe.'
    )
    return caught.value.detail


def test_private_token_file_checks(tmp_path):
    path = write_private(tmp_path / 'token', b'secret\n')
    assert read_owned(path, private=True) == b'secret\n'
    for mode in (0o640, 0o604, 0o660, 0o644, 0o601):
        path.chmod(mode)
        assert 'group/other' in unsafe(read_owned, path, private=True)
    path.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(path)
    unsafe(read_owned, link, private=True)
    hard = tmp_path / 'hard'
    os.link(path, hard)
    assert 'hard links' in unsafe(read_owned, path, private=True)


def test_policy_file_rejects_group_writes(tmp_path):
    path = write_private(tmp_path / 'policy', b'{}', 0o644)
    assert read_owned(path, private=False) == b'{}'
    for mode in (0o664, 0o646, 0o666):
        path.chmod(mode)
        unsafe(read_owned, path, private=False)


def test_fifo_and_oversized_file_are_rejected_without_blocking(tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo, 0o600)
    assert 'regular' in unsafe(read_owned, fifo, private=True)
    directory = tmp_path / 'dir'
    directory.mkdir(mode=0o700)
    unsafe(read_owned, directory, private=True)
    large = write_private(tmp_path / 'large', b'x' * 11)
    assert 'larger' in unsafe(read_owned, large, private=True, limit=10)
    assert len(read_owned(large, private=True, limit=11)) == 11
    unsafe(read_owned, tmp_path / 'missing', private=True)
    unsafe(read_owned, Path('relative/token'), private=True)


@pytest.mark.parametrize('mode', [0o777, 0o757, 0o772, 0o707])
def test_a_world_writable_ancestor_taints_everything_beneath_it(tmp_path, mode):
    """The file's own mode is perfect; the path to it is not."""
    loose = tmp_path / 'loose'
    inner = loose / 'inner'
    inner.mkdir(parents=True, mode=0o700)
    path = write_private(inner / 'token', b'secret')
    assert read_owned(path, private=True) == b'secret'
    loose.chmod(mode)
    try:
        assert 'world-writable' in unsafe(read_owned, path, private=True)
        unsafe(private_directory, inner)
    finally:
        loose.chmod(0o700)


def test_sticky_and_private_group_directories_are_acceptable(
    tmp_path, monkeypatch
):
    sticky = tmp_path / 'sticky'
    sticky.mkdir()
    sticky.chmod(0o1777)  # like /tmp: others may create, never rename ours
    path = write_private(sticky / 'token', b'secret')
    assert read_owned(path, private=True) == b'secret'
    grouped = tmp_path / 'grouped'
    grouped.mkdir()
    grouped.chmod(0o775)  # umask 0002 with a user-private group
    path = write_private(grouped / 'token', b'secret')
    monkeypatch.setattr(files, '_private_group', lambda gid: True)
    assert read_owned(path, private=True) == b'secret'
    monkeypatch.setattr(files, '_private_group', lambda gid: False)
    assert 'group-writable' in unsafe(read_owned, path, private=True)


def test_private_group_means_primary_group_with_no_other_members(monkeypatch):
    import grp
    import pwd

    me = pwd.getpwuid(os.getuid())
    members = {
        'only': [],
        'self': [me.pw_name],
        'shared': [me.pw_name, 'mallory'],
    }

    def group(kind):
        return grp.struct_group(('g', 'x', me.pw_gid, members[kind]))

    for kind, expected in [('only', True), ('self', True), ('shared', False)]:
        monkeypatch.setattr(
            files.grp, 'getgrgid', lambda gid, kind=kind: group(kind)
        )
        assert files._private_group(me.pw_gid) is expected
        assert files._private_group(me.pw_gid + 1) is False


def test_a_swapped_ancestor_symlink_is_never_followed(tmp_path):
    """Symlinked ancestors are resolved once, then verified without following."""
    real = tmp_path / 'real'
    real.mkdir(mode=0o700)
    path = write_private(real / 'token', b'secret')
    alias = tmp_path / 'alias'
    alias.symlink_to(real)
    assert read_owned(alias / 'token', private=True) == b'secret'
    # ...but the final component itself may never be a link.
    (real / 'indirect').symlink_to(path)
    unsafe(read_owned, alias / 'indirect', private=True)


def test_private_directory_is_created_or_verified(tmp_path):
    made = private_directory(tmp_path / 'a' / 'b')
    assert stat.S_IMODE(made.stat().st_mode) == 0o700
    assert private_directory(made) == made
    made.chmod(0o750)
    assert 'group/other' in unsafe(private_directory, made)
    target = tmp_path / 'target'
    target.mkdir(mode=0o700)
    link = tmp_path / 'link'
    link.symlink_to(target)
    unsafe(private_directory, link)
    occupied = write_private(tmp_path / 'file', b'')
    unsafe(private_directory, occupied)


def test_write_new_never_replaces_or_follows(tmp_path):
    path = tmp_path / 'capability'
    write_new(path, b'one')
    assert path.read_bytes() == b'one'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    unsafe(write_new, path, b'two')
    assert path.read_bytes() == b'one'
    victim = write_private(tmp_path / 'victim', b'keep')
    link = tmp_path / 'link'
    link.symlink_to(victim)
    unsafe(write_new, link, b'clobber')
    assert victim.read_bytes() == b'keep'


def test_outside_refuses_guest_writable_locations(tmp_path):
    workspace = tmp_path / 'workspace'
    (workspace / 'sub').mkdir(parents=True)
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    roots = (workspace,)
    assert outside(elsewhere / 'policy.json', roots, what='policy')
    for inside in [
        workspace / 'policy.json',
        workspace / 'sub' / 'x',
        workspace,
    ]:
        with pytest.raises(SecretsError) as caught:
            outside(inside, roots, what='policy')
        assert caught.value.code == 'shared_source'
    # Reaching into the workspace through a link elsewhere is the same thing.
    sneaky = elsewhere / 'link'
    sneaky.symlink_to(workspace / 'sub')
    with pytest.raises(SecretsError):
        outside(sneaky / 'policy.json', roots, what='policy')
    alias = tmp_path / 'alias'
    alias.symlink_to(workspace)
    # ...and so is naming the workspace itself through a link.
    with pytest.raises(SecretsError):
        outside(workspace / 'policy.json', (alias,), what='policy')


def program(path: Path, mode: int = 0o755) -> Path:
    write_private(path, b'#!/bin/sh\nexit 0\n', mode)
    return path


def test_verify_program_accepts_ordinary_tools_and_keeps_their_name(tmp_path):
    tool = program(tmp_path / 'tool')
    assert verify_program(tool) == tool
    # A multi-call binary reached through a link must still be run by name.
    link = tmp_path / 'gh'
    link.symlink_to(tool)
    assert verify_program(link) == link
    relative = tmp_path / 'relative'
    relative.symlink_to('tool')
    assert verify_program(relative) == relative
    assert verify_program(Path('/bin/sh')) == Path('/bin/sh')


def test_verify_program_refuses_what_another_user_could_change(tmp_path):
    assert 'executable' in unsafe(
        verify_program, program(tmp_path / 'data', 0o644)
    )
    assert 'world-writable' in unsafe(
        verify_program, program(tmp_path / 'loose', 0o757)
    )
    unsafe(verify_program, tmp_path / 'missing')
    unsafe(verify_program, tmp_path)
    loop = tmp_path / 'loop'
    loop.symlink_to(loop)
    assert 'symbolic links' in unsafe(verify_program, loop)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    tool = program(bindir / 'tool')
    bindir.chmod(0o777)
    try:
        assert 'world-writable' in unsafe(verify_program, tool)
    finally:
        bindir.chmod(0o700)


def test_verify_program_checks_every_hop_against_untrusted_roots(tmp_path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    safe = tmp_path / 'safe'
    safe.mkdir()
    real = program(safe / 'real')
    assert verify_program(real, (workspace,)) == real
    planted = program(workspace / 'planted')
    link_to_planted = safe / 'looks-fine'
    link_to_planted.symlink_to(planted)
    link_in_workspace = workspace / 'link'
    link_in_workspace.symlink_to(real)
    for path in (planted, link_to_planted, link_in_workspace):
        with pytest.raises(SecretsError) as caught:
            verify_program(path, (workspace,))
        assert caught.value.code == 'shared_source'
