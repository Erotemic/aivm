"""Whole-path checks for the host files a session depends on."""

from __future__ import annotations

import grp
import os
import pwd
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


def test_policy_file_rejects_writes_by_anyone_else(tmp_path, shared_group):
    path = write_private(tmp_path / 'policy', b'{}', 0o644)
    assert read_owned(path, private=False) == b'{}'
    for mode in (0o646, 0o666, 0o602):
        path.chmod(mode)
        assert 'world-writable' in unsafe(read_owned, path, private=False)
    path.chmod(0o664)
    assert 'shared group' in unsafe(read_owned, path, private=False)


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


def test_sticky_directories_are_acceptable(tmp_path, shared_group):
    sticky = tmp_path / 'sticky'
    sticky.mkdir()
    sticky.chmod(0o1777)  # like /tmp: others may create, never rename ours
    path = write_private(sticky / 'token', b'secret')
    assert read_owned(path, private=True) == b'secret'


# -- group-writable paths ----------------------------------------------------
#
# These tests state the account database explicitly, so they mean the same
# thing on a host with a user-private group and on one without.


def accounts(monkeypatch, tmp_path, *, others=(), members=(), nss='files'):
    """Describe a host: who else has our primary group, and how we know."""
    me = pwd.getpwuid(os.getuid())
    entries = [me] + [
        pwd.struct_passwd((name, 'x', uid, gid, '', '/', '/bin/sh'))
        for name, uid, gid in others
    ]
    monkeypatch.setattr(files.pwd, 'getpwall', lambda: entries)
    monkeypatch.setattr(
        files.grp,
        'getgrgid',
        lambda gid: grp.struct_group(('g', 'x', gid, list(members))),
    )
    conf = tmp_path / 'nsswitch.conf'
    conf.write_text(nss if nss.startswith('#') else f'passwd: {nss}\n')
    monkeypatch.setattr(files, 'NSSWITCH', conf)
    return me


@pytest.fixture
def private_group(monkeypatch, tmp_path_factory):
    """A host where our primary group provably has nobody else in it."""
    return accounts(monkeypatch, tmp_path_factory.mktemp('nss'))


@pytest.fixture
def shared_group(monkeypatch, tmp_path_factory):
    """The review's case: another account has our group as *its* primary.

    That account is in no group's member list. Only the account database
    shows it.
    """
    me = pwd.getpwuid(os.getuid())
    return accounts(
        monkeypatch,
        tmp_path_factory.mktemp('nss'),
        others=[('mallory', me.pw_uid + 1, me.pw_gid)],
    )


def grouped(tmp_path):
    directory = tmp_path / 'grouped'
    directory.mkdir()
    directory.chmod(0o775)  # umask 0002
    return directory


def test_a_provably_private_group_may_write(tmp_path, private_group):
    """Stock ``umask 0002`` with a user-private group is not an error."""
    directory = grouped(tmp_path)
    token = write_private(directory / 'token', b'secret')
    assert read_owned(token, private=True) == b'secret'
    policy = write_private(directory / 'policy', b'{}', 0o664)
    assert read_owned(policy, private=False) == b'{}'
    tool = program(directory / 'tool', 0o775)
    assert verify_program(tool) == tool
    assert private_directory(directory / 'audit')
    # A secret is still never group-readable, whoever the group is.
    token.chmod(0o640)
    assert 'group/other' in unsafe(read_owned, token, private=True)


def test_an_account_sharing_the_primary_group_makes_it_shared(
    tmp_path, shared_group
):
    """Nothing about the path changed -- only who else is in the group."""
    directory = grouped(tmp_path)
    token = write_private(directory / 'token', b'secret')
    assert 'shared group' in unsafe(read_owned, token, private=True)
    assert 'shared group' in unsafe(verify_program, program(directory / 'tool'))
    assert 'shared group' in unsafe(private_directory, directory / 'audit')
    directory.chmod(0o755)
    assert read_owned(token, private=True) == b'secret'
    # The directory is now fine; a group-writable file in it is still not.
    policy = write_private(directory / 'policy', b'{}', 0o664)
    assert 'shared group' in unsafe(read_owned, policy, private=False)
    assert 'shared group' in unsafe(
        verify_program, program(directory / 'loose', 0o775)
    )


@pytest.mark.parametrize(
    'host,private',
    [
        ({}, True),
        ({'members': ['@me']}, True),
        ({'nss': 'files systemd'}, True),
        ({'nss': 'files [NOTFOUND=return] systemd  # local only'}, True),
        # An account that shares the uid is the same user under another name.
        ({'others': [('alias', '@uid', '@gid')]}, True),
        ({'others': [('other', '@uid+1', '@gid+1')]}, True),
        ({'others': [('mallory', '@uid+1', '@gid')]}, False),
        ({'members': ['mallory']}, False),
        ({'members': ['@me', 'mallory']}, False),
        # A directory service may not list every account: nothing is proven.
        ({'nss': 'files sss'}, False),
        ({'nss': 'files systemd ldap'}, False),
        ({'nss': 'compat'}, False),
        ({'nss': 'winbind'}, False),
        ({'nss': ''}, False),
        ({'nss': '# passwd: files'}, False),
        ({'nss': '#\ngroup: files\n'}, False),
    ],
)
def test_private_group_requires_proof(monkeypatch, tmp_path, host, private):
    me = pwd.getpwuid(os.getuid())
    names = {'@me': me.pw_name, '@uid': me.pw_uid, '@gid': me.pw_gid}
    names.update({'@uid+1': me.pw_uid + 1, '@gid+1': me.pw_gid + 1})
    host = dict(host)
    host['members'] = [names.get(m, m) for m in host.get('members', [])]
    host['others'] = [
        tuple(names.get(part, part) for part in other)
        for other in host.get('others', [])
    ]
    accounts(monkeypatch, tmp_path, **host)
    assert files._private_group(me.pw_gid) is private
    # Some other group is never ours, whatever its membership.
    assert files._private_group(me.pw_gid + 1) is False


def test_an_unknowable_account_database_proves_nothing(monkeypatch, tmp_path):
    me = accounts(monkeypatch, tmp_path)
    assert files._private_group(me.pw_gid) is True
    monkeypatch.setattr(files, 'NSSWITCH', tmp_path / 'absent')
    assert files._private_group(me.pw_gid) is False
    accounts(monkeypatch, tmp_path)

    def gone(gid):
        raise KeyError(gid)

    monkeypatch.setattr(files.grp, 'getgrgid', gone)
    assert files._private_group(me.pw_gid) is False
    binary = tmp_path / 'binary.conf'
    binary.write_bytes(b'passwd: files \xff\n')
    accounts(monkeypatch, tmp_path)
    monkeypatch.setattr(files, 'NSSWITCH', binary)
    assert files._private_group(me.pw_gid) is False


# -- symbolic links ----------------------------------------------------------


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
    assert outside(elsewhere / 'a' / '..' / 'b', roots, what='x') == (
        elsewhere / 'b'
    )
    loop = elsewhere / 'loop'
    loop.symlink_to(loop)
    unsafe(outside, loop / 'x', roots, what='policy')


@pytest.fixture
def switch(tmp_path):
    """A link *inside* the guest's workspace that leads out of it.

    ``shared/switch -> host`` resolves to a perfectly good host directory.
    The guest still owns the link: it decides, at any moment, where every
    path through it leads.
    """
    host = tmp_path / 'host'
    host.mkdir(mode=0o700)
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o700)
    write_private(host / 'token', b'secret')
    write_private(host / 'policy.json', b'{}', 0o644)
    program(host / 'resolve')
    (shared / 'switch').symlink_to(host)
    return host, shared


def shared(call, *args, **kwargs) -> str:
    with pytest.raises(SecretsError) as caught:
        call(*args, **kwargs)
    assert caught.value.code == 'shared_source'
    return caught.value.detail


def test_a_path_through_a_guest_owned_link_is_refused_wherever_it_leads(
    switch,
):
    host, workspace = switch
    roots = (workspace,)
    through = workspace / 'switch'
    # Sanity: every destination is fine when named directly.
    assert read_owned(host / 'token', private=True, untrusted=roots)
    assert verify_program(host / 'resolve', roots) == host / 'resolve'
    assert outside(host / 'token', roots, what='x') == host / 'token'
    # Through the guest's link, none of them is.
    assert str(workspace) in shared(
        read_owned, through / 'token', private=True, untrusted=roots
    )
    shared(read_owned, through / 'policy.json', private=False, untrusted=roots)
    shared(verify_program, through / 'resolve', roots)
    shared(outside, through / 'token', roots, what='credential file')
    # ... and nothing is created on the far side of it before refusing.
    shared(private_directory, through / 'audit', roots)
    assert not (host / 'audit').exists()


def test_a_host_link_into_the_workspace_is_refused_at_every_depth(switch):
    host, workspace = switch
    roots = (workspace,)
    planted = write_private(workspace / 'token', b'guest-chosen')
    (host / 'direct').symlink_to(workspace)
    (host / 'hop1').symlink_to(host / 'hop2')
    (host / 'hop2').symlink_to(host / 'direct')
    (host / 'relative').symlink_to('../shared')
    (host / 'leaf').symlink_to(planted)
    (host / 'sub').mkdir()
    for path in (
        host / 'direct' / 'token',
        host / 'hop1' / 'token',
        host / 'relative' / 'token',
        host / 'direct' / 'switch' / 'token',  # out, in, and out again
        host / 'sub' / '..' / 'direct' / 'token',
    ):
        shared(read_owned, path, private=True, untrusted=roots)
        shared(outside, path, roots, what='credential file')
    shared(verify_program, host / 'leaf', roots)
    # Without an untrusted root these are ordinary, resolvable paths.
    assert read_owned(host / 'hop1' / 'token', private=True) == b'guest-chosen'


def test_the_workspace_named_through_a_link_is_still_the_workspace(switch):
    host, workspace = switch
    alias = host / 'ws'
    alias.symlink_to(workspace)
    write_private(workspace / 'token', b'x')
    # The root itself is given through a link; both spellings name it.
    shared(read_owned, workspace / 'token', private=True, untrusted=(alias,))
    shared(read_owned, alias / 'token', private=True, untrusted=(alias,))
    shared(read_owned, alias / 'token', private=True, untrusted=(workspace,))


def test_dot_dot_cannot_step_around_the_checks(tmp_path):
    inner = tmp_path / 'a' / 'b'
    inner.mkdir(parents=True, mode=0o700)
    token = write_private(tmp_path / 'a' / 'token', b'secret')
    assert read_owned(inner / '..' / 'token', private=True) == b'secret'
    assert read_owned(inner / '.' / '..' / 'token', private=True) == b'secret'
    workspace = tmp_path / 'ws'
    workspace.mkdir()
    # Lexically this never enters the workspace; resolution still visits it.
    shared(
        read_owned,
        workspace / '..' / 'a' / 'token',
        private=True,
        untrusted=(workspace,),
    )
    assert token.exists()
    unsafe(read_owned, inner / '..', private=True)
    unsafe(read_owned, Path('/'), private=True)


def program(path: Path, mode: int = 0o755) -> Path:
    write_private(path, b'#!/bin/sh\nexit 0\n', mode)
    return path


def test_verify_program_returns_where_the_program_really_is(tmp_path):
    tool = program(tmp_path / 'tool')
    assert verify_program(tool) == tool
    # A name that is a link is *resolved*: what comes back has no link left
    # in it for anyone to re-point.
    link = tmp_path / 'gh'
    link.symlink_to(tool)
    assert verify_program(link) == tool
    relative = tmp_path / 'relative'
    relative.symlink_to('tool')
    assert verify_program(relative) == tool
    nested = tmp_path / 'dir'
    nested.mkdir()
    (nested / 'again').symlink_to('../gh')
    assert verify_program(nested / 'again') == tool
    shell = verify_program(Path('/bin/sh'))
    assert shell == Path(os.path.realpath('/bin/sh'))


def test_a_link_swapped_after_verification_changes_nothing(tmp_path):
    """The verified identity is a location, not a name to look up again."""
    good = program(tmp_path / 'good')
    evil = program(tmp_path / 'evil')
    name = tmp_path / 'resolver'
    name.symlink_to(good)
    verified = verify_program(name)
    name.unlink()
    name.symlink_to(evil)
    assert verified == good and os.path.realpath(name) == str(evil)
    assert os.path.realpath(verified) == str(good)


def test_verify_program_refuses_what_another_user_could_change(tmp_path):
    assert 'executable' in unsafe(
        verify_program, program(tmp_path / 'data', 0o644)
    )
    assert 'world-writable' in unsafe(
        verify_program, program(tmp_path / 'loose', 0o757)
    )
    assert 'regular' in unsafe(verify_program, tmp_path)
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
