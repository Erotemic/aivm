"""End-to-end proof that storage adoption never touches attachment binds.

Attachment export roots live under VM storage and each token directory is
a live bind mount of a real user folder -- same inodes.  The 2026-07-16
incident: ``sudoless setup --adopt`` recursed straight through those binds
and rewrote group ownership and permissions on the user's actual projects.
Unit tests could not have caught it because they fake the subprocess
boundary; this suite builds a **real** bind mount under a scratch tree and
runs the **real** privileged adoption script against it.

Needs passwordless sudo (to create the bind and run the script as root)
plus the ``libvirt`` group and ``libvirt-qemu`` user on the host.  Guarded
by ``AIVM_E2E=1`` like the other e2e suites.
"""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
from pathlib import Path

import pytest

from aivm.cli.host_sudoless import _adopt_script
from tests.e2e._helpers import require_passwordless_sudo

pytestmark = pytest.mark.e2e


def _require_host_identities() -> None:
    try:
        grp.getgrnam('libvirt')
        pwd.getpwnam('libvirt-qemu')
    except KeyError:
        pytest.skip('Adoption e2e needs the libvirt group and libvirt-qemu user.')
    import shutil

    if shutil.which('setfacl') is None or shutil.which('getfacl') is None:
        pytest.skip('Adoption e2e needs the acl package (setfacl/getfacl).')


def _sudo(*cmd: str) -> None:
    subprocess.run(['sudo', '-n', *cmd], check=True, capture_output=True)


def test_adopt_script_prunes_live_bind_mounts(tmp_path: Path) -> None:
    if os.getenv('AIVM_E2E') != '1':
        pytest.skip('Set AIVM_E2E=1 to run e2e tests.')
    require_passwordless_sudo()
    _require_host_identities()

    # The incident layout: a root-owned storage tree whose persistent-root
    # token is a live bind mount of a user-owned folder, plus a symlink
    # escaping the tree (per-entry chgrp/chmod must not follow it).
    tree = tmp_path / 'tree'
    mountpoint = tree / 'vm1' / 'persistent-root' / 'hostcode-proj'
    images = tree / 'vm1' / 'images'
    source = tmp_path / 'source'
    outside = tmp_path / 'outside.txt'
    for d in (mountpoint, images, source):
        d.mkdir(parents=True)
    precious = source / 'precious.txt'
    precious.write_text('data', encoding='utf-8')
    outside.write_text('secret', encoding='utf-8')
    disk = images / 'disk.qcow2'
    disk.write_text('img', encoding='utf-8')
    source_stat_before = precious.stat()

    _sudo('mount', '--bind', str(source), str(mountpoint))
    try:
        _sudo('chown', '-R', 'root:root', str(tree))
        # chown -R itself went through the bind (that is the hazard under
        # test); put the source back to the invoking user before adopting.
        _sudo(
            'chown',
            '-R',
            f'{os.getuid()}:{os.getgid()}',
            str(source),
        )
        _sudo('ln', '-s', str(outside), str(tree / 'vm1' / 'link-out'))

        proc = subprocess.run(
            ['sudo', '-n', 'bash', '-c', _adopt_script(tree)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

        # The bind-mounted source is byte-for-byte untouched: owner, group,
        # mode, and no ACL side channel.
        st = precious.stat()
        assert st.st_uid == os.getuid()
        assert st.st_gid == os.getgid()
        assert st.st_mode == source_stat_before.st_mode
        src_st = source.stat()
        assert src_st.st_gid == os.getgid()
        assert not src_st.st_mode & 0o2000, 'source dir gained setgid'
        facl = subprocess.run(
            ['getfacl', '-p', str(source)], capture_output=True, text=True
        )
        assert facl.returncode == 0, facl.stderr
        assert 'libvirt' not in facl.stdout

        # The symlink target outside the tree is untouched.
        out_st = outside.stat()
        assert out_st.st_gid == os.getgid()

        # The storage proper was adopted: group libvirt, setgid dirs,
        # group-writable image file.
        libvirt_gid = grp.getgrnam('libvirt').gr_gid
        assert disk.stat().st_gid == libvirt_gid
        assert images.stat().st_gid == libvirt_gid
        assert images.stat().st_mode & 0o2000, 'images dir missing setgid'
        assert disk.stat().st_mode & 0o020, 'disk not group-writable'
    finally:
        _sudo('umount', str(mountpoint))
        _sudo('chown', '-R', f'{os.getuid()}:{os.getgid()}', str(tree))


def test_adopt_script_resolves_symlinked_tree_before_pruning(
    tmp_path: Path,
) -> None:
    """A symlink-spelled tree still prunes its binds (mounts are canonical).

    /proc/self/mounts reports canonical paths; a prune list computed
    against a symlinked spelling would be empty and the ownership pass
    would recurse into the bind. The script's realpath canonicalization
    is the last line of defense when a caller hands it an alias.
    """
    if os.getenv('AIVM_E2E') != '1':
        pytest.skip('Set AIVM_E2E=1 to run e2e tests.')
    require_passwordless_sudo()
    _require_host_identities()

    real = (tmp_path / 'real-tree').resolve()
    alias = tmp_path / 'alias'
    mountpoint = real / 'vm1' / 'persistent-root' / 'hostcode-proj'
    source = tmp_path / 'source'
    mountpoint.mkdir(parents=True)
    source.mkdir()
    alias.symlink_to(real)
    precious = source / 'precious.txt'
    precious.write_text('data', encoding='utf-8')

    _sudo('mount', '--bind', str(source), str(mountpoint))
    try:
        _sudo('chown', '-R', 'root:root', str(real))
        _sudo(
            'chown', '-R', f'{os.getuid()}:{os.getgid()}', str(source)
        )

        # Hand the script the ALIAS: pruning only works if it resolves.
        proc = subprocess.run(
            ['sudo', '-n', 'bash', '-c', _adopt_script(alias)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

        st = precious.stat()
        assert st.st_uid == os.getuid()
        assert st.st_gid == os.getgid()
        libvirt_gid = grp.getgrnam('libvirt').gr_gid
        assert (real / 'vm1').stat().st_gid == libvirt_gid
    finally:
        _sudo('umount', str(mountpoint))
        _sudo('chown', '-R', f'{os.getuid()}:{os.getgid()}', str(real))
