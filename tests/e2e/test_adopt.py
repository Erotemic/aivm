"""End-to-end proof that storage adoption never touches attachment binds.

Attachment export roots live under VM storage and each token directory is
a live bind mount of a real user folder -- same inodes. A recursive adoption
must prune those mount points or it can rewrite ownership and permissions on
the user's actual projects.

Needs passwordless sudo (to create the bind and run the script as root) plus
the ``libvirt`` group and ``libvirt-qemu`` user on the host. Guarded by
``AIVM_E2E=1`` like the other e2e suites.
"""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
from pathlib import Path

import pytest

from aivm.cli.host_permissions import _adopt_script
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

    tree = tmp_path / 'tree'
    mountpoint = tree / 'vm1' / 'persistent-root' / 'hostcode-proj'
    images = tree / 'vm1' / 'images'
    source = tmp_path / 'source'
    outside = tmp_path / 'outside.txt'
    for directory in (mountpoint, images, source):
        directory.mkdir(parents=True)
    precious = source / 'precious.txt'
    precious.write_text('data', encoding='utf-8')
    outside.write_text('secret', encoding='utf-8')
    disk = images / 'disk.qcow2'
    disk.write_text('img', encoding='utf-8')
    source_stat_before = precious.stat()

    _sudo('mount', '--bind', str(source), str(mountpoint))
    try:
        _sudo('chown', '-R', 'root:root', str(tree))
        _sudo('chown', '-R', f'{os.getuid()}:{os.getgid()}', str(source))
        _sudo('ln', '-s', str(outside), str(tree / 'vm1' / 'link-out'))

        proc = subprocess.run(
            ['sudo', '-n', 'bash', '-c', _adopt_script(tree)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

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

        out_st = outside.stat()
        assert out_st.st_gid == os.getgid()

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
    """A symlink-spelled tree still prunes its binds."""
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
        _sudo('chown', '-R', f'{os.getuid()}:{os.getgid()}', str(source))

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
