"""Exercise the installed program against real files, without SSH or sudo."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aivm.rc.guest.attachment_symlink import main


def test_symlink_check_is_read_only_and_repair_is_idempotent(tmp_path):
    link = tmp_path / 'parent with spaces' / 'link; $(touch UNEXPECTED)'
    target = str(tmp_path / 'missing target " $HOME')
    argv = ['--link', str(link), '--target', target]
    assert main([*argv, '--check']) == 10
    assert not link.parent.exists()
    assert main(argv) == 0
    info = link.lstat()
    assert os.readlink(link) == target
    assert main([*argv, '--check']) == main(argv) == 0
    assert link.lstat().st_mtime_ns == info.st_mtime_ns


@pytest.mark.parametrize('kind, code', [('wrong-link', 3), ('nonempty', 4), ('file', 5)])
def test_symlink_preserves_conflicts(tmp_path, kind, code):
    link, target = tmp_path / 'link', str(tmp_path / 'target')
    if kind == 'wrong-link':
        link.symlink_to('/unrelated')
    elif kind == 'nonempty':
        link.mkdir()
        (link / 'sentinel').write_text('keep')
    else:
        link.write_text('keep')
    original = link.lstat()
    argv = ['--link', str(link), '--target', target]
    assert main([*argv, '--check']) == main(argv) == code
    assert link.lstat() == original


def test_symlink_replaces_only_empty_directory_and_rechecks(tmp_path):
    link, target = tmp_path / 'link', str(tmp_path / 'target')
    link.mkdir()
    argv = ['--link', str(link), '--target', target]
    assert main([*argv, '--check']) == 10
    (link / 'new-file').write_text('appeared since check')
    assert main(argv) == 4
    (link / 'new-file').unlink()
    assert main(argv) == 0
    assert link.is_symlink()


def test_symlink_program_is_standalone(tmp_path):
    import aivm.rc.guest.attachment_symlink as helper

    program = Path(helper.__file__)
    result = subprocess.run(
        [sys.executable, '-I', str(program), '--check', '--link',
         str(tmp_path / 'link'), '--target', '/target'],
        capture_output=True,
    )
    assert result.returncode == 10
