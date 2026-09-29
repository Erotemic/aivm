#!/usr/bin/env python3
"""Privileged metadata handoff for an existing AIVM storage tree."""

from __future__ import annotations

import argparse
import grp
import os
import shutil
import stat
import subprocess
from pathlib import Path


def _decode_mount_field(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        if (
            text[index] == '\\'
            and index + 3 < len(text)
            and text[index + 1 : index + 4].isdigit()
        ):
            out.append(chr(int(text[index + 1 : index + 4], 8)))
            index += 4
        else:
            out.append(text[index])
            index += 1
    return ''.join(out)


def _descendant_mountpoints(tree: Path) -> set[Path]:
    mountpoints: set[Path] = set()
    with open('/proc/self/mountinfo', encoding='utf-8') as file:
        for line in file:
            fields = line.split()
            if len(fields) < 5:
                continue
            mountpoint = Path(_decode_mount_field(fields[4]))
            if mountpoint != tree and tree in mountpoint.parents:
                mountpoints.add(mountpoint)
    return mountpoints


def adopt_tree(tree: Path, *, group: str, qemu_user: str) -> None:
    """Grant the libvirt group access without crossing mounts or symlinks."""
    tree = Path(os.path.realpath(tree))
    libvirt_gid = grp.getgrnam(group).gr_gid
    mountpoints = _descendant_mountpoints(tree)
    directories: list[Path] = []

    for root_text, dirnames, filenames in os.walk(
        tree, topdown=True, followlinks=False
    ):
        root = Path(root_text)
        dirnames[:] = [
            name
            for name in dirnames
            if not (root / name).is_symlink()
            and (root / name) not in mountpoints
        ]

        directories.append(root)
        paths = [root, *(root / name for name in filenames)]
        for path in paths:
            if path.is_symlink():
                continue
            info = path.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode) | stat.S_IRGRP | stat.S_IWGRP
            if path.is_dir() or mode & (
                stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            ):
                mode |= stat.S_IXGRP
            if path.is_dir():
                mode |= stat.S_ISGID
            os.chown(path, -1, libvirt_gid, follow_symlinks=False)
            os.chmod(path, mode, follow_symlinks=False)

    if shutil.which('setfacl') is None:
        return
    for offset in range(0, len(directories), 128):
        chunk = [str(path) for path in directories[offset : offset + 128]]
        subprocess.run(
            [
                'setfacl',
                '-m',
                f'u:{qemu_user}:x',
                '-m',
                f'default:group:{group}:rwX',
                '-m',
                f'default:user:{qemu_user}:x',
                '--',
                *chunk,
            ],
            check=True,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--group', required=True)
    parser.add_argument('--qemu-user', required=True)
    args = parser.parse_args()
    adopt_tree(args.tree, group=args.group, qemu_user=args.qemu_user)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
