#!/usr/bin/env python3
"""Inspect or safely create an attachment's companion symlink.

Exit 10 from --check means creation is needed. All mutations recheck the path;
an unrelated symlink, file, or nonempty directory is always preserved.
"""

import argparse
import os
import stat
import sys
from pathlib import Path


def inspect(link: Path, target: str) -> tuple[int, str]:
    try:
        info = link.lstat()
    except FileNotFoundError:
        return 10, ""
    if stat.S_ISLNK(info.st_mode):
        current = os.readlink(link)
        if current == target:
            return 0, ""
        return 3, f"{link} is a symlink to {current} not {target}; skipping"
    if stat.S_ISDIR(info.st_mode):
        if not any(link.iterdir()):
            return 10, ""
        return 4, f"{link} is a non-empty directory; skipping"
    return 5, f"{link} is a regular file or special file; skipping"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--link', required=True, type=Path)
    parser.add_argument('--target', required=True)
    args = parser.parse_args(argv)
    if not args.link.is_absolute() or not Path(args.target).is_absolute():
        parser.error('link and target must be absolute paths')
    code, message = inspect(args.link, args.target)
    if message:
        print(f'aivm-symlink-warn: {message}', file=sys.stderr)
    if args.check or code != 10:
        return code
    # rmdir refuses a newly populated directory; symlink refuses replacement
    # if another process creates any entry after inspection.
    if args.link.is_dir() and not args.link.is_symlink():
        args.link.rmdir()
    args.link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(args.target, args.link)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
