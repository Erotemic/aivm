#!/usr/bin/env python3
"""Batch live foreground checks. This program never repairs guest state.

Expected hashes and symlink pairs are ordinary command arguments so the
logged invocation is reproducible. Outdated helpers are never executed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REPLAY = '/usr/local/libexec/aivm-persistent-attachment-replay'
SYMLINK = '/usr/local/libexec/aivm/attachment-symlink'
UNIT = '/etc/systemd/system/aivm-persistent-attachment-replay.service'
MANIFEST = '/var/lib/aivm/attachments.json'


def check_command(argv):
    result = subprocess.run(argv, capture_output=True, text=True)
    return {'code': result.returncode, 'stderr': result.stderr.strip()}


def inspect(args):
    files = {}
    for path, expected in args.file:
        if path not in (REPLAY, SYMLINK, UNIT) or path in files:
            raise ValueError(f'unexpected or duplicate helper path: {path}')
        try:
            files[path] = (
                hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected
            )
        except FileNotFoundError:
            files[path] = False
    links = []
    for link, target in args.symlink:
        result = None
        if files.get(SYMLINK):
            result = check_command(
                [SYMLINK, '--check', '--link', link, '--target', target]
            )
        links.append(
            {'link': link, 'target': target, 'remove': False, 'result': result}
        )
    for link, target in args.remove_symlink:
        path = Path(link)
        needs_removal = path.is_symlink() and str(path.readlink()) == target
        links.append(
            {
                'link': link,
                'target': target,
                'remove': True,
                'result': {'code': 10 if needs_removal else 0, 'stderr': ''},
            }
        )
    replay = None
    if files.get(REPLAY) and Path(MANIFEST).is_file():
        replay = check_command(
            [REPLAY, '--check', '--only-guest-dst', args.guest_dst]
        )
    return {
        'version': 1,
        'files': files,
        'symlinks': links,
        'manifest_directory': Path(MANIFEST).parent.is_dir(),
        'replay': replay,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-dst', required=True)
    parser.add_argument(
        '--file',
        nargs=2,
        action='append',
        default=[],
        metavar=('PATH', 'SHA256'),
    )
    parser.add_argument(
        '--symlink',
        nargs=2,
        action='append',
        default=[],
        metavar=('LINK', 'TARGET'),
    )
    parser.add_argument(
        '--remove-symlink',
        nargs=2,
        action='append',
        default=[],
        metavar=('LINK', 'TARGET'),
    )
    print(json.dumps(inspect(parser.parse_args())))


if __name__ == '__main__':
    main()
