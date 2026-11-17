#!/usr/bin/python3 -I
"""Root-installed, stdlib-only helper for preprovisioning another host user.

The administrator's CLI installs this inspectable program in
/usr/local/libexec/aivm/onboard-user. It runs *only* user-home preparation and
SSH verification under the target account's real uid/gid. It does not expose
private SSH key material to the administrator or change sudoers/groups.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


# Unlike the main CLI (Python >=3.11), this installed root-owned helper runs
# via /usr/bin/python3. On some hosts that is Python 3.10, which lacks tomllib.
# Only the top-level identity fields rendered by AIVM need to be examined.
_PROFILE_IDENTITY_KEYS = frozenset((
    'active_vm', 'ssh_identity_file', 'ssh_pubkey_path', 'default_guest_user',
))


def _profile_identity_fields(text: str) -> dict[str, str]:
    """Read required top-level TOML strings, rejecting ambiguous encodings.

    This is intentionally not a general TOML parser: AIVM writes these fields
    as JSON-compatible, double-quoted strings. Reject unsupported forms rather
    than accepting a potentially misleading interpretation of a user profile.
    """
    fields: dict[str, str] = {}
    in_root_table = True
    decoder = json.JSONDecoder()
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('['):
            # TOML has no way to return to the root table after a table header.
            in_root_table = False
            continue
        if not in_root_table:
            continue
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.*)', stripped)
        if match is None:
            raise ValueError(f'Unsupported AIVM profile syntax on line {number}')
        key, literal = match.groups()
        # Multiline TOML strings could contain lines masquerading as keys.
        # The standard profile renderer never emits them.
        if literal.startswith(('"""', "'''")):
            raise ValueError('Multiline AIVM profile values are not supported by onboarding')
        if key not in _PROFILE_IDENTITY_KEYS:
            continue
        if key in fields:
            raise ValueError(f'Duplicate AIVM profile field: {key}')
        try:
            value, end = decoder.raw_decode(literal)
        except ValueError as ex:
            raise ValueError(
                f'Expected a double-quoted AIVM profile string for {key}'
            ) from ex
        remainder = literal[end:].strip()
        if not isinstance(value, str) or (remainder and not remainder.startswith('#')):
            raise ValueError(f'Unsupported AIVM profile string syntax for {key}')
        fields[key] = value
    missing = _PROFILE_IDENTITY_KEYS.difference(fields)
    if missing:
        raise ValueError('Missing AIVM profile identity fields: ' + ', '.join(sorted(missing)))
    return fields



def _account(username: str) -> pwd.struct_passwd:
    if not username or username.startswith('-'):
        raise ValueError('A valid host login is required')
    try:
        account = pwd.getpwnam(username)
    except KeyError as ex:
        raise ValueError(f'Unknown host account: {username!r}') from ex
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise ValueError('Refusing to provision root or a root-group account')
    home = Path(account.pw_dir)
    if not home.is_absolute() or '..' in home.parts or home == Path('/'):
        raise ValueError('Host account has an unsafe home directory')
    return account


def _validate_names(vm: str, guest: str) -> None:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', vm):
        raise ValueError('Unsafe managed VM name')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', guest):
        raise ValueError('Unsafe guest account name')


def _ensure_home(account: pwd.struct_passwd) -> Path:
    """Only root may create a missing passwd home; never traverse symlinks.

    Once it exists, the entire profile/key operation runs with the owner's
    kernel credentials. A home owned by someone else is not ours to adopt.
    """
    home = Path(account.pw_dir)
    parts = list(reversed([home, *home.parents]))
    try:
        metadata = os.lstat(home)
        missing_home = False
    except FileNotFoundError:
        metadata = None
        missing_home = True
    for ancestor in parts[:-1]:
        parent_metadata = os.lstat(ancestor)
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise ValueError(f'Non-directory or symlink in home path: {ancestor}')
        if missing_home and (parent_metadata.st_uid != 0 or parent_metadata.st_mode & 0o022):
            raise ValueError(
                f'Cannot safely create {home}: all parent directories '
                'must be root-owned and not group/world-writable'
            )
    if missing_home:
        os.mkdir(home, 0o700)
        os.chown(home, account.pw_uid, account.pw_gid)
        metadata = os.lstat(home)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != account.pw_uid:
        raise ValueError(f'Home must be a real directory owned by {account.pw_name}: {home}')
    return home


def _owner_environment(account: pwd.struct_passwd) -> dict[str, str]:
    return {
        'HOME': account.pw_dir,
        'USER': account.pw_name,
        'LOGNAME': account.pw_name,
        'PATH': '/usr/local/bin:/usr/bin:/bin',
        'LANG': 'C.UTF-8',
    }


def _owned_directory(path: Path, *, mode: int = 0o700) -> None:
    """Create only within the owner's home; reject symlinked components."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        path.mkdir(mode=mode)
        metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError(f'Not an owner-controlled directory: {path}')


def _regular_owner_file(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError(f'Not a regular owner-controlled file: {path}')
    return True


def _paths(account: pwd.struct_passwd) -> tuple[Path, Path, Path]:
    home = Path(account.pw_dir)
    private = home / '.ssh' / 'id_aivm_ed25519'
    return private, Path(str(private) + '.pub'), home / '.config' / 'aivm' / 'profile.toml'


def _prepare_owner(account: pwd.struct_passwd, vm: str, guest: str, profile_text: str) -> dict[str, object]:
    """This function runs only as the target owner, never as root."""
    if os.getuid() != account.pw_uid or os.getgid() != account.pw_gid:
        raise ValueError('Profile generation must run with the target owner identity')
    home = Path(account.pw_dir)
    private, public, profile = _paths(account)
    _owned_directory(home / '.ssh')
    os.chmod(private.parent, 0o700)
    _owned_directory(home / '.config')
    _owned_directory(home / '.config' / 'aivm')
    os.chmod(profile.parent, 0o700)
    # Reject a conflicting user profile before creating any SSH key.
    existing_profile = _regular_owner_file(profile)
    if existing_profile:
        current = _profile_identity_fields(profile.read_text(encoding='utf-8'))
        expected = _profile_identity_fields(profile_text)
        for field in ('active_vm', 'ssh_identity_file', 'ssh_pubkey_path', 'default_guest_user'):
            if current.get(field) != expected.get(field):
                raise ValueError(
                    f'Existing {profile} has a different {field}; '
                    'refusing to overwrite an existing user profile'
                )
    have_private = _regular_owner_file(private)
    have_public = _regular_owner_file(public)
    if have_private != have_public:
        raise ValueError(f'Incomplete existing AIVM SSH identity: {private}')
    created_key = False
    comment = f'aivm-onboard@{vm}'
    if have_private:
        line = public.read_text(encoding='utf-8').strip()
        parts = line.split()
        if len(parts) != 3 or parts[2] != comment:
            raise ValueError(
                f'Existing key is not an AIVM onboard key for {vm}: {private}; '
                'refusing to borrow or overwrite another SSH identity'
            )
        derived = subprocess.run(
            ['ssh-keygen', '-y', '-P', '', '-f', str(private)],
            capture_output=True, text=True, check=True, env=_owner_environment(account),
        ).stdout.strip().split()
        if derived[:2] != parts[:2]:
            raise ValueError(f'Private/public SSH key mismatch: {private}')
    else:
        subprocess.run(
            ['ssh-keygen', '-q', '-t', 'ed25519', '-f', str(private),
             '-N', '', '-C', comment],
            check=True, capture_output=True, text=True,
            env=_owner_environment(account),
        )
        created_key = True
    os.chmod(private, 0o600)
    os.chmod(public, 0o644)
    if not existing_profile:
        with tempfile.NamedTemporaryFile(
            'w', dir=str(profile.parent), encoding='utf-8',
            prefix='.profile.', delete=False,
        ) as stream:
            temp = Path(stream.name)
            stream.write(profile_text)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temp, 0o600)
            os.replace(temp, profile)
        finally:
            temp.unlink(missing_ok=True)
    return {
        'public_key': public.read_text(encoding='utf-8').strip(),
        'private_path': str(private), 'profile_path': str(profile),
        'created_key': created_key, 'created_profile': not existing_profile,
    }


def _verify_owner(account: pwd.struct_passwd, vm: str, guest: str, ip: str) -> dict[str, object]:
    if os.getuid() != account.pw_uid or os.getgid() != account.pw_gid:
        raise ValueError('SSH proof must execute as the target host user')
    private, public, profile = _paths(account)
    if not _regular_owner_file(private) or not _regular_owner_file(public):
        raise ValueError('Target user does not have the prepared SSH keypair')
    if not _regular_owner_file(profile):
        raise ValueError('Target user does not have the prepared AIVM profile')
    current = _profile_identity_fields(profile.read_text(encoding='utf-8'))
    if (current.get('active_vm'), current.get('ssh_identity_file')) != (vm, str(private)):
        raise ValueError('Target profile no longer selects the provisioned VM and key')
    # The authenticated SSH subprocess receives the target's uid, gid, home,
    # and no administrator SSH agent. Root never opens the private key.
    cmd = [
        'ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=10', '-i', str(private),
        f'{guest}@{ip}', 'true',
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30,
        env=_owner_environment(account),
    )
    if result.returncode:
        raise ValueError(
            f'Owner-identity SSH proof failed (exit {result.returncode}): '
            f'{result.stderr.strip()[:1000]}'
        )
    return {'verified': True, 'public_key': public.read_text(encoding='utf-8').strip()}


def _run_as_owner(account: pwd.struct_passwd, action: str, vm: str, guest: str, ip: str, profile: str) -> int:
    """Root forks, drops supplementary groups/uid, then does no more work."""
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            os.chdir(account.pw_dir)
            if action == 'prepare':
                answer = _prepare_owner(account, vm, guest, profile)
            else:
                answer = _verify_owner(account, vm, guest, ip)
            print(json.dumps(answer), flush=True)
            os._exit(0)
        except Exception as ex:
            print(f'AIVM onboard helper: {ex}', file=sys.stderr, flush=True)
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--user', required=True)
    parser.add_argument('--vm', required=True)
    parser.add_argument('--guest', required=True)
    parser.add_argument('--ip', default='')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('This root-owned helper must run under administrator sudo')
    try:
        account = _account(args.user)
        _validate_names(args.vm, args.guest)
        if args.action == 'verify' and (not args.ip or args.ip.startswith('-')):
            raise ValueError('A valid guest IP or hostname is required')
        profile_text = sys.stdin.read(32768) if args.action == 'prepare' else ''
        if args.action == 'prepare':
            from_text = _profile_identity_fields(profile_text)
            private, public, _ = _paths(account)
            if (
                from_text.get('active_vm') != args.vm
                or from_text.get('default_guest_user') != args.guest
                or from_text.get('ssh_identity_file') != str(private)
                or from_text.get('ssh_pubkey_path') != str(public)
            ):
                raise ValueError('Prepared profile does not match requested user and VM')
            _ensure_home(account)
        return _run_as_owner(
            account, args.action, args.vm, args.guest, args.ip, profile_text
        )
    except Exception as ex:
        print(f'AIVM onboard helper: {ex}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
