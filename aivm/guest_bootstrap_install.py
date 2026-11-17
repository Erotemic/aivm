"""Restricted guest bootstrap installer shared by migration and repair.

The installer must only run via SSH to an already-authorized guest account
followed by `sudo -n bash -s`. It never uses an untrusted bootstrap login.
"""

from __future__ import annotations

import base64
import shlex

from .errors import AIVMError
from .guestctl import (
    BOOTSTRAP_GUEST_USER,
    BOOTSTRAP_SUDOERS_PATH,
    GUESTCTL_PATH,
    guestctl_source,
    restricted_bootstrap_authorized_key,
)


def guest_bootstrap_install_script(public_key: str) -> str:
    restricted = restricted_bootstrap_authorized_key(public_key)
    guestctl_b64 = base64.b64encode(guestctl_source().encode('utf-8')).decode(
        'ascii'
    )
    key_b64 = base64.b64encode((restricted + '\n').encode('utf-8')).decode(
        'ascii'
    )
    sudoers = (
        f'{BOOTSTRAP_GUEST_USER} ALL=(root) NOPASSWD: '
        f'{GUESTCTL_PATH} --forced\n'
    )
    sudoers_b64 = base64.b64encode(sudoers.encode('utf-8')).decode('ascii')
    user_q = shlex.quote(BOOTSTRAP_GUEST_USER)
    home_q = shlex.quote(f'/var/lib/{BOOTSTRAP_GUEST_USER}')
    auth_q = shlex.quote(
        f'/var/lib/{BOOTSTRAP_GUEST_USER}/.ssh/authorized_keys'
    )
    key_parts = public_key.split()
    if len(key_parts) < 2:
        raise AIVMError('Malformed bootstrap public key')
    payload_q = shlex.quote(key_parts[1])
    return f"""set -euo pipefail
if ! getent group {user_q} >/dev/null 2>&1; then
    groupadd --system {user_q}
fi
if ! id -u {user_q} >/dev/null 2>&1; then
    useradd --system --gid {user_q} --home-dir {home_q} --create-home --shell /bin/bash {user_q}
fi
install -d -m 0700 -o {user_q} -g {user_q} {home_q}/.ssh
printf %s {shlex.quote(key_b64)} | base64 -d > {auth_q}
chown {user_q}:{user_q} {auth_q}
chmod 0600 {auth_q}
printf %s {shlex.quote(guestctl_b64)} | base64 -d > {shlex.quote(GUESTCTL_PATH)}
chmod 0755 {shlex.quote(GUESTCTL_PATH)}
printf %s {shlex.quote(sudoers_b64)} | base64 -d > {shlex.quote(BOOTSTRAP_SUDOERS_PATH)}
chmod 0440 {shlex.quote(BOOTSTRAP_SUDOERS_PATH)}
visudo -cf {shlex.quote(BOOTSTRAP_SUDOERS_PATH)} >/dev/null
test -x {shlex.quote(GUESTCTL_PATH)}
grep -Fq {payload_q} {auth_q}
"""


