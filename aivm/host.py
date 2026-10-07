"""Host capability checks and dependency installation helpers.

Host-facing workflows declare the capability they need here instead of learning
which executables happen to implement it.  Detection is side-effect free; only
explicit workflow policy may offer to install packages.  External processes
continue to execute exclusively through :class:`aivm.commands.CommandManager`.
"""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from loguru import logger

from .commands import CommandError, CommandManager
from .errors import AIVMError
from .host_identity import current_host_identity
from .machine_store import (
    DEFAULT_MACHINE_STORE_ROOT,
    MACHINE_STORE_ROOT_ENV,
    MachineStoreAccessError,
    MachineStoreLayout,
    MachineStoreSessionRefreshRequired,
    current_machine_group_name,
    current_process_has_machine_group,
    ensure_machine_store_layout,
    machine_group_exists,
    machine_store_layout,
    machine_store_root_ready,
    resolve_machine_group_gid,
    user_has_machine_group_membership,
)
from .privilege import LIBVIRT_GROUP, require_sudo_allowed
from .util import which

log = logger


class HostCapability(str, Enum):
    """Named host prerequisites consumed by higher-level workflows."""

    LIBVIRT_CLIENT = 'libvirt-client'
    VM_LIFECYCLE = 'vm-lifecycle'


@dataclass(frozen=True)
class MachineStoreAuthorityPreparation:
    """Result of establishing durable host-side machine-store authority.

    Preparation changes persistent host state only.  It does not and cannot
    refresh the supplementary groups carried by the already-running process.
    Callers that intend to use a newly prepared shared authority immediately
    must check ``session_membership_active`` before touching store contents.
    """

    layout: MachineStoreLayout
    membership_added: bool
    membership_configured: bool
    session_membership_active: bool | None

    @property
    def requires_session_refresh(self) -> bool:
        return (
            self.layout.shared
            and self.membership_configured
            and self.session_membership_active is False
        )


_VM_LIFECYCLE_CMDS = (
    'virsh',
    'virt-install',
    'qemu-img',
    'cloud-localds',
    'dnsmasq',
    'curl',
    'ip',
    'ssh',
)
_CAPABILITY_COMMANDS: dict[HostCapability, tuple[str, ...]] = {
    HostCapability.LIBVIRT_CLIENT: ('virsh',),
    HostCapability.VM_LIFECYCLE: _VM_LIFECYCLE_CMDS,
}
OPTIONAL_CMDS = ['nft', 'ssh-keyscan', 'setfacl']


def required_commands(
    capability: HostCapability = HostCapability.VM_LIFECYCLE,
) -> list[str]:
    """Return executable prerequisites for one named host capability."""
    return list(_CAPABILITY_COMMANDS[capability])


def missing_commands(capability: HostCapability) -> list[str]:
    """Return missing executables without running an external command."""
    return [c for c in required_commands(capability) if which(c) is None]


def check_commands() -> tuple[list[str], list[str]]:
    """Return the full VM-lifecycle preflight used by ``host doctor``."""
    missing = missing_commands(HostCapability.VM_LIFECYCLE)
    missing_opt = [c for c in OPTIONAL_CMDS if which(c) is None]
    return missing, missing_opt


def require_host_capability(capability: HostCapability) -> None:
    """Fail clearly when a host capability is unavailable.

    This is the defensive boundary for low-level operations.  It never
    installs packages: callers that own user-facing remediation policy should
    use :func:`ensure_host_capability` before entering those operations.
    """
    missing = missing_commands(capability)
    if not missing:
        return
    noun = 'command' if len(missing) == 1 else 'commands'
    rendered = ', '.join(missing)
    raise AIVMError(
        f'Host capability {capability.value!r} is unavailable; missing required '
        f'{noun}: {rendered}. Run `aivm host install_deps` and retry.'
    )


def ensure_host_capability(
    capability: HostCapability,
    *,
    yes: bool,
    dry_run: bool,
) -> None:
    """Satisfy one host capability at a workflow boundary when possible.

    Detection and remediation policy live together so callers only declare
    what they need.  Package installation is still an explicit application
    action; a low-level command failure never triggers package management.
    """
    missing = missing_commands(capability)
    if not missing:
        return

    missing_txt = ', '.join(missing)
    print(
        f'Missing required host dependencies for {capability.value}: '
        f'{missing_txt}'
    )
    print('Suggested command: aivm host install_deps')
    if dry_run:
        print(
            'DRYRUN: would satisfy the missing host capability before '
            'continuing.'
        )
        return
    if not host_is_debian_like():
        raise AIVMError(
            'Host is not detected as Debian/Ubuntu. Install dependencies '
            'manually, then retry.'
        )
    if not yes:
        if not sys.stdin.isatty():
            raise AIVMError(
                'Missing required host dependencies in non-interactive mode. '
                'Run `aivm host install_deps` first, or re-run with --yes.'
            )
        ans = (
            input('Install missing dependencies now with apt? [Y/n]: ')
            .strip()
            .lower()
        )
        if ans not in {'', 'y', 'yes'}:
            raise AIVMError('Aborted by user.')

    install_deps_debian(assume_yes=True)
    require_host_capability(capability)


def prepare_machine_store_authority(
    *,
    user: str,
    dry_run: bool,
) -> MachineStoreAuthorityPreparation:
    """Prepare durable machine-store authority without claiming session access.

    This is the one host-side transition used by both ``host permissions
    setup`` and fresh shared bootstrap. It may create durable group membership
    and the root-owned/setgid authority root. A running process keeps the group
    credentials it had at login, so preparation deliberately reports live
    activation separately instead of treating a successful ``usermod`` (or an
    already-listed account) as immediate access.
    """
    mgr = CommandManager.current()
    configured_root = os.environ.get(MACHINE_STORE_ROOT_ENV, '').strip()
    layout = machine_store_layout(
        None if configured_root else DEFAULT_MACHINE_STORE_ROOT
    )
    if configured_root:
        if dry_run:
            print(
                f'DRYRUN: prepare caller-owned AIVM machine store at '
                f'{layout.root}'
            )
        else:
            ensure_machine_store_layout(layout, group_gid=os.getgid())
        return MachineStoreAuthorityPreparation(
            layout=layout,
            membership_added=False,
            membership_configured=True,
            session_membership_active=True,
        )

    group_name = current_machine_group_name()
    group_exists = machine_group_exists(group_name)
    owns_group = group_name != LIBVIRT_GROUP
    configured = group_exists and user_has_machine_group_membership(
        user, group_name=group_name
    )
    group_request = (
        mgr.request(
            ['groupadd', '--system', group_name],
            sudo=True,
            role='modify',
            check=True,
            capture=True,
            summary=f'Create the {group_name} group',
        )
        if not group_exists and owns_group
        else None
    )
    member_request = (
        mgr.request(
            ['usermod', '-aG', group_name, user],
            sudo=True,
            role='modify',
            check=True,
            capture=True,
            summary=f'Add {user} to the {group_name} group',
        )
        if not configured and (group_exists or owns_group)
        else None
    )
    parent_request = mgr.request(
        [
            'install', '-d', '-o', 'root', '-g', 'root', '-m', '0755',
            str(layout.root.parent),
        ],
        sudo=True,
        role='modify',
        check=True,
        capture=True,
        summary=f'Prepare root-owned {layout.root.parent}',
    )
    root_request = mgr.request(
        [
            'install', '-d', '-o', 'root', '-g', group_name, '-m', '2770',
            str(layout.root),
        ],
        sudo=True,
        role='modify',
        check=True,
        capture=True,
        summary=f'Prepare shared AIVM state at {layout.root}',
    )

    if dry_run:
        if group_request is not None:
            group_request.preview()
        if member_request is not None:
            member_request.preview()
        parent_request.preview()
        root_request.preview()
        return MachineStoreAuthorityPreparation(
            layout=layout,
            membership_added=member_request is not None,
            membership_configured=configured or member_request is not None,
            session_membership_active=(
                current_process_has_machine_group(group_name=group_name)
                if user == current_host_identity().username
                else None
            ),
        )

    if not group_exists and not owns_group:
        # The default group belongs to libvirt.  Never fabricate a group with
        # the right name but no qemu:///system authority.
        resolve_machine_group_gid(group_name)

    with mgr.intent(
        'Prepare the shared AIVM machine store',
        why=(
            'Machine definitions, principals, and attachments need one '
            'group-writable host-wide authority.'
        ),
        role='modify',
    ):
        if group_request is not None:
            with mgr.step(
                'Create the trusted AIVM host group',
                why='The machine store is shared by trusted local AIVM users.',
                approval_scope='host-permissions-setup-aivm-group',
            ):
                group_request.submit()
        if member_request is not None:
            with mgr.step(
                'Add the invoking user to the AIVM host group',
                why='Group membership permits shared machine-store updates.',
                approval_scope='host-permissions-setup-aivm-member',
            ):
                member_request.submit()
        with mgr.step(
            'Create the shared AIVM machine-store root',
            why=(
                'The setgid root preserves trusted-group ownership on '
                'atomic replacements and split config fragments.'
            ),
            approval_scope='host-permissions-setup-aivm-root',
        ):
            # Keep the parent root-owned/non-group-writable because the root
            # persistent-replay service trusts that directory chain.
            parent_request.submit()
            root_request.submit()

    return MachineStoreAuthorityPreparation(
        layout=layout,
        membership_added=member_request is not None,
        membership_configured=True,
        session_membership_active=(
            current_process_has_machine_group(group_name=group_name)
            if user == current_host_identity().username
            else None
        ),
    )


def require_machine_store_session_access(
    preparation: MachineStoreAuthorityPreparation,
) -> None:
    """Require a prepared shared authority to be usable by this process.

    Authority preparation and process activation are intentionally separate
    lifecycle phases. Creating the shared root durably records the user's
    shared-machine choice; a process started before the corresponding group
    membership was active must stop here and resume from a new login session.
    """
    if not preparation.layout.shared:
        return
    if preparation.requires_session_refresh:
        group = current_machine_group_name()
        raise MachineStoreSessionRefreshRequired(
            f'Prepared the shared AIVM authority at '
            f'{preparation.layout.root}. '
            f'{current_host_identity().username!r} is configured in the '
            f'{group!r} group, but this process does not carry that group in '
            'its kernel credentials yet. Log out and back in (or start a new '
            'login session), then rerun the command. No AIVM config was '
            'written; the prepared shared root records the scope choice so '
            'AIVM will continue with the same authority after login.'
        )
    if preparation.session_membership_active is None:
        raise MachineStoreAccessError(
            'AIVM cannot verify live shared-store access for a different host '
            'user from this process. Start the command as that user after host '
            'permissions setup has completed.'
        )
    if not machine_store_root_ready(preparation.layout):
        raise MachineStoreAccessError(
            f'The shared AIVM authority at {preparation.layout.root} was '
            'prepared, but this process still cannot read, write, and traverse '
            'it. Run `aivm host permissions check` to inspect the active group '
            'credentials and directory ownership before continuing.'
        )


def check_commands_with_sudo() -> tuple[list[str], str | None]:
    """Check required commands in a non-interactive sudo environment."""
    mgr = CommandManager.current()
    sudo_probe = mgr.run(
        ['sudo', '-n', 'true'],
        role='read',
        check=False,
        capture=True,
        text=True,
    )
    if sudo_probe.code != 0:
        return [], (
            'non-interactive sudo (sudo -n) is not available. Run `sudo -v` '
            'to cache credentials and retry, or run `aivm host doctor` '
            'without --sudo.'
        )
    missing = []
    for cmd in required_commands(HostCapability.VM_LIFECYCLE):
        # Match sudo's effective PATH and shell command lookup behavior.
        probe = mgr.run(
            ['sudo', '-n', 'sh', '-c', f'command -v {shlex.quote(cmd)}'],
            role='read',
            check=False,
            capture=True,
            text=True,
        )
        if probe.code != 0:
            missing.append(cmd)
    return missing, None


def host_is_debian_like() -> bool:
    try:
        data = Path('/etc/os-release').read_text(encoding='utf-8')
        return any(
            k in data for k in ('ID=debian', 'ID=ubuntu', 'ID_LIKE=debian')
        )
    except Exception:
        return False


def _debian_noninteractive_cmd(*args: str) -> list[str]:
    # Keep Debian package operations explicitly non-interactive so bootstrap and
    # e2e flows do not emit debconf frontend warnings or hang on prompts.
    return [
        'env',
        'DEBIAN_FRONTEND=noninteractive',
        'NEEDRESTART_MODE=a',
        *args,
    ]


def _debian_apt_install_cmd(*packages: str) -> list[str]:
    # CI/bootstrap flows should avoid recommended desktop/media packages.
    return _debian_noninteractive_cmd(
        'apt-get',
        'install',
        '-y',
        '--no-install-recommends',
        *packages,
    )


def _is_apt_lock_error(ex: Exception) -> bool:
    if not isinstance(ex, CommandError):
        return False
    text = f'{ex.result.stderr}\n{ex.result.stdout}\n{ex}'.lower()
    lock_markers = (
        'could not get lock',
        'unable to acquire the dpkg frontend lock',
        'unable to lock the administration directory',
        'is another process using it',
    )
    return any(marker in text for marker in lock_markers)


def install_deps_debian(*, assume_yes: bool = True) -> None:
    # TODO: add alternative ways to install deps for other common systems that
    # can use libvirt.
    require_sudo_allowed(
        feature='Host dependency installation (apt-get)',
        hint=(
            'Install the packages manually, or run this one command with '
            "behavior.privilege_mode set to 'as-needed'."
        ),
    )
    if not host_is_debian_like():
        raise AIVMError(
            'Host is not detected as Debian/Ubuntu; install deps manually.'
        )
    pkgs = [
        # KVM/QEMU runtime used to boot the guest.
        'qemu-kvm',
        'qemu-system-common',
        # libvirt daemon + client tooling used by almost every host operation.
        'libvirt-daemon-system',
        'libvirt-clients',
        # libvirt NAT/DHCP networks require dnsmasq at runtime.
        'dnsmasq-base',
        # `virt-install` and cloud image helpers used to define new VMs.
        'virtinst',
        'cloud-image-utils',
        # Disk/image inspection and copy-on-write helpers.
        'qemu-utils',
        # Host-side networking, SSH, and firewall tools that the workflows call.
        'curl',
        'openssh-client',
        'iproute2',
        'nftables',
        # setfacl/getfacl: sudo-free storage prep and storage adoption grant
        # libvirt-qemu traversal via POSIX ACLs instead of chown/chmod.
        'acl',
    ]
    del assume_yes
    mgr = CommandManager.current()
    try:
        with mgr.intent(
            'Prepare host libvirt dependencies',
            why=(
                'Fresh-machine VM workflows need libvirt, qemu, cloud-init tools, '
                'and libvirtd available before network or VM setup can succeed.'
            ),
            role='modify',
        ):
            with mgr.step(
                'Install Debian/Ubuntu host dependencies',
                why=(
                    'Refresh apt metadata, install required VM host packages, '
                    'attempt optional virtiofsd installation, and enable libvirtd.'
                ),
                approval_scope='host-install-deps',
            ):
                mgr.submit(
                    _debian_noninteractive_cmd('apt-get', 'update', '-y'),
                    sudo=True,
                    role='modify',
                    check=True,
                    capture=False,
                    summary='Refresh apt package metadata',
                )
                mgr.submit(
                    _debian_apt_install_cmd(*pkgs),
                    sudo=True,
                    role='modify',
                    check=True,
                    capture=False,
                    summary='Install required qemu/libvirt/cloud-init host packages',
                )
                # Some distros split virtiofsd into a separate package; install
                # best-effort so folder sharing can work when available.
                virtiofsd_install = mgr.submit(
                    _debian_apt_install_cmd('virtiofsd'),
                    sudo=True,
                    role='modify',
                    check=False,
                    capture=False,
                    summary='Try installing optional virtiofsd package',
                    detail='Folder sharing can rely on virtiofsd on some hosts.',
                )
                mgr.submit(
                    ['systemctl', 'enable', '--now', 'libvirtd'],
                    sudo=True,
                    role='modify',
                    check=False,
                    capture=False,
                    summary='Enable and start libvirtd service',
                )
    except CommandError as ex:
        if _is_apt_lock_error(ex):
            raise AIVMError(
                'apt/dpkg appears to be locked by another process. '
                'Close other package managers or wait for unattended upgrades to finish, then retry.'
            ) from ex
        raise
    if virtiofsd_install.code != 0:
        log.warning(
            'Optional package `virtiofsd` was not installed. '
            'Folder sharing may fail if virtiofsd is unavailable on this host.'
        )
