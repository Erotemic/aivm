"""CLI commands that inspect and establish host permissions.

``aivm host permissions check`` reports whether the current account can
perform routine system-libvirt and VM-storage operations without sudo, while
separately identifying features that inherently require escalation.
``aivm host permissions setup`` establishes the host-side prerequisites:
libvirt group membership and a user-owned VM storage tree with libvirt-qemu
traversal ACLs. ``--adopt`` additionally performs a privileged in-place
metadata pass over each existing storage tree.

Setup does not change privilege policy. ``behavior.privilege_mode`` and
``firewall.enabled`` stay yours to set. Once the host work is done, the
default ``privilege_mode='as-needed'`` stops invoking sudo for libvirt and
image operations on its own. ``--persist`` opts in to the one config value
the host work genuinely depends on (``defaults.paths.base_dir``, which the
ACLs are granted on), and writes nothing else.
"""

from __future__ import annotations

import getpass
import os
import shlex
import textwrap
from pathlib import Path
from typing import Any

import kwconf

from ..commands import CommandManager
from ..config import AgentVMConfig, BehaviorConfig, PathsConfig
from ..config_store import load_store, materialize_vm_cfg, save_store
from ..errors import AIVMError
from ..modes import PrivilegeMode
from ..privilege import (
    LIBVIRT_GROUP,
    LIBVIRT_QEMU_USER,
    libvirt_without_sudo_ok,
    normalize_privilege_mode,
    qemu_traversal_blockers,
    user_can_write_path,
    user_in_libvirt_group,
)
from ..services import cfg_path
from ..status import status_line
from ..util import expand, which
from ..vm.domain import (
    _get_vm_state,
    _is_vm_active,
    _start_vm,
    _wait_for_vm_state,
    shutdown_vm,
)
from ._common import _BaseCommand

#: Where setup puts VM storage when the configured base_dir needs root.
USER_BASE_DIR = '~/.local/share/aivm'


def _effective_default_base_dir(config_opt: str | None) -> Path:
    """Return the base_dir new VMs would get from the config store."""
    try:
        path = cfg_path(config_opt)
        if path.exists():
            reg = load_store(path)
            if reg.defaults is not None and reg.defaults.paths.base_dir:
                return Path(expand(reg.defaults.paths.base_dir))
    except Exception:
        pass
    return Path(expand(PathsConfig().base_dir))


def _storage_dirs_to_grade(config_opt: str | None) -> list[tuple[Path, str]]:
    """Return ``(dir, used_by)`` pairs for the storage the store actually uses.

    Readiness is a property of the directories aivm will really touch: each
    distinct ``base_dir`` of a stored VM, plus the persisted defaults dir
    (what new VMs get) when one is set.  The built-in default only matters
    when the store records neither -- grading it despite every actual VM
    living elsewhere would fail hosts that are in fact fully ready.
    """
    dirs: dict[Path, list[str]] = {}
    reg = None
    try:
        path = cfg_path(config_opt)
        if path.exists():
            reg = load_store(path)
    except Exception:
        reg = None
    if reg is not None:
        if reg.defaults is not None and reg.defaults.paths.base_dir:
            dirs.setdefault(
                Path(expand(reg.defaults.paths.base_dir)), []
            ).append('new VMs')
        for rec in reg.vms:
            base = rec.cfg.paths.base_dir
            if base:
                dirs.setdefault(Path(expand(base)), []).append(
                    f'vm {rec.name!r}'
                )
    if not dirs:
        dirs[Path(expand(PathsConfig().base_dir))] = ['new VMs']
    return [(d, ', '.join(users)) for d, users in dirs.items()]


#: Adoption changes metadata recursively. Reject broad system roots even when
#: they happen to be configured as a storage directory.
_PROTECTED_ADOPT_PATHS = {
    Path('/'),
    Path('/bin'),
    Path('/boot'),
    Path('/dev'),
    Path('/etc'),
    Path('/home'),
    Path('/lib'),
    Path('/lib64'),
    Path('/mnt'),
    Path('/opt'),
    Path('/proc'),
    Path('/root'),
    Path('/run'),
    Path('/sbin'),
    Path('/srv'),
    Path('/sys'),
    Path('/tmp'),
    Path('/usr'),
    Path('/var'),
    Path('/var/lib'),
    Path('/var/lib/libvirt'),
}


def _adopt_safety_error(tree: Path) -> str | None:
    """Return why ``tree`` is too broad for recursive metadata changes."""
    try:
        resolved = tree.resolve(strict=True)
    except OSError as ex:
        return f'cannot resolve the storage directory: {ex}'
    if not resolved.is_dir():
        return 'the configured storage path is not a directory'
    protected = set(_PROTECTED_ADOPT_PATHS)
    try:
        protected.add(Path.home().resolve(strict=True))
    except OSError:
        pass
    if resolved in protected:
        return 'the path is a broad system or home directory, not dedicated VM storage'
    return None


def _vms_stored_under(config_opt: str | None, tree: Path) -> list[str]:
    """Names of stored VMs whose ``base_dir`` is ``tree``."""
    try:
        path = cfg_path(config_opt)
        if not path.exists():
            return []
        reg = load_store(path)
    except Exception:
        return []
    return sorted(
        rec.name
        for rec in reg.vms
        if rec.cfg.paths.base_dir
        and Path(expand(rec.cfg.paths.base_dir)) == tree
    )


def _adoptable_storage_trees(config_opt: str | None) -> list[Path]:
    """Existing storage dirs from the store that still need sudo."""
    return [
        tree
        for tree, _used_by in _storage_dirs_to_grade(config_opt)
        if tree.is_dir() and not user_can_write_path(tree)
    ]


def _cfg_for_stored_vm(config_opt: str | None, name: str) -> AgentVMConfig:
    """Materialize a stored VM's config; fall back to a name-only config.

    The lifecycle helpers adoption drives (``shutdown_vm``) only read
    ``cfg.vm.name``, so a store whose network record is missing must not
    block the storage handoff.
    """
    try:
        reg = load_store(cfg_path(config_opt))
        return materialize_vm_cfg(reg, name)
    except Exception:
        cfg = AgentVMConfig()
        cfg.vm.name = name
        return cfg


def _adopt_script(tree: Path) -> str:
    """Render the privileged in-place storage metadata handoff.

    The walk never follows symlinks and prunes every descendant mount point
    listed in ``/proc/self/mountinfo``. That second rule is essential: a bind
    mount can live on the same filesystem, so ``find -xdev`` is not sufficient.
    """
    program = textwrap.dedent(
        f"""\
        import grp
        import os
        import stat
        import subprocess
        from pathlib import Path

        tree = Path(os.path.realpath({str(tree)!r}))
        libvirt_gid = grp.getgrnam({LIBVIRT_GROUP!r}).gr_gid

        def decode_mount_field(text):
            out = []
            index = 0
            while index < len(text):
                if (
                    ord(text[index]) == 92
                    and index + 3 < len(text)
                    and text[index + 1:index + 4].isdigit()
                ):
                    out.append(chr(int(text[index + 1:index + 4], 8)))
                    index += 4
                else:
                    out.append(text[index])
                    index += 1
            return ''.join(out)

        mountpoints = set()
        with open('/proc/self/mountinfo', encoding='utf-8') as file:
            for line in file:
                fields = line.split()
                if len(fields) >= 5:
                    mountpoint = Path(decode_mount_field(fields[4]))
                    if mountpoint != tree and tree in mountpoint.parents:
                        mountpoints.add(mountpoint)

        directories = []
        for root_text, dirnames, filenames in os.walk(
            tree, topdown=True, followlinks=False
        ):
            root = Path(root_text)
            kept = []
            for name in dirnames:
                path = root / name
                if path.is_symlink() or path in mountpoints:
                    continue
                kept.append(name)
            dirnames[:] = kept

            directories.append(root)
            paths = [root]
            paths.extend(root / name for name in filenames)
            for path in paths:
                if path.is_symlink():
                    continue
                info = path.stat(follow_symlinks=False)
                mode = stat.S_IMODE(info.st_mode)
                mode |= stat.S_IRGRP | stat.S_IWGRP
                if path.is_dir() or mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    mode |= stat.S_IXGRP
                if path.is_dir():
                    mode |= stat.S_ISGID
                os.chown(path, -1, libvirt_gid, follow_symlinks=False)
                os.chmod(path, mode, follow_symlinks=False)

        if subprocess.run(
            ['sh', '-c', 'command -v setfacl >/dev/null 2>&1']
        ).returncode == 0:
            for offset in range(0, len(directories), 128):
                chunk = [str(path) for path in directories[offset:offset + 128]]
                subprocess.run(
                    [
                        'setfacl',
                        '-m',
                        'u:{LIBVIRT_QEMU_USER}:x',
                        '-m',
                        'default:group:{LIBVIRT_GROUP}:rwX',
                        '-m',
                        'default:user:{LIBVIRT_QEMU_USER}:x',
                        '--',
                        *chunk,
                    ],
                    check=True,
                )
        """
    )
    return f'python3 -c {shlex.quote(program)}'


def _adopt_one_tree(
    args: Any, mgr: CommandManager, tree: Path, vm_names: list[str]
) -> None:
    """Hand one storage tree to the libvirt group, cycling running VMs."""
    running: list[str] = []
    for name in vm_names:
        code, state, _err = _get_vm_state(name)
        if code == 0 and _is_vm_active(state):
            running.append(name)
    print(
        f'Adopting {tree} in place: group ownership and access metadata are '
        f'updated recursively for {LIBVIRT_GROUP}. Disk bytes, VM definitions, '
        'and storage paths are not changed.'
    )
    if running:
        print(
            f'Stopping {", ".join(running)} first: libvirt records disk '
            'ownership when a VM starts and restores it at shutdown. Every VM '
            'that reaches the shut-off state will be restarted even if the '
            'metadata handoff fails.'
        )
    if args.dry_run:
        for name in running:
            print(f'DRYRUN: virsh shutdown {name} (start again afterwards)')
        print(
            f'DRYRUN: recursively grant {LIBVIRT_GROUP} access under {tree}; '
            'prune mounted subtrees and symlinks; set setgid/default ACLs'
        )
        return

    stopped: list[str] = []
    pending_error: BaseException | None = None
    try:
        for name in running:
            print(f'Shutting down VM {name} ...')
            shutdown_vm(_cfg_for_stored_vm(args.config, name))
            _wait_for_vm_state(
                name, 'shut off', timeout_s=180, poll_interval_s=2
            )
            stopped.append(name)
        with mgr.step(
            'Hand VM storage to the libvirt group',
            why=(
                'Changing access metadata on the existing tree removes sudo '
                'from routine image operations without moving or recreating '
                'the VM.'
            ),
            approval_scope=f'host-permissions-adopt:{tree}',
        ):
            mgr.submit(
                ['bash', '-c', _adopt_script(tree)],
                sudo=True,
                role='modify',
                check=True,
                capture=True,
                summary=f'Grant {LIBVIRT_GROUP} access to {tree}',
                detail=f'tree={tree}; descendant mounts and symlinks pruned',
            )
    except BaseException as ex:
        pending_error = ex

    restart_errors: list[str] = []
    for name in stopped:
        try:
            print(f'Starting VM {name} again ...')
            _start_vm(name)
        except Exception as ex:
            restart_errors.append(f'{name}: {ex}')

    if pending_error is not None:
        if restart_errors:
            pending_error.add_note(
                'Additionally failed to restart: ' + '; '.join(restart_errors)
            )
        raise pending_error.with_traceback(pending_error.__traceback__)
    if restart_errors:
        raise AIVMError(
            'Storage adoption completed, but some VMs did not restart: '
            + '; '.join(restart_errors)
        )
    print(f'✅ Adopted {tree}; file operations there no longer need sudo.')


def _run_storage_adoption(
    args: Any, mgr: CommandManager, *, group_added: bool
) -> int:
    trees = _adoptable_storage_trees(args.config)
    if not trees:
        print(
            'Nothing to adopt: every storage directory your config uses is '
            'already writable without sudo.'
        )
        print()
        _print_policy_report(args.config, group_added=group_added)
        return 0
    for tree in trees:
        safety_error = _adopt_safety_error(tree)
        if safety_error is not None:
            print(
                f'❌ Refusing to adopt {tree}: {safety_error}. Point VM '
                'storage at a dedicated directory first.'
            )
            return 2
    if which('setfacl') is None:
        print(
            '❌ Storage adoption requires setfacl so existing and future '
            f'files remain reachable by {LIBVIRT_QEMU_USER}. Install the acl '
            'package before retrying.'
        )
        return 2
    for tree in trees:
        _adopt_one_tree(args, mgr, tree, _vms_stored_under(args.config, tree))
    print()
    _print_policy_report(args.config, group_added=group_added)
    return 0


def _print_base_dir_toml(base_dir: Path) -> None:
    """Print the exact config lines that point VM storage at ``base_dir``."""
    print()
    print('    [defaults.paths]')
    print(f'    base_dir = "{base_dir}"')
    print()


def _configured_privilege_mode(config_opt: str | None) -> PrivilegeMode:
    """Return the persisted privilege mode."""
    try:
        path = cfg_path(config_opt)
        if not path.exists():
            return normalize_privilege_mode(BehaviorConfig().privilege_mode)
        reg = load_store(path)
    except Exception:
        return normalize_privilege_mode(BehaviorConfig().privilege_mode)
    return normalize_privilege_mode(reg.behavior.privilege_mode)


def _print_policy_report(config_opt: str | None, *, group_added: bool) -> None:
    """Report the privilege policy setup deliberately did not change."""
    mode = _configured_privilege_mode(config_opt)
    if mode == PrivilegeMode.ALWAYS:
        print("behavior.privilege_mode = 'always': aivm escalates for every")
        print('  privileged-capable operation, so the host work above buys you')
        print("  nothing until you switch to 'as-needed'.")
    else:
        print(f"behavior.privilege_mode = '{mode}', unchanged and correct:")
        print('  once the libvirt group is active, aivm stops invoking sudo for')
        print('  libvirt and image operations on its own. Sudo remains for')
        print('  managed nftables, apt-get, and establishing a new host bind mount.')
    if group_added:
        print(
            f'👉 Group membership added. Log out and back in (or run `newgrp '
            f'{LIBVIRT_GROUP}`) so it takes effect.'
        )
    print('Run `aivm host permissions check` to verify readiness.')


def _firewall_enabled_anywhere(config_opt: str | None) -> bool:
    """Return True when any stored config still enables the nft firewall.

    Firewall settings live on ``[[networks]]`` records (VM entries keep only
    a ``network_name`` pointer, and ``rec.cfg.firewall`` is the *default*,
    not the persisted value -- see ``materialize_vm_cfg``), so the network
    records and the defaults section are the two truth sources.
    """
    try:
        path = cfg_path(config_opt)
        if not path.exists():
            return AgentVMConfig().firewall.enabled
        reg = load_store(path)
        if reg.defaults is not None and reg.defaults.firewall.enabled:
            return True
        if reg.defaults is None and not reg.networks:
            return AgentVMConfig().firewall.enabled
        return any(net.firewall.enabled for net in reg.networks)
    except Exception:
        return True


class HostPermissionsCheckCLI(_BaseCommand):
    """Report where aivm still needs sudo on this host.

    Under ``'as-needed'`` (the default), operations that still need sudo are
    reported as friction rather than failure. The exit code is nonzero only
    when something breaks VM operation regardless of privilege policy.
    """

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        mode = _configured_privilege_mode(args.config)
        lines: list[str] = ['🔐 Host permission readiness']
        broken: list[str] = []  # breaks VMs regardless of privilege mode
        sudo_needs: list[str] = []

        def friction_line(
            ok: bool, label: str, detail: str, need: str
        ) -> str:
            """Render an operation that still costs sudo as a warning."""
            if not ok:
                sudo_needs.append(need)
            return status_line(ok, label, detail, warn_only=True)

        in_group = user_in_libvirt_group()
        lines.append(
            friction_line(
                in_group,
                f'{LIBVIRT_GROUP} group membership',
                'grants direct qemu:///system access without sudo'
                if in_group
                else f'run `sudo usermod -aG {LIBVIRT_GROUP} {getpass.getuser()}` '
                'or `aivm host permissions setup`',
                'libvirt access (virsh)',
            )
        )

        live_access = libvirt_without_sudo_ok()
        live_detail = 'virsh reaches qemu:///system without sudo'
        if not live_access:
            live_detail = (
                'virsh cannot reach qemu:///system without sudo'
                + (
                    ' (group added but not active in this session; log out/in '
                    f'or use `newgrp {LIBVIRT_GROUP}`)'
                    if in_group
                    else ''
                )
            )
        lines.append(
            friction_line(
                live_access,
                'live libvirt access',
                live_detail,
                'libvirt access (virsh)',
            )
        )

        any_blockers = False
        for base_dir, used_by in _storage_dirs_to_grade(args.config):
            writable = user_can_write_path(base_dir)
            if writable:
                storage_detail = f'{base_dir} ({used_by})'
            elif base_dir.is_dir():
                storage_detail = (
                    f'{base_dir} ({used_by}) needs sudo; `aivm host '
                    'permissions setup --adopt` hands it to the libvirt '
                    'group in place'
                )
            else:
                storage_detail = (
                    f'{base_dir} ({used_by}) needs sudo; `aivm host '
                    'permissions setup` prepares a user-owned dir'
                )
            lines.append(
                friction_line(
                    writable,
                    'VM storage writable',
                    storage_detail,
                    f'VM storage under {base_dir}',
                )
            )
            blockers = qemu_traversal_blockers(base_dir)
            if blockers is None:
                lines.append(
                    status_line(
                        None,
                        f'{LIBVIRT_QEMU_USER} traversal',
                        'undetermined (libvirt not fully installed?)',
                    )
                )
            else:
                if blockers:
                    # qemu cannot read images it cannot reach; that breaks VM
                    # start regardless of privilege policy.
                    broken.append(f'qemu traversal to {base_dir}')
                    any_blockers = True
                lines.append(
                    status_line(
                        not blockers,
                        f'{LIBVIRT_QEMU_USER} traversal',
                        f'qemu can reach {base_dir}'
                        if not blockers
                        else 'blocked by: '
                        + ', '.join(str(b) for b in blockers)
                        + ' (setup grants ACLs on dirs you own)',
                    )
                )

        setfacl_ok = which('setfacl') is not None
        if setfacl_ok:
            lines.append(
                status_line(
                    True,
                    'setfacl available',
                    'used to grant qemu traversal without loosening '
                    'permissions',
                )
            )
        elif any_blockers:
            broken.append('setfacl (needed to fix the traversal above)')
            lines.append(
                status_line(
                    False, 'setfacl available', 'install the `acl` package'
                )
            )
        else:
            lines.append(
                status_line(
                    None,
                    'setfacl available',
                    'not installed; only needed when granting qemu traversal '
                    'on user-owned storage',
                )
            )

        fw_enabled = _firewall_enabled_anywhere(args.config)
        if not fw_enabled:
            lines.append(
                status_line(
                    None,
                    'firewall compatibility',
                    'firewall disabled; nothing needs root',
                )
            )
        else:
            lines.append(
                friction_line(
                    False,
                    'firewall compatibility',
                    'applying nftables rules uses sudo; disable '
                    'firewall.enabled to avoid it',
                    'the nftables firewall',
                )
            )

        lines.append(
            status_line(
                True if mode != PrivilegeMode.ALWAYS else None,
                'privilege mode',
                f'behavior.privilege_mode = {str(mode)!r}',
            )
        )

        print('\n'.join(lines))
        needs = list(dict.fromkeys(sudo_needs))
        if broken:
            print(
                '❌ Broken in every privilege mode: '
                + '; '.join(dict.fromkeys(broken))
                + '. Run `aivm host permissions setup`.'
            )
            return 2
        if needs:
            print(
                f'✅ Ready under privilege_mode {str(mode)!r}; sudo will be '
                'used for: ' + '; '.join(needs) + '.'
            )
            print('   `aivm host permissions setup` trims that list.')
            return 0
        print('✅ Host permissions are ready for routine VM operation.')
        return 0


class HostPermissionsSetupCLI(_BaseCommand):
    """Prepare host permissions for routine aivm operation.

    Normal setup may use sudo for libvirt group membership. Adoption also
    uses one privileged in-place metadata pass over each existing storage tree.
    Your config is not modified
    unless you pass ``--persist``, and even then only
    ``defaults.paths.base_dir`` is written.
    """

    base_dir: str = kwconf.Value(
        '',
        help=(
            'User-owned VM storage directory to prepare (default: the '
            f'directory your config already resolves to, else {USER_BASE_DIR}).'
        ),
    )
    persist: bool = kwconf.Flag(
        False,
        help=(
            'Write the prepared directory to defaults.paths.base_dir. '
            'Nothing else is ever written: privilege_mode and '
            'firewall.enabled stay yours to set.'
        ),
    )
    adopt: bool = kwconf.Flag(
        False,
        help=(
            'Instead of preparing a new user-owned directory, grant the '
            'libvirt group access to existing VM storage in place. File '
            'ownership, modes, and ACLs change recursively, but disk bytes, '
            'VM definitions, and storage paths do not. Descendant mounts and '
            'symlinks are pruned. Running VMs are briefly stopped and restarted.'
        ),
    )
    dry_run: bool = kwconf.Flag(False, help='Print actions without running.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        mgr = CommandManager.current()

        group_added = False
        if not user_in_libvirt_group():
            # Under `sudo aivm ...`, the account that needs libvirt access
            # is the invoking user, not root.
            user = os.environ.get('SUDO_USER') or getpass.getuser()
            if args.dry_run:
                print(f'DRYRUN: sudo usermod -aG {LIBVIRT_GROUP} {user}')
            else:
                with mgr.intent(
                    'Enable libvirt access without sudo',
                    why=(
                        'Membership in the libvirt group lets virsh reach '
                        'qemu:///system without sudo (polkit rule shipped '
                        'with libvirt).'
                    ),
                    role='modify',
                ):
                    with mgr.step(
                        'Add user to libvirt group',
                        why=(
                            'This privileged step grants direct access to the '
                            'system libvirt daemon for future commands.'
                        ),
                        approval_scope='host-permissions-setup-group',
                    ):
                        mgr.submit(
                            ['usermod', '-aG', LIBVIRT_GROUP, user],
                            sudo=True,
                            role='modify',
                            check=True,
                            capture=True,
                            summary=f'Add {user} to the {LIBVIRT_GROUP} group',
                        )
                group_added = True

        if args.adopt:
            # Adoption keeps every VM exactly where it is; only ownership
            # changes. It is the mode-switch path for hosts with existing
            # sudo-era VMs; the flow below instead prepares a fresh
            # user-owned tree for hosts starting clean.
            return _run_storage_adoption(args, mgr, group_added=group_added)

        # The ACLs below are granted on one specific directory, so they are
        # worthless unless aivm goes on to use it. Prefer the directory the
        # config already resolves to: when that is user-owned the host work
        # lands where aivm already looks and no config change is implied.
        resolved_default = _effective_default_base_dir(args.config)
        base_dir = (
            Path(expand(args.base_dir)) if args.base_dir else resolved_default
        )
        if not args.base_dir and not user_can_write_path(base_dir):
            base_dir = Path(expand(USER_BASE_DIR))
            print(
                f'{resolved_default} is not user-writable, so preparing '
                f'{base_dir} instead.'
            )
        if not user_can_write_path(base_dir):
            print(
                f'❌ {base_dir} is not writable by you; pass a user-owned '
                'directory via --base_dir.'
            )
            return 2
        config_gap = base_dir != resolved_default

        if args.dry_run:
            print(f'DRYRUN: mkdir -p {base_dir}; grant {LIBVIRT_QEMU_USER} ACLs')
        else:
            with mgr.intent(
                'Prepare VM storage permissions',
                why=(
                    'VM images and cloud-init artifacts live in a '
                    'user-owned tree so no file operation needs sudo.'
                ),
                role='modify',
            ):
                with mgr.step(
                    'Create user-owned VM storage and grant qemu traversal',
                    why=(
                        'QEMU runs as libvirt-qemu and needs execute (search) '
                        'access on every ancestor of the image tree; targeted '
                        'ACLs grant that without changing ownership.'
                    ),
                    approval_scope=f'host-permissions-setup-storage:{base_dir}',
                ):
                    mgr.submit(
                        ['mkdir', '-p', str(base_dir)],
                        sudo=False,
                        role='modify',
                        check=True,
                        capture=True,
                        summary='Create VM storage directory',
                        detail=f'target={base_dir}',
                    )
                    mgr.submit(
                        ['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(base_dir)],
                        sudo=False,
                        role='modify',
                        check=True,
                        capture=True,
                        summary=f'Allow {LIBVIRT_QEMU_USER} to traverse {base_dir}',
                    )
            blockers = qemu_traversal_blockers(base_dir) or []
            own_blockers = [b for b in blockers if user_can_write_path(b)]
            foreign = [b for b in blockers if not user_can_write_path(b)]
            for b in own_blockers:
                mgr.run(
                    ['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(b)],
                    sudo=False,
                    role='modify',
                    check=True,
                    capture=True,
                    summary=f'Allow {LIBVIRT_QEMU_USER} to traverse {b}',
                )
            if foreign:
                print(
                    '⚠️ These directories still block libvirt-qemu and are '
                    'not owned by you:'
                )
                for b in foreign:
                    print(f'  sudo setfacl -m u:{LIBVIRT_QEMU_USER}:x {b}')

        store = cfg_path(args.config)
        has_defaults = store.exists() and load_store(store).defaults is not None
        if config_gap and args.persist and not has_defaults:
            # Creating a [defaults] section to hold one path would materialize
            # every other default alongside it, pinning values the user never
            # chose -- including a hostname-derived vm.name. Decline.
            print()
            print(
                f'❌ Cannot persist: {store} has no [defaults] section, and '
                'creating one would pin every other default value. Run '
                '`aivm config init` first, or add this yourself:'
            )
            _print_base_dir_toml(base_dir)
            return 2
        if config_gap and args.persist:
            if args.dry_run:
                print(f'DRYRUN: would persist default base_dir={base_dir}')
            else:
                reg = load_store(store)
                assert reg.defaults is not None  # guarded by has_defaults
                reg.defaults.paths.base_dir = str(base_dir)
                save_store(
                    reg,
                    store,
                    reason=f'Persist host permission setup: base_dir={base_dir}.',
                )
                print(f'Persisted default paths.base_dir = {base_dir}')
        elif config_gap:
            print()
            print(
                f'Nothing in your config changed. aivm still resolves VM '
                f'storage to {resolved_default}, so the ACLs just granted on '
                f'{base_dir} will go unused until you point it there. Add to '
                f'{store}:'
            )
            _print_base_dir_toml(base_dir)
            if has_defaults:
                print('Or re-run with --persist to write exactly that line.')
        else:
            print(
                f'Nothing in your config needs to change; VM storage already '
                f'resolves to {base_dir}.'
            )

        print()
        _print_policy_report(args.config, group_added=group_added)
        existing_vms = load_store(store).vms if store.exists() else []
        for rec in existing_vms:
            vm_base = Path(expand(rec.cfg.paths.base_dir))
            if not user_can_write_path(vm_base):
                print(
                    f'⚠️ Existing VM {rec.name!r} stores images under '
                    f'{vm_base}, which still needs sudo. Run `aivm host '
                    'permissions setup --adopt` to hand that storage to the '
                    'libvirt group in place -- the VM is untouched (briefly '
                    'stopped if running) and no config change is needed.'
                )
        return 0


class HostPermissionsModalCLI(kwconf.ModalCLI):
    """Inspect or establish host permissions for routine VM operation."""

    check = HostPermissionsCheckCLI
    setup = HostPermissionsSetupCLI
