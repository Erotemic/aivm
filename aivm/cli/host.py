"""Host-focused CLI commands.

Covers host preflight checks, dependency installation, and host-level helpers
that are prerequisites for VM workflows.
"""

from __future__ import annotations

import sys
from typing import Any

import kwconf

from ..commands import CommandManager
from ..detect import running_under_wsl, systemd_is_pid1
from ..host import (
    check_commands,
    check_commands_with_sudo,
    host_is_debian_like,
    install_deps_debian,
)
from ..services import resolve_cfg_fallback
from ..vm import fetch_image
from ._common import _BaseCommand
from .firewall import FirewallModalCLI
from .host_sudoless import SudolessModalCLI
from .net import NetModalCLI


def _print_wsl_diagnostics() -> bool:
    """Print WSL2-specific prerequisite findings; True when one is fatal.

    WSL hosts hit a distinct set of footguns (no /dev/kvm without nested
    virtualization, systemd disabled so the system libvirt daemon cannot
    run). Surfacing them here keeps `aivm host doctor` the one diagnostic
    entry point. See docs/source/wsl.rst.
    """
    if not running_under_wsl():
        return False
    print('ℹ️ WSL detected (see the WSL guide in the aivm docs).')
    problem = False
    from pathlib import Path

    if not Path('/dev/kvm').exists():
        problem = True
        print(
            '❌ /dev/kvm is missing. WSL1 cannot run KVM at all; on WSL2 '
            'enable nested virtualization: add `nestedVirtualization=true` '
            'under `[wsl2]` in `%UserProfile%\\.wslconfig` on Windows, then '
            '`wsl --shutdown` and reopen.'
        )
    if not systemd_is_pid1():
        problem = True
        print(
            '❌ systemd is not PID 1. The system libvirt daemon needs '
            'systemd: add `[boot]\nsystemd=true` to /etc/wsl.conf, then '
            '`wsl --shutdown` and reopen.'
        )
    return problem


class DoctorCLI(_BaseCommand):
    """Check host prerequisites and list missing required tools."""

    sudo: bool = kwconf.Flag(
        False,
        help='Also verify required commands are available under sudo -n.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        wsl_problem = _print_wsl_diagnostics()
        missing, missing_opt = check_commands()
        if missing:
            print('❌ Missing required commands:', ', '.join(missing))
            print('💡 On Debian/Ubuntu you can run: aivm host install_deps')
            return 2
        if wsl_problem:
            return 2
        if args.sudo:
            missing_sudo, sudo_err = check_commands_with_sudo()
            if sudo_err:
                print(f'❌ Sudo preflight failed: {sudo_err}')
                return 2
            if missing_sudo:
                print(
                    '❌ Missing required commands under sudo PATH:',
                    ', '.join(missing_sudo),
                )
                print(
                    '💡 Ensure required tools are installed in locations '
                    'available to sudo secure_path.'
                )
                return 2
        if missing_opt:
            print('➖ Missing optional commands:', ', '.join(missing_opt))
        print('✅ Required host commands are present.')
        return 0


class HostInstallDepsCLI(_BaseCommand):
    """Install required host dependencies on Debian/Ubuntu."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        _ = cls.cli(argv=argv, data=kwargs)
        if not host_is_debian_like():
            print(
                '❌ Host not detected as Debian/Ubuntu. Install dependencies manually.',
                file=sys.stderr,
            )
            return 2
        mgr = CommandManager.current()
        with mgr.intent(
            'Prepare host dependencies',
            why='Install the host packages required for libvirt-managed VM workflows.',
            role='modify',
        ):
            install_deps_debian(assume_yes=True)
        print('✅ Installed host dependencies (best effort).')
        return 0


class ImageFetchCLI(_BaseCommand):
    """Download/cache the configured Ubuntu base image."""

    dry_run: bool = kwconf.Flag(
        False, help='Print actions without running.'
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        cfg, _ = resolve_cfg_fallback(args.config)
        mgr = CommandManager.current()
        with mgr.intent(
            'Fetch base image',
            why='Prepare the Ubuntu cloud image used for later VM creation.',
            role='modify',
        ):
            print(str(fetch_image(cfg, dry_run=args.dry_run)))
        return 0


class HostModalCLI(kwconf.ModalCLI):
    """Host preparation and host-level operations."""

    doctor = DoctorCLI
    install_deps = HostInstallDepsCLI
    image_fetch = ImageFetchCLI
    net = NetModalCLI
    fw = FirewallModalCLI
    sudoless = SudolessModalCLI
