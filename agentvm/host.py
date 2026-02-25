from __future__ import annotations

from pathlib import Path

from loguru import logger

from .util import run_cmd, which

log = logger

REQUIRED_CMDS = [
    "virsh",
    "virt-install",
    "qemu-img",
    "cloud-localds",
    "curl",
    "ip",
    "ssh",
]
OPTIONAL_CMDS = ["nft", "ssh-keyscan"]


def check_commands() -> tuple[list[str], list[str]]:
    missing = [c for c in REQUIRED_CMDS if which(c) is None]
    missing_opt = [c for c in OPTIONAL_CMDS if which(c) is None]
    return missing, missing_opt


def host_is_debian_like() -> bool:
    try:
        data = Path("/etc/os-release").read_text(encoding="utf-8")
        return any(k in data for k in ("ID=debian", "ID=ubuntu", "ID_LIKE=debian"))
    except Exception:
        return False


def install_deps_debian(*, assume_yes: bool = True) -> None:
    if not host_is_debian_like():
        raise RuntimeError(
            "Host is not detected as Debian/Ubuntu; install deps manually."
        )
    pkgs = [
        "qemu-kvm",
        "libvirt-daemon-system",
        "libvirt-clients",
        "virtinst",
        "cloud-image-utils",
        "qemu-utils",
        "curl",
        "openssh-client",
        "iproute2",
        "nftables",
    ]
    run_cmd(["apt-get", "update", "-y"], sudo=True, check=True, capture=True)
    run_cmd(["apt-get", "install", "-y", *pkgs], sudo=True, check=True, capture=True)
    run_cmd(
        ["systemctl", "enable", "--now", "libvirtd"],
        sudo=True,
        check=False,
        capture=True,
    )
