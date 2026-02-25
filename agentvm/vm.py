from __future__ import annotations
import time
from pathlib import Path

from loguru import logger

from .config import AgentVMConfig, DEFAULT_UBUNTU_NOBLE_IMG_URL
from .util import run_cmd, ensure_dir

log = logger


def _paths(cfg: AgentVMConfig, *, dry_run: bool = False) -> dict[str, Path]:
    cfg = cfg.expanded_paths()
    base_dir = Path(cfg.paths.base_dir) / cfg.vm.name
    img_dir = base_dir / "images"
    ci_dir = base_dir / "cloud-init"
    state_dir = Path(cfg.paths.state_dir) / cfg.vm.name
    return {
        "base_dir": base_dir,
        "img_dir": img_dir,
        "ci_dir": ci_dir,
        "state_dir": state_dir,
        "ip_file": state_dir / f"{cfg.vm.name}.ip",
        "known_hosts": state_dir / "known_hosts",
    }


def fetch_image(cfg: AgentVMConfig, *, dry_run: bool = False) -> Path:
    log.debug("Fetching Ubuntu cloud image")
    p = _paths(cfg, dry_run=dry_run)
    base_img = p["img_dir"] / cfg.image.cache_name
    url = cfg.image.ubuntu_img_url or DEFAULT_UBUNTU_NOBLE_IMG_URL
    if base_img.exists() and not cfg.image.redownload:
        log.info("Base image cached: %s", base_img)
        return base_img
    if dry_run:
        log.info("DRYRUN: curl -L --fail -o %s %s", base_img, url)
        return base_img
    ensure_dir(p["img_dir"])
    run_cmd(["mkdir", "-p", str(p["img_dir"])], sudo=True, check=True, capture=True)
    run_cmd(
        ["curl", "-L", "--fail", "-o", str(base_img), url],
        sudo=True,
        check=True,
        capture=True,
    )
    log.info("Downloaded base image: %s", base_img)
    return base_img


def _ensure_qemu_access(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    cfg = cfg.expanded_paths()
    base_root = Path(cfg.paths.base_dir) / cfg.vm.name
    grp = "kvm"
    if run_cmd(["getent", "group", "kvm"], check=False, capture=True).code != 0:
        grp = "libvirt-qemu"
    if dry_run:
        log.info("DRYRUN: chown/chmod %s for qemu access (group=%s)", base_root, grp)
        return
    run_cmd(["mkdir", "-p", str(base_root)], sudo=True, check=True, capture=True)
    run_cmd(
        ["chown", "-R", f"root:{grp}", str(base_root)],
        sudo=True,
        check=True,
        capture=True,
    )
    run_cmd(["chmod", "0751", str(base_root)], sudo=True, check=True, capture=True)
    for sub in ("images", "cloud-init"):
        d = base_root / sub
        run_cmd(["mkdir", "-p", str(d)], sudo=True, check=True, capture=True)
        run_cmd(
            ["chown", "-R", f"root:{grp}", str(d)], sudo=True, check=True, capture=True
        )
        run_cmd(["chmod", "0750", str(d)], sudo=True, check=True, capture=True)


def _write_cloud_init(cfg: AgentVMConfig, *, dry_run: bool = False) -> dict[str, Path]:
    cfg = cfg.expanded_paths()
    p = _paths(cfg, dry_run=dry_run)
    ci_dir = p["ci_dir"]
    user_data = ci_dir / "user-data"
    meta_data = ci_dir / "meta-data"
    seed_iso = ci_dir / f"{cfg.vm.name}-seed.iso"

    pubkey_path = Path(cfg.paths.ssh_pubkey_path) if cfg.paths.ssh_pubkey_path else None
    if not pubkey_path or not pubkey_path.exists():
        raise RuntimeError(
            f"Missing SSH public key. Set paths.ssh_pubkey_path in config (got: {cfg.paths.ssh_pubkey_path})"
        )
    pubkey = pubkey_path.read_text(encoding="utf-8").strip()

    ssh_pwauth = "true" if cfg.vm.allow_password_login else "false"
    lock_passwd = "false" if cfg.vm.allow_password_login else "true"
    passwd_block = ""
    sshd_pw = "yes" if cfg.vm.allow_password_login else "no"
    sshd_kbd = "yes" if cfg.vm.allow_password_login else "no"
    if cfg.vm.allow_password_login:
        if ":" in cfg.vm.password or "\n" in cfg.vm.password:
            raise RuntimeError(
                "VM password must not contain ':' or newlines (cloud-init chpasswd format)."
            )
        passwd_block = f"""
chpasswd:
  expire: false
  users:
    - name: {cfg.vm.user}
      password: {cfg.vm.password}
"""

    cloud = f"""#cloud-config
users:
  - name: {cfg.vm.user}
    groups: [sudo]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: {lock_passwd}
    ssh_authorized_keys:
      - {pubkey}

ssh_pwauth: {ssh_pwauth}
disable_root: true

{passwd_block}
package_update: true
packages:
  - openssh-server
  - ca-certificates
  - curl
  - git
  - python3
  - python3-venv
  - python3-pip
  - unattended-upgrades

write_files:
  - path: /etc/ssh/sshd_config.d/99-agentvm-hardening.conf
    permissions: "0644"
    content: |
      PasswordAuthentication {sshd_pw}
      PermitRootLogin no
      KbdInteractiveAuthentication {sshd_kbd}
      X11Forwarding no
      AllowTcpForwarding yes
      GatewayPorts no

runcmd:
  - systemctl enable --now ssh
  - systemctl enable --now unattended-upgrades || true
"""

    meta = f"""instance-id: {cfg.vm.name}
local-hostname: {cfg.vm.name}
"""

    if dry_run:
        log.info("DRYRUN: write cloud-init + cloud-localds %s", seed_iso)
        return {"user_data": user_data, "meta_data": meta_data, "seed_iso": seed_iso}

    run_cmd(["mkdir", "-p", str(ci_dir)], sudo=True, check=True, capture=True)
    _ensure_qemu_access(cfg, dry_run=False)
    run_cmd(
        ["bash", "-lc", f"cat > {user_data} <<'EOF'\n{cloud}\nEOF"],
        sudo=True,
        check=True,
        capture=True,
    )
    run_cmd(
        ["bash", "-lc", f"cat > {meta_data} <<'EOF'\n{meta}\nEOF"],
        sudo=True,
        check=True,
        capture=True,
    )
    run_cmd(
        ["cloud-localds", "-v", str(seed_iso), str(user_data), str(meta_data)],
        sudo=True,
        check=True,
        capture=True,
    )
    return {"user_data": user_data, "meta_data": meta_data, "seed_iso": seed_iso}


def _ensure_disk(
    cfg: AgentVMConfig, base_img: Path, *, dry_run: bool = False, recreate: bool = False
) -> Path:
    p = _paths(cfg, dry_run=dry_run)
    vm_disk = p["img_dir"] / f"{cfg.vm.name}.qcow2"
    if vm_disk.exists() and recreate:
        if dry_run:
            log.info("DRYRUN: rm -f %s", vm_disk)
        else:
            run_cmd(["rm", "-f", str(vm_disk)], sudo=True, check=True, capture=True)
    if vm_disk.exists():
        log.info("VM disk exists: %s", vm_disk)
        return vm_disk
    if dry_run:
        log.info(
            "DRYRUN: qemu-img create -f qcow2 -F qcow2 -b %s %s %sG",
            base_img,
            vm_disk,
            cfg.vm.disk_gb,
        )
        return vm_disk
    run_cmd(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(base_img),
            str(vm_disk),
            f"{cfg.vm.disk_gb}G",
        ],
        sudo=True,
        check=True,
        capture=True,
    )
    return vm_disk


def vm_exists(cfg: AgentVMConfig, *, dry_run: bool = False) -> bool:
    if dry_run:
        return False
    return (
        run_cmd(
            ["virsh", "dominfo", cfg.vm.name], sudo=True, check=False, capture=True
        ).code
        == 0
    )


def create_or_start_vm(
    cfg: AgentVMConfig, *, dry_run: bool = False, recreate: bool = False
) -> None:
    log.debug("Creating or starting VM %s", cfg.vm.name)
    cfg = cfg.expanded_paths()
    base_img = fetch_image(cfg, dry_run=dry_run)
    ci = _write_cloud_init(cfg, dry_run=dry_run)
    vm_disk = _ensure_disk(cfg, base_img, dry_run=dry_run, recreate=recreate)
    seed_iso = ci["seed_iso"]

    if vm_exists(cfg, dry_run=dry_run):
        if recreate:
            if dry_run:
                log.info("DRYRUN: virsh destroy/undefine %s", cfg.vm.name)
            else:
                run_cmd(
                    ["virsh", "destroy", cfg.vm.name],
                    sudo=True,
                    check=False,
                    capture=True,
                )
                run_cmd(
                    ["virsh", "undefine", cfg.vm.name, "--remove-all-storage"],
                    sudo=True,
                    check=False,
                    capture=True,
                )
                run_cmd(
                    ["virsh", "undefine", cfg.vm.name],
                    sudo=True,
                    check=False,
                    capture=True,
                )
        else:
            st = (
                run_cmd(
                    ["virsh", "domstate", cfg.vm.name],
                    sudo=True,
                    check=False,
                    capture=True,
                )
                .stdout.strip()
                .lower()
            )
            if "running" in st:
                log.info("VM already running: %s", cfg.vm.name)
                return
            if dry_run:
                log.info("DRYRUN: virsh start %s", cfg.vm.name)
                return
            run_cmd(
                ["virsh", "start", cfg.vm.name], sudo=True, check=True, capture=True
            )
            log.info("VM started: %s", cfg.vm.name)
            return

    extra = []
    if cfg.share.enabled and cfg.share.host_src:
        extra += ["--memorybacking", "source.type=memfd,access.mode=shared"]
        extra += [
            "--filesystem",
            f"source={cfg.share.host_src},target={cfg.share.tag},driver.type=virtiofs",
        ]

    cmd = [
        "virt-install",
        "--name",
        cfg.vm.name,
        "--memory",
        str(cfg.vm.ram_mb),
        "--vcpus",
        str(cfg.vm.cpus),
        "--cpu",
        "host-passthrough",
        "--import",
        "--os-variant",
        "ubuntu24.04",
        "--disk",
        f"path={vm_disk},format=qcow2,bus=virtio",
        "--disk",
        f"path={seed_iso},device=cdrom",
        "--network",
        f"network={cfg.network.name},model=virtio",
        "--graphics",
        "none",
        "--noautoconsole",
        "--rng",
        "/dev/urandom",
        "--boot",
        "uefi",
        *extra,
    ]
    if dry_run:
        log.info("DRYRUN: %s", " ".join(cmd))
        return
    run_cmd(cmd, sudo=True, check=True, capture=True)
    log.info("VM created: %s", cfg.vm.name)


def _mac_for_vm(cfg: AgentVMConfig) -> str:
    res = run_cmd(
        ["virsh", "domiflist", cfg.vm.name], sudo=True, check=False, capture=True
    )
    for line in res.stdout.splitlines():
        if (
            "network" in line.lower()
            and "interface" not in line.lower()
            and "---" not in line
        ):
            parts = line.split()
            if parts:
                return parts[-1].strip()
    return ""


def get_ip_cached(cfg: AgentVMConfig) -> str | None:
    p = _paths(cfg, dry_run=False)
    ip_file = p["ip_file"]
    if ip_file.exists():
        return ip_file.read_text(encoding="utf-8").strip() or None
    return None


def wait_for_ip(
    cfg: AgentVMConfig, *, timeout_s: int = 360, dry_run: bool = False
) -> str:
    log.debug("Waiting for VM IP via DHCP lease")
    p = _paths(cfg, dry_run=dry_run)
    ip_file = p["ip_file"]
    if dry_run:
        log.info("DRYRUN: wait for IP and write %s", ip_file)
        return "0.0.0.0"
    ensure_dir(p["state_dir"])
    mac = _mac_for_vm(cfg)
    if not mac:
        log.warning(
            "Could not determine VM MAC; DHCP lease lookup may fail. Falling back to domifaddr."
        )
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        ip = ""
        if mac:
            leases = run_cmd(
                ["virsh", "net-dhcp-leases", cfg.network.name],
                sudo=True,
                check=False,
                capture=True,
            ).stdout
            for line in leases.splitlines():
                if mac.lower() in line.lower():
                    parts = line.split()
                    for part in parts:
                        if "/" in part and "." in part:
                            ip = part.split("/")[0]
                            break
                if ip:
                    break
        if not ip:
            domif = run_cmd(
                ["virsh", "domifaddr", cfg.vm.name],
                sudo=True,
                check=False,
                capture=True,
            ).stdout
            for line in domif.splitlines():
                if "ipv4" in line.lower():
                    parts = line.split()
                    for part in parts:
                        if "/" in part and "." in part:
                            ip = part.split("/")[0]
                            break
                if ip:
                    break
        if ip:
            ip_file.write_text(ip + "\n", encoding="utf-8")
            log.info("VM IP: %s (saved to %s)", ip, ip_file)
            return ip
        time.sleep(2)
    raise TimeoutError(
        f"Timed out waiting for VM IP. Try: sudo virsh net-dhcp-leases {cfg.network.name}"
    )


def destroy_vm(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    name = cfg.vm.name
    if dry_run:
        log.info("DRYRUN: virsh destroy/undefine %s", name)
        return
    run_cmd(["virsh", "destroy", name], sudo=True, check=False, capture=True)
    run_cmd(
        ["virsh", "undefine", name, "--remove-all-storage"],
        sudo=True,
        check=False,
        capture=True,
    )
    run_cmd(["virsh", "undefine", name], sudo=True, check=False, capture=True)
    log.info("VM removed: %s", name)


def vm_status(cfg: AgentVMConfig) -> str:
    name = cfg.vm.name
    dom = run_cmd(["virsh", "dominfo", name], sudo=True, check=False, capture=True)
    if dom.code != 0:
        return f"VM not found: {name}\n"
    state = run_cmd(
        ["virsh", "domstate", name], sudo=True, check=False, capture=True
    ).stdout.strip()
    ip = get_ip_cached(cfg) or ""
    return dom.stdout + f"\nstate={state}\n" + (f"cached_ip={ip}\n" if ip else "")


def ssh_config(cfg: AgentVMConfig) -> str:
    cfg = cfg.expanded_paths()
    ip = get_ip_cached(cfg) or "VM_IP_UNKNOWN"
    ident = cfg.paths.ssh_identity_file or "~/.ssh/id_ed25519"
    host = cfg.vm.name
    return f"""Host {host}
  HostName {ip}
  User {cfg.vm.user}
  IdentityFile {ident}
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
"""


def provision(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    log.debug("Provisioning VM with developer tools")
    if not cfg.provision.enabled:
        log.info("Provision disabled; skipping.")
        return
    cfg = cfg.expanded_paths()
    if dry_run:
        ip = "0.0.0.0"
    else:
        ip = get_ip_cached(cfg) or wait_for_ip(cfg, timeout_s=360, dry_run=False)
    ident = cfg.paths.ssh_identity_file
    if not ident:
        raise RuntimeError(
            "paths.ssh_identity_file is empty; run agentvm init or set it in config."
        )
    pkgs = list(cfg.provision.packages)
    docker_pkgs = (
        ["docker.io", "docker-compose-v2"] if cfg.provision.install_docker else []
    )
    remote = (
        "set -euo pipefail; "
        "sudo apt-get update -y; "
        "sudo apt-get install -y software-properties-common >/dev/null 2>&1 || true; "
        "sudo add-apt-repository -y universe >/dev/null 2>&1 || true; "
        "sudo apt-get update -y; "
        f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {' '.join(docker_pkgs + pkgs)}"
    )
    cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-i",
        ident,
        f"{cfg.vm.user}@{ip}",
        remote,
    ]
    if dry_run:
        log.info("DRYRUN: %s", " ".join(cmd))
        return
    run_cmd(cmd, sudo=False, check=True, capture=True)
    log.info("Provisioning complete.")
