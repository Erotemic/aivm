"""Configuration schema and TOML serialization helpers.

These dataclasses describe user-facing config knobs. ``store.py`` composes them
into the global config registry format.
"""

from __future__ import annotations

import re
import socket
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from loguru import logger as log

from .util import expand

# TODO(design): replace the ad-hoc URL + hash globals here with a network asset
# dataclass/registry that can describe the primary URL, SHA256, mirrors,
# torrent magnet, and IPFS CID for a pinned image artifact.
# Pinned daily image path so URL and hash are coupled to a specific artifact.
DEFAULT_UBUNTU_NOBLE_IMG_URL = 'https://cloud-images.ubuntu.com/noble/20260225/noble-server-cloudimg-amd64.img'
SUPPORTED_IMAGE_SHA256 = {
    DEFAULT_UBUNTU_NOBLE_IMG_URL: '7aa6d9f5e8a3a55c7445b138d31a73d1187871211b2b7da9da2e1a6cbf169b21',
}

_DEFAULT_VM_NAME_PREFIX = 'aivm-2404-'
_MAX_GUEST_HOSTNAME_LEN = 63


def default_host_label(hostname: str | None = None) -> str:
    """Return the host label used to make default VM names local-host specific.

    The source identity is the host's own short node name, not an FQDN that
    DNS might synthesize later. The returned value is safe for libvirt domain
    names, SSH host aliases, and Linux guest hostnames.
    """
    raw = socket.gethostname() if hostname is None else hostname
    short = str(raw or '').split('.', 1)[0].strip().lower()
    label = re.sub(r'[^a-z0-9-]+', '-', short)
    label = re.sub(r'-+', '-', label).strip('-')
    return label or 'host'


def default_vm_name(hostname: str | None = None) -> str:
    """Return the default canonical VM / guest-host / SSH alias name.

    Existing explicit config values are not migrated. Missing/implicit names use
    this factory, so users relying on the old implicit ``aivm-2404`` default now
    get a host-qualified default such as ``aivm-2404-workstation``.
    """
    label = default_host_label(hostname)
    max_label_len = _MAX_GUEST_HOSTNAME_LEN - len(_DEFAULT_VM_NAME_PREFIX)
    if max_label_len > 0 and len(label) > max_label_len:
        label = label[:max_label_len].rstrip('-') or 'host'
    return f'{_DEFAULT_VM_NAME_PREFIX}{label}'


@dataclass
class NetworkConfig:
    name: str = 'aivm-net'
    bridge: str = 'virbr-aivm'
    subnet_cidr: str = '10.77.0.0/24'
    gateway_ip: str = '10.77.0.1'
    dhcp_start: str = '10.77.0.100'
    dhcp_end: str = '10.77.0.200'


@dataclass
class FirewallConfig:
    enabled: bool = True
    table: str = 'aivm_sandbox'
    block_cidrs: list[str] = field(
        # TODO: document why these are the defaults
        default_factory=lambda: [
            '0.0.0.0/8',
            '10.0.0.0/8',
            '100.64.0.0/10',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '224.0.0.0/4',
            '240.0.0.0/4',
        ]
    )
    extra_block_cidrs: list[str] = field(default_factory=list)
    allow_tcp_ports: list[int] = field(default_factory=list)
    allow_udp_ports: list[int] = field(default_factory=list)


@dataclass
class ImageConfig:
    ubuntu_img_url: str = DEFAULT_UBUNTU_NOBLE_IMG_URL
    # TODO(design): shift from name-based cache identity toward digest-based
    # identity so content-addressable image fallback paths are first-class.
    cache_name: str = 'noble-base.img'
    redownload: bool = False


@dataclass
class VMConfig:
    name: str = field(default_factory=default_vm_name)
    user: str = 'agent'
    cpus: int = 4
    ram_mb: int = 8192
    disk_gb: int = 40
    allow_password_login: bool = True
    password: str = 'agent'
    # IANA timezone name for the guest (e.g. "America/New_York"). Empty
    # means "match the host at cloud-init time"; see
    # aivm.detect.detect_host_timezone. Set explicitly (e.g. "UTC") to
    # pin the guest to a specific timezone regardless of the host's.
    timezone: str = ''
    # Create the guest user with the host invoking-user's numeric UID/GID
    # so files shared via virtiofs have matching ownership on both sides.
    # The host UID is captured at create-time and baked into cloud-init;
    # changing this on an existing VM requires recreation.
    match_host_user_ids: bool = True
    # Maintain a host-side symlink that mirrors the layout of folders
    # shared into the guest, so guest-side absolute paths resolve to the
    # same host-side filesystem location. Off by default for backwards
    # compatibility with existing setups.
    mirror_shared_home_folders: bool = False


@dataclass
class ProvisionConfig:
    enabled: bool = True
    install_docker: bool = True
    packages: list[str] = field(
        default_factory=lambda: [
            'git',
            'jq',
            'ripgrep',
            'fd-find',
            'tmux',
            'htop',
            'unzip',
            'ca-certificates',
            'curl',
        ]
    )


@dataclass
class ToolsConfig:
    """Guest developer tools managed outside apt/snap packaging.

    Tool fields are compact declarative specs:
      * ``"off"`` disables management.
      * ``"latest"`` means the upstream default current release.
      * a version/channel string pins the requested tool.

    ``uv`` uses Astral's standalone installer. ``rust`` uses rustup, not
    distro Rust packages or snap. Rust is off by default because it is a
    larger toolchain; set ``rust = "stable"`` to manage it. ``code`` installs
    the VS Code CLI from Microsoft's apt repository (not snap) so
    ``code tunnel`` workflows can run inside the VM; it is off by default
    because it is only useful for VS Code Remote Tunnels users. Enable it
    persistently with ``code = "latest"`` in this section, or one-shot via
    ``aivm vm provision code``.
    """

    uv: str = 'latest'
    rust: str = 'off'
    code: str = 'off'
    bin_dir: str = '~/.local/bin'


@dataclass
class PathsConfig:
    base_dir: str = '/var/lib/libvirt/aivm'
    state_dir: str = '~/.cache/aivm'
    ssh_identity_file: str = ''
    ssh_pubkey_path: str = ''


#: Default user-owned VM storage tree for the session runtime.
SESSION_DEFAULT_BASE_DIR = '~/.local/share/aivm'


@dataclass
class RuntimeConfig:
    """Which libvirt runtime a VM binds to.

    ``mode``:

    * ``'system'``  -- privileged system daemon (``qemu:///system``):
      managed NAT network, shared storage under ``/var/lib/libvirt/aivm``,
      optional nftables firewall. The classic default.
    * ``'session'`` -- per-user daemon (``qemu:///session``): fully
      rootless. User-owned storage, user-mode passt networking with a
      forwarded localhost SSH port, no managed network, no firewall, and
      a structural never-sudo guarantee (session forces
      ``behavior.privilege_mode='sudoless'``).

    The runtime is a per-VM property: a session VM and a system VM can
    coexist in one config store with distinct URIs, storage, and
    connectivity records. Changing the mode of an existing VM is not a
    migration -- recreate the VM instead.
    """

    mode: str = 'system'


def apply_session_runtime_defaults(cfg: 'AgentVMConfig') -> None:
    """Adjust config defaults that differ under the session runtime.

    A session VM cannot use the system-mode storage default (root-owned
    ``/var/lib/libvirt/aivm``), so a still-default ``paths.base_dir`` is
    re-pointed at the user-owned session tree. Explicitly configured
    paths are respected as-is.
    """
    if str(cfg.runtime.mode or '').strip().lower() != 'session':
        return
    default_base = expand(PathsConfig().base_dir)
    if expand(cfg.paths.base_dir) == default_base:
        cfg.paths.base_dir = SESSION_DEFAULT_BASE_DIR


@dataclass
class BehaviorConfig:
    yes_sudo: bool = False
    auto_approve_readonly_sudo: bool = True
    verbose: int = 1
    # How aivm acquires privileges for host operations:
    #   'auto'     - probe what works without sudo (libvirt group membership,
    #                user-writable image trees) and escalate only when needed.
    #   'sudo'     - always use sudo for privileged host operations.
    #   'sudoless' - never invoke sudo; root-only features (firewall,
    #                shared-root/persistent host bind mounts, dependency
    #                install) fail with guidance. See `aivm host sudoless`.
    privilege_mode: str = 'auto'


@dataclass
class VirtiofsConfig:
    """Per-VM virtiofs compatibility knobs.

    ``inode_file_handles`` is kept for config-file compatibility with a
    short-lived experimental wrapper strategy. Normal managed-libvirt mode
    intentionally ignores non-empty values for now: AIVM must not silently
    generate host-side executables/scripts and configure libvirt to run them.

    See ``dev/design/future/virtiofsd-inode-file-handles.md`` before
    re-enabling any strategy for passing ``--inode-file-handles``.
    """

    # Empty means: use libvirt's managed virtiofsd invocation. If an older
    # config contains ``prefer``/``never``/``mandatory``, current update logic
    # treats it as disabled and removes old AIVM-managed wrapper paths from
    # domain XML.
    inode_file_handles: str = ''
    # Guest-side virtiofs fd guard (see docs/source/virtiofs.rst and
    # aivm/fdguard.py). Host virtiofsd pins one O_PATH fd per inode the
    # guest keeps cached and hits EMFILE at min(RLIMIT_NOFILE, fs.nr_open),
    # typically 1,048,576. The guard runs inside the guest from a systemd
    # timer: it keeps updatedb from sweeping virtiofs shares nightly and
    # flushes guest dentry/inode caches when the fuse inode count crosses
    # ``fd_guard_threshold``. New VMs get it via cloud-init when enabled;
    # existing running VMs are reconciled by ``aivm vm update`` (install,
    # refresh on config/version change, uninstall when disabled), and
    # ``aivm vm fdguard`` offers direct manual control.
    fd_guard: bool = True
    fd_guard_threshold: int = 500_000
    fd_guard_interval_sec: int = 60


@dataclass
class AgentVMConfig:
    vm: VMConfig = field(default_factory=VMConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    image: ImageConfig = field(default_factory=ImageConfig)
    provision: ProvisionConfig = field(default_factory=ProvisionConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    virtiofs: VirtiofsConfig = field(default_factory=VirtiofsConfig)
    verbosity: int = 1

    def expanded_paths(self) -> 'AgentVMConfig':
        self.paths.base_dir = expand(self.paths.base_dir)
        self.paths.state_dir = expand(self.paths.state_dir)
        self.paths.ssh_identity_file = (
            expand(self.paths.ssh_identity_file)
            if self.paths.ssh_identity_file
            else ''
        )
        self.paths.ssh_pubkey_path = (
            expand(self.paths.ssh_pubkey_path)
            if self.paths.ssh_pubkey_path
            else ''
        )
        return self


def _toml_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('"', '\\"')


def dump_toml(cfg: AgentVMConfig) -> str:
    d = asdict(cfg)
    lines: list[str] = []
    verbosity = d.get('verbosity', 1)
    if isinstance(verbosity, int) and verbosity != 1:
        lines.append(f'verbosity = {verbosity}')
        lines.append('')
    for section, body in d.items():
        if section == 'verbosity':
            continue
        if isinstance(body, dict):
            lines.append(f'[{section}]')
            for k, v in body.items():
                if isinstance(v, bool):
                    lines.append(f'{k} = {"true" if v else "false"}')
                elif isinstance(v, int):
                    lines.append(f'{k} = {v}')
                elif isinstance(v, list):
                    parts = [f'"{_toml_escape(str(item))}"' for item in v]
                    lines.append(f'{k} = [{", ".join(parts)}]')
                else:
                    lines.append(f'{k} = "{_toml_escape(str(v))}"')
            lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def load(path: Path) -> AgentVMConfig:
    raw = tomllib.loads(path.read_text(encoding='utf-8'))
    cfg = AgentVMConfig()
    for section in (
        'vm',
        'runtime',
        'network',
        'firewall',
        'image',
        'provision',
        'tools',
        'paths',
        'virtiofs',
    ):
        if section in raw and isinstance(raw[section], dict):
            sec = raw[section]
            obj = getattr(cfg, section)
            for k, v in sec.items():
                if hasattr(obj, k):
                    setattr(obj, k, v)
    if 'verbosity' in raw:
        cfg.verbosity = raw['verbosity']
    return cfg


def save(path: Path, cfg: AgentVMConfig) -> None:
    log.info('Writing VM config to {}', path)
    path.write_text(dump_toml(cfg), encoding='utf-8')
