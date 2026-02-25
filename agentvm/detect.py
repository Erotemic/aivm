from __future__ import annotations

import ipaddress
import os
from pathlib import Path

import logging

from .config import AgentVMConfig
from .util import run_cmd, which, expand

log = logging.getLogger("agentvm")


def detect_ssh_identity() -> tuple[str, str]:
    if which("ssh"):
        try:
            res = run_cmd(
                ["ssh", "-G", "unknown@doesnt.exist"], check=True, capture=True
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].lower() == "identityfile":
                    ident = expand(parts[1])
                    pub = ident + ".pub"
                    if os.path.exists(ident):
                        return ident, pub if os.path.exists(pub) else ""
        except Exception:
            pass
    for cand in ("~/.ssh/id_ed25519", "~/.ssh/id_rsa"):
        p = expand(cand)
        if os.path.exists(p):
            pub = p + ".pub"
            return p, pub if os.path.exists(pub) else ""
    return "", ""


def existing_ipv4_routes() -> list[ipaddress.IPv4Network]:
    res = run_cmd(["ip", "-4", "route", "show"], check=True, capture=True)
    nets: list[ipaddress.IPv4Network] = []
    for line in res.stdout.splitlines():
        tok = line.split()[0]
        if "/" in tok:
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))  # type: ignore[arg-type]
            except Exception:
                continue
    return nets


def pick_free_subnet(preferred: list[str]) -> str:
    routes = existing_ipv4_routes()
    for cidr in preferred:
        cand = ipaddress.ip_network(cidr, strict=False)  # type: ignore[arg-type]
        if not any(cand.overlaps(r) for r in routes):
            return cidr
    return preferred[0]


def auto_defaults(cfg: AgentVMConfig, *, project_dir: Path) -> AgentVMConfig:
    ident, pub = detect_ssh_identity()
    if not cfg.paths.ssh_identity_file and ident:
        cfg.paths.ssh_identity_file = ident
    if not cfg.paths.ssh_pubkey_path and pub:
        cfg.paths.ssh_pubkey_path = pub

    if not cfg.share.host_src:
        cfg.share.host_src = str(project_dir)

    preferred = [
        "10.77.0.0/24",
        "10.78.0.0/24",
        "10.79.0.0/24",
        "10.88.0.0/24",
        "10.99.0.0/24",
        "192.168.77.0/24",
        "192.168.88.0/24",
    ]
    subnet = pick_free_subnet(preferred)
    cfg.network.subnet_cidr = subnet
    net = ipaddress.ip_network(subnet, strict=False)  # type: ignore[arg-type]
    base = int(net.network_address)
    cfg.network.gateway_ip = str(ipaddress.IPv4Address(base + 1))
    cfg.network.dhcp_start = str(ipaddress.IPv4Address(base + 100))
    cfg.network.dhcp_end = str(ipaddress.IPv4Address(base + 200))

    if len(cfg.network.bridge) > 15:
        cfg.network.bridge = "virbr-aivm"

    return cfg
