from __future__ import annotations

import logging

from .config import AgentVMConfig
from .util import run_cmd

log = logging.getLogger("agentvm")


def _nft_script(cfg: AgentVMConfig) -> str:
    table = cfg.firewall.table
    br = cfg.network.bridge
    gw = cfg.network.gateway_ip
    blocks = list(cfg.firewall.block_cidrs) + list(cfg.firewall.extra_block_cidrs or [])
    seen = set()
    blocks2 = []
    for b in blocks:
        b = b.strip()
        if not b or b in seen:
            continue
        seen.add(b)
        blocks2.append(b)
    block_set = ", ".join(blocks2)
    return f"""
table inet {table} {{
  chain input {{
    type filter hook input priority 0; policy accept;
    ct state established,related accept
    iifname "{br}" ip daddr {gw} udp dport {{67,68}} accept
    iifname "{br}" ip daddr {gw} udp dport 53 accept
    iifname "{br}" ip daddr {gw} tcp dport 53 accept
    iifname "{br}" ip daddr {gw} icmp type echo-request accept
    iifname "{br}" drop
  }}
  chain forward {{
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
    iifname "{br}" ip daddr {{{block_set}}} drop
    iifname "{br}" accept
  }}
}}
"""


def apply_firewall(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    if not cfg.firewall.enabled:
        log.info("Firewall disabled in config; skipping.")
        return
    script = _nft_script(cfg)
    table = cfg.firewall.table
    if dry_run:
        log.info("DRYRUN: nft -f - <<EOF\\n%s\\nEOF", script.rstrip())
        return
    run_cmd(
        ["nft", "delete", "table", "inet", table], sudo=True, check=False, capture=True
    )
    run_cmd(["nft", "-f", "-"], sudo=True, check=True, capture=True, input_text=script)
    log.info("Firewall rules applied (table=inet %s).", table)


def firewall_status(cfg: AgentVMConfig) -> str:
    table = cfg.firewall.table
    res = run_cmd(
        ["nft", "list", "table", "inet", table], sudo=True, check=False, capture=True
    )
    return res.stdout + (res.stderr or "")


def remove_firewall(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    table = cfg.firewall.table
    if dry_run:
        log.info("DRYRUN: nft delete table inet %s", table)
        return
    run_cmd(
        ["nft", "delete", "table", "inet", table], sudo=True, check=False, capture=True
    )
    log.info("Firewall removed (table=inet %s).", table)
