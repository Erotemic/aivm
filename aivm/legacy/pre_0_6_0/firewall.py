"""Cleanup helpers for nftables state created before AIVM 0.6."""

from __future__ import annotations

from ...config import AgentVMConfig


def table_to_remove(
    cfg: AgentVMConfig,
    *,
    current_table: str,
) -> str | None:
    """Return the old un-namespaced table if it may still shadow 0.6 rules."""
    old_table = str(cfg.firewall.table or '').strip()
    if old_table and old_table != current_table:
        return old_table
    return None
