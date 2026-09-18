"""Managed firewall drift detection and reconciliation for ``vm update``."""

from __future__ import annotations

from ...config import AgentVMConfig
from ...firewall import (
    _firewall_policy_fingerprint,
    _normalize_port_list,
    apply_firewall,
    read_firewall_live_state,
    remove_firewall,
)
from .models import FirewallDrift


def _firewall_update_drift(
    cfg: AgentVMConfig,
) -> tuple[FirewallDrift | None, tuple[str, ...]]:
    """Compare the generated firewall policy with the live managed table."""
    state, error = read_firewall_live_state(cfg, use_sudo=True)
    if state is None:
        return None, (
            'Could not inspect managed firewall policy for vm update: '
            f'{error}',
        )

    desired_tcp = tuple(_normalize_port_list(cfg.firewall.allow_tcp_ports))

    if not cfg.firewall.enabled:
        if state.present:
            return (
                FirewallDrift(
                    action='remove',
                    current_tcp_ports=state.tcp_ports,
                    desired_tcp_ports=(),
                    reason=(
                        'firewall is disabled in config but the managed '
                        'table is present'
                    ),
                ),
                (),
            )
        return None, ()

    desired_fingerprint = _firewall_policy_fingerprint(
        cfg, bridge=state.bridge, gateway=state.gateway
    )
    if not state.present:
        return (
            FirewallDrift(
                action='apply',
                current_tcp_ports=None,
                desired_tcp_ports=desired_tcp,
                reason='managed firewall table is missing',
            ),
            (),
        )

    ports_differ = state.tcp_ports != desired_tcp
    policy_differ = state.policy_fingerprint != desired_fingerprint
    if not ports_differ and not policy_differ:
        return None, ()

    if ports_differ:
        reason = 'configured allowed TCP ports differ from the live table'
    elif state.policy_fingerprint is None:
        reason = 'live table predates the current firewall policy generator'
    else:
        reason = 'generated firewall policy differs from the live table'
    return (
        FirewallDrift(
            action='apply',
            current_tcp_ports=state.tcp_ports,
            desired_tcp_ports=desired_tcp,
            reason=reason,
        ),
        (),
    )


def _apply_firewall_drift(
    cfg: AgentVMConfig, drift: FirewallDrift, *, dry_run: bool
) -> bool:
    """Apply firewall reconciliation without requiring a VM restart."""
    if drift.action == 'apply':
        apply_firewall(cfg, dry_run=dry_run)
        if not dry_run:
            print('Updated managed firewall policy.')
        return True
    if drift.action == 'remove':
        remove_firewall(cfg, dry_run=dry_run)
        if not dry_run:
            print('Removed managed firewall policy (disabled in config).')
        return True
    raise AssertionError(f'Unsupported firewall drift action: {drift.action!r}')
