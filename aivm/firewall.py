"""Nftables policy generation/apply helpers for guest network isolation.

Rules are bridge-scoped and oriented toward "WAN allowed, private ranges
restricted" behavior unless caller config loosens/tightens policy.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import TypeAlias, TypeGuard

from loguru import logger

from .commands import CommandManager
from .config import AgentVMConfig
from .errors import AIVMError
from .legacy.pre_0_6_0.firewall import table_to_remove
from .privilege import require_sudo_allowed, sudo_allowed
from .runtime import virsh_cmd
from .xmlutil import parse_domain_xml

JsonObj: TypeAlias = Mapping[str, object]

log = logger


def effective_firewall_table(cfg: AgentVMConfig) -> str:
    """Return the network-specific nftables table managed for ``cfg``.

    A configured table name is a namespace prefix, not a globally shared
    singleton.  Including stable network identity prevents applying or removing
    one network policy from replacing another network's rules.
    """
    base = re.sub(
        r'[^A-Za-z0-9_.-]+', '_', str(cfg.firewall.table or '').strip()
    )
    base = base.strip('._-') or 'aivm_sandbox'
    network = re.sub(
        r'[^A-Za-z0-9_.-]+', '_', str(cfg.network.name or '').strip()
    )
    network = network.strip('._-') or 'network'
    # Network name is the stable system-wide identity. Bridge and subnet are
    # mutable configuration; including them would orphan the old firewall
    # table every time a network is edited.
    identity = str(cfg.network.name or '')
    digest = hashlib.sha256(identity.encode('utf-8')).hexdigest()[:10]
    suffix = f'{network[:32]}_{digest}'
    max_base = max(1, 127 - len(suffix) - 1)
    return f'{base[:max_base]}_{suffix}'


def _is_json_obj(value: object) -> TypeGuard[JsonObj]:
    return isinstance(value, Mapping)


def _normalize_port_list(ports: list[int]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for raw in ports or []:
        try:
            p = int(raw)
        except Exception as ex:
            raise AIVMError(f'Invalid firewall port value: {raw!r}') from ex
        if p < 1 or p > 65535:
            raise AIVMError(
                f'Invalid firewall port {p}; expected range 1..65535.'
            )
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _effective_bridge_and_gateway(cfg: AgentVMConfig) -> tuple[str, str]:
    """Prefer live libvirt network metadata over potentially stale config."""
    bridge = cfg.network.bridge
    gateway = cfg.network.gateway_ip
    mgr = CommandManager.current()
    if mgr.current_plan() is None:
        with mgr.step(
            'Inspect live libvirt network metadata',
            why=(
                'Read the current libvirt network XML so firewall rules use '
                'the live bridge and gateway even if config is stale.'
            ),
            approval_scope=f'network-xml:{cfg.network.name}',
        ):
            res = mgr.submit(
                virsh_cmd('net-dumpxml', cfg.network.name),
                sudo=True,
                role='read',
                check=False,
                capture=True,
                eager=True,
                summary=f'Read live libvirt XML for network {cfg.network.name}',
            )
    else:
        res = mgr.submit(
            virsh_cmd('net-dumpxml', cfg.network.name),
            sudo=True,
            role='read',
            check=False,
            capture=True,
            eager=True,
            summary=f'Read live libvirt XML for network {cfg.network.name}',
        )
    if res.code != 0 or not (res.stdout or '').strip():
        return bridge, gateway
    root = parse_domain_xml(res.stdout)
    if root is None:
        return bridge, gateway
    br_node = root.find('./bridge')
    ip_node = root.find('./ip')
    live_bridge = (
        br_node.attrib.get('name', '').strip() if br_node is not None else ''
    )
    live_gateway = (
        ip_node.attrib.get('address', '').strip() if ip_node is not None else ''
    )
    if live_bridge and live_bridge != bridge:
        log.warning(
            'Firewall bridge differs from config: config={} live={}. Using live value.',
            bridge,
            live_bridge,
        )
        bridge = live_bridge
    if live_gateway and live_gateway != gateway:
        log.warning(
            'Firewall gateway differs from config: config={} live={}. Using live value.',
            gateway,
            live_gateway,
        )
        gateway = live_gateway
    return bridge, gateway


def _nft_script(cfg: AgentVMConfig, *, inspect_live: bool = True) -> str:
    table = effective_firewall_table(cfg)
    if inspect_live:
        br, gw = _effective_bridge_and_gateway(cfg)
    else:
        br, gw = cfg.network.bridge, cfg.network.gateway_ip
    blocks = list(cfg.firewall.block_cidrs) + list(
        cfg.firewall.extra_block_cidrs or []
    )
    seen = set()
    blocks2 = []
    for b in blocks:
        b = b.strip()
        if not b or b in seen:
            continue
        seen.add(b)
        blocks2.append(b)
    block_set = ', '.join(blocks2)
    allow_tcp = _normalize_port_list(cfg.firewall.allow_tcp_ports)
    allow_udp = _normalize_port_list(cfg.firewall.allow_udp_ports)
    host_allow_lines: list[str] = []
    blocked_allow_lines: list[str] = []
    if allow_tcp:
        ports = ', '.join(str(p) for p in allow_tcp)
        host_allow_lines.append(
            f'    iifname "{br}" tcp dport {{{ports}}} accept'
        )
        blocked_allow_lines.append(
            f'    iifname "{br}" ip daddr {{{block_set}}} tcp dport {{{ports}}} accept'
        )
    if allow_udp:
        ports = ', '.join(str(p) for p in allow_udp)
        host_allow_lines.append(
            f'    iifname "{br}" udp dport {{{ports}}} accept'
        )
        blocked_allow_lines.append(
            f'    iifname "{br}" ip daddr {{{block_set}}} udp dport {{{ports}}} accept'
        )
    host_allow = '\n'.join(host_allow_lines)
    blocked_allow = '\n'.join(blocked_allow_lines)
    if host_allow:
        host_allow = host_allow + '\n'
    if blocked_allow:
        blocked_allow = blocked_allow + '\n'
    return f"""
table inet {table} {{
  chain input {{
    type filter hook input priority 0; policy accept;
    ct state established,related accept
    # DHCP client traffic may be broadcast (255.255.255.255), not just gateway-directed.
    iifname "{br}" udp dport {{67,68}} accept
    iifname "{br}" ip daddr {gw} udp dport 53 accept
    iifname "{br}" ip daddr {gw} tcp dport 53 accept
    iifname "{br}" ip daddr {gw} icmp type echo-request accept
{host_allow}    # All other VM->host traffic on bridge is denied by default.
    iifname "{br}" drop
  }}
  chain forward {{
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
{blocked_allow}    # Default blocklist for VM->LAN/private ranges.
    iifname "{br}" ip daddr {{{block_set}}} drop
    iifname "{br}" accept
  }}
}}
"""


def apply_firewall(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    log.debug('Applying nftables firewall rules')
    if not cfg.firewall.enabled:
        log.info('Firewall disabled in config; skipping.')
        return
    require_sudo_allowed(
        feature='Firewall management (nftables)',
        hint=(
            'Disable the managed firewall (firewall.enabled = false) or set '
            "behavior.privilege_mode to 'as-needed' to allow sudo for it."
        ),
    )
    script = _nft_script(cfg, inspect_live=not dry_run)
    table = effective_firewall_table(cfg)
    mgr = CommandManager.current()
    if dry_run:
        mgr.preview(
            ['nft', 'delete', 'table', 'inet', table],
            sudo=True,
            role='modify',
            check=False,
            capture=True,
            summary=f'Remove previous nftables table inet {table} if present',
        )
        legacy = table_to_remove(cfg, current_table=table)
        if legacy:
            mgr.preview(
                ['nft', 'delete', 'table', 'inet', legacy],
                sudo=True,
                role='modify',
                check=False,
                capture=True,
                summary=f'Remove pre-upgrade nftables table inet {legacy} if present',
            )
        mgr.preview(
            ['nft', '-f', '-'],
            sudo=True,
            role='modify',
            check=True,
            capture=True,
            input_text=script,
            summary=f'Load rendered nftables rules into inet {table}',
        )
        return
    with mgr.intent(
        f'Apply firewall table {table}',
        why=(
            'The VM bridge firewall step enforces the configured host/guest '
            'isolation policy before workloads run inside the VM.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Replace nftables rules for managed VM bridge',
            why=(
                'Clear the previous managed nftables table if present, then '
                'load the freshly rendered ruleset.'
            ),
            approval_scope=f'firewall:{table}',
        ):
            mgr.submit(
                ['nft', 'delete', 'table', 'inet', table],
                sudo=True,
                role='modify',
                check=False,
                capture=True,
                summary=f'Remove previous nftables table inet {table} if present',
            )
            legacy = table_to_remove(cfg, current_table=table)
            if legacy:
                mgr.submit(
                    ['nft', 'delete', 'table', 'inet', legacy],
                    sudo=True,
                    role='modify',
                    check=False,
                    capture=True,
                    summary=(
                        f'Remove pre-upgrade nftables table inet {legacy} '
                        'if present'
                    ),
                    detail=(
                        'Older aivm versions installed rules under the '
                        'configured table name directly; a leftover copy '
                        'would keep filtering alongside the new table.'
                    ),
                )
            mgr.submit(
                ['nft', '-f', '-'],
                sudo=True,
                role='modify',
                check=True,
                capture=True,
                input_text=script,
                summary=f'Load rendered nftables rules into inet {table}',
            )
    log.info('Firewall rules applied (table=inet {}).', table)


def ensure_firewall_ready(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    """Verify the managed nftables table before a guest runs, and repair it.

    The one place that decides what to do about the sandbox firewall when a
    VM is about to carry a workload. Both the attached-session reconcile and
    plain ``vm up``/``vm restart`` call it, because a guest that boots
    without the table is equally unprotected either way and the two paths
    drifting apart is how that goes unnoticed.

    Three outcomes, and the distinction between the last two is the whole
    point:

    * the table is present -- nothing to do;
    * the table is *known* missing -- install it, or say clearly that it is
      missing and could not be installed;
    * the table could not be *checked* -- say exactly that and change
      nothing.

    Unverifiable is not the same as missing. ``nft`` has no unprivileged
    read, so on a shared workstation every non-administrator lands in the
    third case permanently: their account cannot inspect the table an admin
    already installed correctly. Treating that silence as "absent" would
    schedule a repair they cannot perform and abort a session that had
    nothing wrong with it. The honest answer is to report the blind spot and
    let the guest run, which is also why this never raises: a firewall that
    cannot be checked must not be the thing that stops a user from working.
    """
    if not cfg.firewall.enabled:
        return
    table = effective_firewall_table(cfg)
    if dry_run:
        # No guest is about to run, so there is nothing to guarantee -- and
        # a privileged nftables read would be a real escalation inside a
        # command whose whole promise is that it changes nothing.
        log.info('DRYRUN: would verify firewall table inet {}', table)
        return
    mgr = CommandManager.current()
    # One start-time guarantee per invocation. Both the session reconcile
    # and the VM start path call this, and re-reading nftables for the
    # second one only buys a duplicate sudo prompt.
    #
    # Deliberately not keyed on mutation_generation, unlike the probe caches
    # that convention covers: "this table is installed" is not invalidated
    # by an unrelated mutation, and starting a VM bumps that counter, which
    # would expire the memo every single time and defeat it. The only local
    # commands that can falsify it are in this module, and remove_firewall
    # drops the entry itself.
    cache: dict[str, bool] = mgr.probe_cache.setdefault('firewall_ready', {})
    if cache.get(table):
        return
    if not sudo_allowed():
        log.warning(
            'Skipping firewall reconciliation: privilege_mode = never and '
            'nftables requires root. Set firewall.enabled = false to '
            'silence this warning.'
        )
        return
    from .status import probe_firewall

    # The read is attempted even when `sudo -n true` says credentials are
    # cold: a host may carry a NOPASSWD rule scoped to nft alone, and
    # pre-judging from a generic sudo probe would skip the check on exactly
    # the hosts that configured it most carefully.
    _note_unavoidable_firewall_sudo(table)
    present: bool | None = None
    with mgr.attempt(
        f'Verify managed firewall table inet {table}',
        why=(
            'Reading nftables requires root; when that read is unavailable '
            'the session continues with the firewall unverified rather than '
            'assuming the table is missing.'
        ),
    ) as checking:
        present = probe_firewall(cfg, use_sudo=True).ok
    if checking.failed:
        _warn_firewall_unverified(table, checking.reason)
        return
    if present:
        cache[table] = True
        return
    if present is None:
        _warn_firewall_unverified(
            table, 'the privileged nftables read returned no usable answer'
        )
        return

    # Only here is the table known to be absent. Repairing it is likewise
    # attempted rather than gated on a sudo capability guess, so a host with
    # a narrowly scoped NOPASSWD rule still gets its rules installed.
    with mgr.attempt(
        f'Install managed firewall table inet {table}',
        why=(
            'A guest must not silently lose its sandbox rules, but a caller '
            'without root cannot install them either.'
        ),
    ) as applying:
        apply_firewall(cfg)
    if applying.failed:
        _warn_firewall_missing(table, detail=applying.reason)
        return
    cache[table] = True


def _warn_firewall_unverified(table: str, reason: str) -> None:
    log.warning(
        'Could not verify the managed firewall table inet {}: {}.',
        table,
        reason,
    )
    log.warning(
        '  The guest is starting with its sandbox rules UNVERIFIED. They may '
        'be installed and working, or absent; reading nftables needs root '
        'and this run could not.'
    )
    log.warning(
        '  A host administrator can confirm with `sudo aivm firewall status` '
        'and install them with `sudo aivm firewall apply`.'
    )


def _warn_firewall_missing(table: str, *, detail: str = '') -> None:
    log.warning(
        'The managed firewall table inet {} is MISSING and could not be '
        'installed from this account.',
        table,
    )
    if detail:
        log.warning('  Reason: {}', detail)
    log.warning(
        '  The guest is starting WITHOUT its sandbox network rules. Ask a '
        'host administrator to run `sudo aivm firewall apply`.'
    )


def _note_unavoidable_firewall_sudo(table: str) -> None:
    """Explain the firewall probe's sudo prompt before it appears.

    This one is not avoidable and not a symptom of anything being wrong, so
    say that up front rather than letting it read as a stray escalation:
    ``nft`` offers no unprivileged read, and the managed table lives only in
    the kernel's live ruleset, so a host reboot always takes it with it.

    Quiet when sudo is already authenticated -- with no prompt coming, the
    explanation is just noise.
    """
    if not CommandManager.current().sudo_authentication_required():
        return
    log.info(
        'The next step needs sudo and there is no way around it: reading '
        'nftables state (table inet {}) requires root, with no unprivileged '
        'fallback.',
        table,
    )
    log.info(
        'The managed table exists only in the live kernel ruleset, so it is '
        'gone after every host reboot and has to be checked (and usually '
        'reinstalled) before the first session.'
    )
    log.info(
        'Expect this roughly once per boot: later runs skip the firewall '
        'check entirely while the VM stays reachable over SSH. Pass '
        '--no-ensure_firewall to skip it, at the cost of running the '
        'session without verified sandbox rules.'
    )


def firewall_status(cfg: AgentVMConfig) -> str:
    if not sudo_allowed():
        return 'firewall status needs privileges (unavailable when mode)\n'
    table = effective_firewall_table(cfg)
    mgr = CommandManager.current()
    with mgr.intent(
        f'Inspect firewall table {table}',
        why='Read the current nftables rules for the managed VM bridge.',
        role='read',
    ):
        with mgr.step(
            'Read managed nftables firewall table',
            why=(
                'Inspect the current nftables table so firewall diagnostics '
                'match the live host state.'
            ),
            approval_scope=f'firewall-status:{table}',
        ):
            res = mgr.submit(
                ['nft', 'list', 'table', 'inet', table],
                sudo=True,
                role='read',
                check=False,
                capture=True,
                summary=f'Read nftables table inet {table}',
            )
    result = res.result()
    return result.stdout + (result.stderr or '')


def read_firewall_tcp_ports(
    cfg: AgentVMConfig, *, use_sudo: bool
) -> tuple[tuple[int, ...] | None, str]:
    # TODO: this function can be a lot cleaner and server other use-cases
    # currently only used in drift detection.

    table = effective_firewall_table(cfg)
    bridge = cfg.network.bridge

    if not sudo_allowed():
        # nft reads require root; report unavailable instead of escalating.
        return None, 'firewall checks need privileges (privilege_mode = never)'

    res = CommandManager.current().run(
        ['nft', '--json', 'list', 'table', 'inet', table],
        role='read',
        sudo=use_sudo,
        check=False,
        capture=True,
    )

    if res.code != 0:
        raw = (res.stderr or res.stdout or 'nft list table failed').strip()
        if 'you must be root' in res.stderr or 'not permitted' in res.stderr:
            return None, raw
        return None, raw

    import json

    text = res.stdout or ''
    data = json.loads(text)

    def _expr_is_iifname_match(expr: object, want_ifname: str) -> bool:
        if not _is_json_obj(expr):
            return False

        match = expr.get('match')
        if not _is_json_obj(match):
            return False

        op = match.get('op')
        left = match.get('left')
        right = match.get('right')

        if op != '==':
            return False
        if left != {'meta': {'key': 'iifname'}}:
            return False
        return right == want_ifname

    def _extract_tcp_dports(expr: object) -> tuple[int, ...]:
        """
        Handles forms like:
            {"match": {"left": {"payload": {...}}, "op": "==", "right": 22}}
            {"match": {"left": {"payload": {...}}, "op": "==", "right": {"set": [22, 80]}}}
        """
        if not _is_json_obj(expr):
            return ()

        match = expr.get('match')
        if not _is_json_obj(match):
            return ()

        left = match.get('left')
        if not _is_json_obj(left):
            return ()

        payload = left.get('payload')
        if not _is_json_obj(payload):
            return ()

        if payload.get('protocol') != 'tcp' or payload.get('field') != 'dport':
            return ()

        right = match.get('right')
        vals: list[int] = []

        if isinstance(right, int):
            vals.append(right)
        elif isinstance(right, str) and right.isdigit():
            vals.append(int(right))
        elif _is_json_obj(right):
            set_items = right.get('set')
            if isinstance(set_items, list):
                for item in set_items:
                    if isinstance(item, int):
                        vals.append(item)
                    elif isinstance(item, str) and item.isdigit():
                        vals.append(int(item))

        return tuple(sorted(set(vals)))

    def _rule_has_ip_daddr_constraint(exprs: Sequence[object]) -> bool:
        """
        Reject rules with any explicit ip daddr match, because those are
        infrastructure/special-case rules (e.g. gateway DNS), not the user
        allow_tcp_ports rule we want.
        """
        for expr in exprs:
            if not _is_json_obj(expr):
                continue

            match = expr.get('match')
            if not _is_json_obj(match):
                continue

            left = match.get('left')
            if not _is_json_obj(left):
                continue

            payload = left.get('payload')
            if not _is_json_obj(payload):
                continue

            if (
                payload.get('protocol') == 'ip'
                and payload.get('field') == 'daddr'
            ):
                return True
        return False

    ports: set[int] = set()

    for item in data.get('nftables', []):
        if not _is_json_obj(item):
            continue

        rule = item.get('rule')
        if not _is_json_obj(rule):
            continue

        if rule.get('family') != 'inet' or rule.get('table') != table:
            continue

        exprs = rule.get('expr')
        if not isinstance(exprs, list) or not exprs:
            continue

        # Only consider rules bound to the VM bridge.
        if not any(_expr_is_iifname_match(expr, bridge) for expr in exprs):
            continue

        # Exclude gateway/service-specific rules like tcp dport 53 to gateway.
        if _rule_has_ip_daddr_constraint(exprs):
            continue

        # Find a plain tcp dport match in the rule.
        rule_ports: tuple[int, ...] = ()
        for expr in exprs:
            extracted = _extract_tcp_dports(expr)
            if extracted:
                rule_ports = extracted
                break

        if not rule_ports:
            continue

        # Require terminal verdict accept.
        has_accept = any(
            _is_json_obj(expr)
            and 'accept' in expr
            and expr.get('accept') is None
            for expr in exprs
        )
        if not has_accept:
            continue

        ports.update(rule_ports)

    return tuple(sorted(ports)), ''


def remove_firewall(cfg: AgentVMConfig, *, dry_run: bool = False) -> None:
    require_sudo_allowed(
        feature='Firewall management (nftables)',
        hint=(
            "Set behavior.privilege_mode to 'as-needed' to allow sudo for "
            'firewall operations.'
        ),
    )
    table = effective_firewall_table(cfg)
    mgr = CommandManager.current()
    if dry_run:
        mgr.preview(
            ['nft', 'delete', 'table', 'inet', table],
            sudo=True,
            role='modify',
            check=False,
            capture=True,
            summary=f'Remove nftables table inet {table}',
        )
        legacy = table_to_remove(cfg, current_table=table)
        if legacy:
            mgr.preview(
                ['nft', 'delete', 'table', 'inet', legacy],
                sudo=True,
                role='modify',
                check=False,
                capture=True,
                summary=f'Remove pre-upgrade nftables table inet {legacy}',
            )
        return
    # Whatever ensure_firewall_ready concluded earlier in this invocation is
    # about to stop being true.
    mgr.probe_cache.setdefault('firewall_ready', {}).pop(table, None)
    with mgr.intent(
        f'Remove firewall table {table}',
        why='Delete the managed nftables table for this VM network.',
        role='modify',
    ):
        with mgr.step(
            'Delete managed nftables firewall table',
            why='Remove the nftables table created by aivm for this VM bridge.',
            approval_scope=f'firewall-remove:{table}',
        ):
            mgr.submit(
                ['nft', 'delete', 'table', 'inet', table],
                sudo=True,
                role='modify',
                check=False,
                capture=True,
                summary=f'Remove nftables table inet {table}',
            )
            legacy = table_to_remove(cfg, current_table=table)
            if legacy:
                mgr.submit(
                    ['nft', 'delete', 'table', 'inet', legacy],
                    sudo=True,
                    role='modify',
                    check=False,
                    capture=True,
                    summary=(
                        f'Remove pre-upgrade nftables table inet {legacy} '
                        'if present'
                    ),
                )
    log.info('Firewall removed (table=inet {}).', table)
