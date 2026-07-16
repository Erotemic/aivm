"""Status probe and rendering utilities for host + VM operational visibility.

This module deliberately separates *probe* functions from markdown/text
rendering so other CLI flows can reuse tri-state outcomes (``True`` /
``False`` / ``None``) without duplicating command/parsing logic.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from .commands import CommandManager
from .config import AgentVMConfig
from .config_store import AttachmentEntry, load_store
from .firewall import effective_firewall_table
from .host import check_commands
from .modes import PrivilegeMode
from .privilege import sudo_allowed, virsh_needs_sudo
from .runtime import (
    require_ssh_identity,
    ssh_base_args,
    virsh_cmd,
    virsh_domain_missing,
)
from .util import which
from .vm import get_ip_cached, vm_share_mappings
from .vm.drift import saved_vm_drift_report
from .vm.host_access import _local_stat_answer


@dataclass(frozen=True)
class ProbeOutcome:
    """Normalized status probe result.

    ``ok`` uses tri-state semantics:
    * ``True``  -> check succeeded / condition present
    * ``False`` -> check completed and condition is absent/failing
    * ``None``  -> check inconclusive/skipped (commonly privilege dependent)
    """

    ok: bool | None
    detail: str
    diag: str = ''


def status_line(ok: bool | None, label: str, detail: str = '') -> str:
    """Render a single user-facing status line with consistent icons."""
    icon = '✅' if ok is True else ('➖' if ok is None else '❌')
    suffix = f' - {detail}' if detail else ''
    return f'{icon} {label}{suffix}'


def clip(text: str, *, max_lines: int = 60) -> str:
    """Truncate multi-line diagnostics for readable terminal output."""
    lines = (text or '').strip().splitlines()
    if len(lines) <= max_lines:
        return '\n'.join(lines)
    keep: list[str] = list(lines[:max_lines])
    keep.append(f'... ({len(lines) - max_lines} more lines)')
    return '\n'.join(keep)


@dataclass
class _StatusChecklist:
    """Accumulate status lines and the done/total progress tally.

    Wraps the shared output ``lines`` list so a check appends its status
    line and updates the progress counters in one call, instead of the
    caller repeating ``total += 1; done += int(ok)`` next to every append.
    """

    lines: list[str]
    done: int = 0
    total: int = 0

    def check(
        self,
        ok: bool | None,
        label: str,
        detail: str,
        *,
        counted: bool | None = None,
    ) -> None:
        """Append a status line, counting it toward progress when conclusive.

        By default a check counts toward the denominator when ``ok`` is not
        ``None`` (the inconclusive/skipped state). Pass ``counted`` to force
        it on (a check that always counts) or off (a purely informational
        line that never affects the tally).
        """
        should_count = (ok is not None) if counted is None else counted
        if should_count:
            self.total += 1
            self.done += int(bool(ok))
        self.lines.append(status_line(ok, label, detail))

    def bump(self, ok: bool) -> None:
        """Count a check toward progress without emitting its own line.

        For the rare case where the counted state and the displayed line
        are decoupled (the cached-IP check counts on VM-state
        conclusiveness but prints a separate, more nuanced line).
        """
        self.total += 1
        self.done += int(bool(ok))


def probe_cwd_shared_with_vm(
    cfg: AgentVMConfig, store_cfg_path: Path
) -> ProbeOutcome:
    """Report whether the current working directory is covered by a saved share.

    The status command is often run from inside a project folder, so this probe
    checks whether that exact directory or one of its parents is registered as a
    host attachment for the selected VM.
    """
    reg = load_store(store_cfg_path)
    cwd = Path.cwd()
    try:
        cwd_norm = cwd.resolve()
    except Exception:
        cwd_norm = cwd.absolute()

    matches: list[tuple[Path, AttachmentEntry]] = []
    for att in reg.attachments:
        if att.vm_name != cfg.vm.name or not att.host_path:
            continue
        share_root = Path(att.host_path)
        try:
            share_root = share_root.resolve()
        except Exception:
            share_root = share_root.absolute()
        if cwd_norm == share_root or share_root in cwd_norm.parents:
            matches.append((share_root, att))

    if not matches:
        return ProbeOutcome(
            False, f'{cwd_norm} is not covered by a saved VM share'
        )

    best_match, best_att = max(matches, key=lambda t: len(t[0].parts))
    if cwd_norm == best_match:
        return ProbeOutcome(True, f'current directory is shared: {best_att}')
    rel = cwd_norm.relative_to(best_match)
    return ProbeOutcome(
        True,
        f'parent share covers current directory: {best_match} (+{rel}) ({best_att})',
    )


def probe_runtime_environment() -> ProbeOutcome:
    """Best-effort detection of whether we are on bare metal or in a VM."""
    diag_lines: list[str] = []
    mgr = CommandManager.current()
    if which('systemd-detect-virt'):
        det = mgr.run(
            ['systemd-detect-virt'], sudo=False, check=False, capture=True
        )
        raw = (det.stdout or det.stderr).strip()
        if raw:
            diag_lines.append(f'systemd-detect-virt: {raw} (code={det.code})')
        kind = (det.stdout or '').strip().lower()
        if kind and kind != 'none':
            return ProbeOutcome(
                True,
                f'virtualized guest ({kind})',
                '\n'.join(diag_lines),
            )
        if det.code == 0 and kind == 'none':
            return ProbeOutcome(
                True,
                'host system (no virtualization detected)',
                '\n'.join(diag_lines),
            )
    else:
        diag_lines.append('systemd-detect-virt unavailable')

    cpuinfo_path = Path('/proc/cpuinfo')
    if cpuinfo_path.exists():
        try:
            cpuinfo = cpuinfo_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            cpuinfo = ''
        if cpuinfo:
            has_hypervisor_flag = False
            for line in cpuinfo.splitlines():
                low = line.strip().lower()
                if low.startswith('flags') or low.startswith('features'):
                    if 'hypervisor' in low.split():
                        has_hypervisor_flag = True
                        break
            diag_lines.append(
                f'cpuinfo_hypervisor_flag={"yes" if has_hypervisor_flag else "no"}'
            )
            if has_hypervisor_flag:
                return ProbeOutcome(
                    True,
                    'virtualized guest (cpu hypervisor flag)',
                    '\n'.join(diag_lines),
                )

    dmi_path = Path('/sys/class/dmi/id/product_name')
    if dmi_path.exists():
        try:
            product_name = dmi_path.read_text(
                encoding='utf-8', errors='ignore'
            ).strip()
        except Exception:
            product_name = ''
        if product_name:
            diag_lines.append(f'dmi_product_name={product_name}')
            lower = product_name.lower()
            vm_signals = (
                'kvm',
                'qemu',
                'vmware',
                'virtualbox',
                'bochs',
                'xen',
                'hyper-v',
            )
            if any(sig in lower for sig in vm_signals):
                return ProbeOutcome(
                    True,
                    f'virtualized guest ({product_name})',
                    '\n'.join(diag_lines),
                )

    return ProbeOutcome(
        None,
        'unable to determine host vs guest',
        '\n'.join(diag_lines),
    )


def probe_network(cfg: AgentVMConfig, *, use_sudo: bool) -> ProbeOutcome:
    """Inspect libvirt network state for the configured network name.

    The raw ``net-info`` output is preserved in ``diag`` so detail rendering
    can show it without re-running the probe.
    """
    info = CommandManager.current().run(
        virsh_cmd('net-info', cfg.network.name),
        sudo=use_sudo and virsh_needs_sudo(),
        check=False,
        capture=True,
        summary=f'Inspect libvirt network {cfg.network.name}',
    )
    raw = (info.stdout + '\n' + info.stderr).strip()
    if info.code != 0:
        raw_detail = (info.stderr or info.stdout or '').strip()
        if info.code in {126, 127}:
            return ProbeOutcome(None, 'virsh unavailable on this host', raw)
        detail = raw_detail.lower()
        if 'permission denied' in detail or 'authentication failed' in detail:
            return ProbeOutcome(
                None,
                f'{cfg.network.name} unavailable (run status --sudo for privileged checks)',
                raw,
            )
        if not use_sudo:
            return ProbeOutcome(
                None,
                f'{cfg.network.name} probe inconclusive without sudo ({raw_detail or "unknown error"})',
                raw,
            )
        return ProbeOutcome(False, f'{cfg.network.name} not defined', raw)
    active = False
    autostart = False
    for line in (info.stdout or '').splitlines():
        if ':' not in line:
            continue
        key, val = [x.strip().lower() for x in line.split(':', 1)]
        if key == 'active':
            active = val == 'yes'
        elif key == 'autostart':
            autostart = val == 'yes'
    if active:
        return ProbeOutcome(
            True,
            f'{cfg.network.name} active (autostart={"yes" if autostart else "no"})',
            raw,
        )
    return ProbeOutcome(False, f'{cfg.network.name} defined but inactive', raw)


def probe_firewall(cfg: AgentVMConfig, *, use_sudo: bool) -> ProbeOutcome:
    """Check whether the expected nftables table exists.

    The raw ``nft list table`` output is preserved in ``diag`` so detail
    rendering can show it without re-running the probe.
    """
    if not cfg.firewall.enabled:
        return ProbeOutcome(None, 'disabled in config')
    mgr = CommandManager.current()
    if mgr.privilege_mode == PrivilegeMode.NEVER:
        # nft reads require root; there is no unprivileged fallback.
        return ProbeOutcome(
            None,
            'firewall checks need privileges (privilege_mode = never)',
        )
    if use_sudo and mgr.current_plan() is None:
        with mgr.step(
            'Inspect firewall status',
            why=(
                'Check whether the managed nftables table already exists '
                'before deciding whether firewall repair is needed.'
            ),
            approval_scope=f'firewall-probe:{effective_firewall_table(cfg)}',
        ):
            res = mgr.submit(
                ['nft', 'list', 'table', 'inet', effective_firewall_table(cfg)],
                sudo=True,
                role='read',
                check=False,
                capture=True,
                eager=True,
                summary=f'Inspect nftables table inet {effective_firewall_table(cfg)}',
            ).result()
    else:
        res = mgr.run(
            ['nft', 'list', 'table', 'inet', effective_firewall_table(cfg)],
            sudo=use_sudo,
            check=False,
            capture=True,
            summary=f'Inspect nftables table inet {effective_firewall_table(cfg)}',
        )
    raw = (res.stdout + '\n' + res.stderr).strip()
    if res.code == 0:
        return ProbeOutcome(
            True, f'table inet {effective_firewall_table(cfg)} present', raw
        )
    if res.code in {126, 127}:
        return ProbeOutcome(None, 'nft unavailable on this host', raw)
    detail = (res.stderr or res.stdout or '').strip().lower()
    if 'operation not permitted' in detail or 'permission denied' in detail:
        return ProbeOutcome(
            None,
            'requires privileges (run status --sudo for firewall checks)',
            raw,
        )
    return ProbeOutcome(
        False, f'table inet {effective_firewall_table(cfg)} missing', raw
    )


def _command_output_block(cmd: list[str], stdout: str, stderr: str) -> str:
    """Render one command's output the way detail diagnostics display it."""
    body = clip((stdout + '\n' + stderr).strip() or '(no output)')
    return f'`{" ".join(cmd)}`\n```text\n{body}\n```'


def probe_vm_state(
    cfg: AgentVMConfig, *, use_sudo: bool
) -> tuple[ProbeOutcome, bool | None]:
    """Return VM run-state probe plus explicit domain-defined flag.

    The probe always tries unprivileged libvirt access first and escalates
    to sudo only when ``use_sudo`` is True and the unprivileged read failed
    for a reason other than the domain not existing. Raw dominfo/domstate
    output is preserved in ``diag`` so detail rendering can show it without
    re-running the commands.
    """
    mgr = CommandManager.current()
    dominfo_cmd = virsh_cmd('dominfo', cfg.vm.name)
    sudo_used = False
    # Closed stdin keeps the unprivileged probe from blocking on a polkit
    # password prompt outside the manager's approval flow, and LC_ALL=C
    # keeps error/state string matching locale-independent.
    probe_env = {**os.environ, 'LC_ALL': 'C'}
    dom = mgr.run(
        dominfo_cmd,
        sudo=False,
        check=False,
        capture=True,
        input_text='',
        env=probe_env,
        summary=f'Inspect VM definition {cfg.vm.name}',
    )
    if (
        dom.code not in {0, 126, 127}
        and use_sudo
        and mgr.privilege_mode != PrivilegeMode.NEVER
        and not virsh_domain_missing(dom.stderr)
    ):
        sudo_used = True
        dom = mgr.run(
            dominfo_cmd,
            sudo=True,
            check=False,
            capture=True,
            env=probe_env,
            summary=f'Inspect VM definition {cfg.vm.name}',
        )
    if dom.code != 0:
        diag = _command_output_block(dominfo_cmd, dom.stdout, dom.stderr)
        if dom.code in {126, 127}:
            return (
                ProbeOutcome(None, 'virsh unavailable on this host', diag),
                None,
            )
        raw_detail = (dom.stderr or dom.stdout or '').strip()
        detail = raw_detail.lower()
        if 'permission denied' in detail or 'authentication failed' in detail:
            return (
                ProbeOutcome(
                    None,
                    f'{cfg.vm.name} unavailable (run status --sudo for privileged checks)',
                    diag,
                ),
                None,
            )
        if not use_sudo and not virsh_domain_missing(dom.stderr):
            return (
                ProbeOutcome(
                    None,
                    f'{cfg.vm.name} probe inconclusive without sudo ({raw_detail or "unknown error"})',
                    diag,
                ),
                None,
            )
        return ProbeOutcome(False, f'{cfg.vm.name} not defined', diag), False
    domstate_cmd = virsh_cmd('domstate', cfg.vm.name)
    state_res = mgr.run(
        domstate_cmd,
        sudo=sudo_used,
        check=False,
        capture=True,
        env=probe_env,
        summary=f'Inspect VM runtime state {cfg.vm.name}',
    )
    state = state_res.stdout.strip()
    diag = '\n'.join(
        [
            _command_output_block(dominfo_cmd, dom.stdout, dom.stderr),
            _command_output_block(
                domstate_cmd, state_res.stdout, state_res.stderr
            ),
        ]
    )
    if state_res.code in {126, 127}:
        return ProbeOutcome(None, 'virsh unavailable on this host', diag), None
    return ProbeOutcome(
        'running' in state.lower(), f'{cfg.vm.name} state={state}', diag
    ), True


def probe_ssh_ready(cfg: AgentVMConfig, ip: str) -> ProbeOutcome:
    """Best-effort SSH readiness probe to the guest."""
    try:
        ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    except Exception as ex:
        return ProbeOutcome(False, str(ex), '')
    cmd = [
        'ssh',
        *ssh_base_args(
            ident,
            batch_mode=True,
            connect_timeout=3,
            strict_host_key_checking='no',
            user_known_hosts_file='/dev/null',
        ),
        f'{cfg.vm.user}@{ip}',
        'true',
    ]
    res = CommandManager.current().run(
        cmd, sudo=False, check=False, capture=True, timeout=5
    )
    detail = 'ready' if res.code == 0 else 'not ready'
    diag = (res.stdout + '\n' + res.stderr).strip()
    return ProbeOutcome(res.code == 0, detail, diag)


_TOOL_DISABLED_SPECS = {'', '0', 'false', 'no', 'none', 'off', 'disabled'}


def _guest_tool_enabled(cfg: AgentVMConfig, name: str, *, default: str) -> bool:
    """Return whether status should expect a managed guest tool."""
    tools = getattr(cfg, 'tools', None)
    raw = getattr(tools, name, default)
    if isinstance(raw, bool):
        return raw
    spec = str(raw or '').strip().lower()
    return spec not in _TOOL_DISABLED_SPECS


def _guest_tool_uv_enabled(cfg: AgentVMConfig) -> bool:
    """Return whether status should expect uv in the guest."""
    return _guest_tool_enabled(cfg, 'uv', default='latest')


def _guest_tool_rust_enabled(cfg: AgentVMConfig) -> bool:
    """Return whether status should expect Rust in the guest."""
    return _guest_tool_enabled(cfg, 'rust', default='off')


def probe_provisioned(cfg: AgentVMConfig, ip: str) -> ProbeOutcome:
    """Check whether configured guest packages appear to be installed."""
    if not cfg.provision.enabled:
        return ProbeOutcome(None, 'disabled in config', '')
    try:
        ident = require_ssh_identity(cfg.paths.ssh_identity_file)
    except Exception as ex:
        return ProbeOutcome(False, str(ex), '')
    needed = list(cfg.provision.packages)
    if cfg.provision.install_docker:
        needed.extend(['docker.io', 'docker-compose-v2'])
    checks = ['set -e']
    if needed:
        quoted = ' '.join(shlex.quote(p) for p in needed)
        checks.append(
            f'for p in {quoted}; do '
            "dpkg-query -W -f='${Status}' \"$p\" 2>/dev/null | grep -q 'install ok installed' || exit 10; "
            'done'
        )
    if _guest_tool_uv_enabled(cfg):
        checks.append('command -v uv >/dev/null 2>&1 || exit 11')
    if _guest_tool_rust_enabled(cfg):
        checks.append(
            'command -v rustup >/dev/null 2>&1 || exit 12; '
            'command -v cargo >/dev/null 2>&1 || exit 13; '
            'command -v rustc >/dev/null 2>&1 || exit 14'
        )
    remote = '; '.join(checks)
    cmd = [
        'ssh',
        *ssh_base_args(
            ident,
            batch_mode=True,
            connect_timeout=4,
            strict_host_key_checking='no',
            user_known_hosts_file='/dev/null',
        ),
        f'{cfg.vm.user}@{ip}',
        remote,
    ]
    res = CommandManager.current().run(
        cmd, sudo=False, check=False, capture=True
    )
    if res.code == 0:
        return ProbeOutcome(
            True, 'configured packages/tools appear present', ''
        )
    diag = (res.stdout + '\n' + res.stderr).strip()
    return ProbeOutcome(
        False, 'one or more configured packages/tools missing', diag
    )


def anticipated_status_sudo_commands(
    cfg: AgentVMConfig, *, detail: bool = False
) -> list[list[str]]:
    """Return the privileged probe commands status may run.

    The status flow is partly data-dependent, so this is a best-effort
    preview of the sudo-backed probes that may be executed when
    ``render_status(..., use_sudo=True)`` runs.
    """
    base_img = (
        Path(cfg.paths.base_dir) / cfg.vm.name / 'images' / cfg.image.cache_name
    )
    cmds: list[list[str]] = [
        list(virsh_cmd('net-info', cfg.network.name)),
        ['nft', 'list', 'table', 'inet', effective_firewall_table(cfg)],
        ['test', '-f', str(base_img)],
        list(virsh_cmd('dominfo', cfg.vm.name)),
        list(virsh_cmd('domstate', cfg.vm.name)),
        list(virsh_cmd('dumpxml', cfg.vm.name)),
    ]
    if detail:
        cmds.extend(
            [
                list(virsh_cmd('net-dumpxml', cfg.network.name)),
                ['ls', '-lh', str(base_img)],
                list(virsh_cmd('domiflist', cfg.vm.name)),
                list(virsh_cmd('domifaddr', cfg.vm.name)),
                list(virsh_cmd('net-dhcp-leases', cfg.network.name)),
            ]
        )
    deduped: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for cmd in cmds:
        key = tuple(str(part) for part in cmd)
        if key in seen:
            continue
        seen.add(key)
        deduped.append([str(part) for part in cmd])
    return deduped


def render_status(
    cfg: AgentVMConfig,
    path: Path,
    *,
    detail: bool = False,
    use_sudo: bool = False,
) -> str:
    """Render contextual status for one resolved VM configuration.

    ``use_sudo=False`` intentionally favors safe/non-privileged checks and marks
    sudo-only checks as inconclusive instead of failing hard.
    """
    privilege_mode = CommandManager.current().privilege_mode
    lines: list[str] = [
        '🧭 AgentVM Status',
        f'📄 Config: {path}',
        f'🔐 Privilege mode: {privilege_mode}',
    ]
    lines.append('')
    report = _StatusChecklist(lines)

    missing, missing_opt = check_commands()
    host_ok = len(missing) == 0
    host_detail = (
        'all required commands found'
        if host_ok
        else f'missing: {", ".join(missing)}'
    )
    if missing_opt:
        host_detail += f' (optional missing: {", ".join(missing_opt)})'
    report.check(host_ok, 'Host dependencies', host_detail, counted=True)

    env = probe_runtime_environment()
    report.check(env.ok, 'Runtime environment', env.detail, counted=False)

    net = probe_network(cfg, use_sudo=use_sudo)
    report.check(net.ok, 'Libvirt network', net.detail)

    fw = probe_firewall(cfg, use_sudo=use_sudo)
    report.check(fw.ok, 'Firewall', fw.detail)

    base_img = (
        Path(cfg.paths.base_dir) / cfg.vm.name / 'images' / cfg.image.cache_name
    )
    # TODO(design): once digest-addressable image cache fallback exists,
    # surface both named-path and digest-path resolution in status.
    # A local stat answers definitively when it can (the image tree is often
    # root-only, so EACCES means "ask again with sudo", not "missing").
    img_ok: bool | None = _local_stat_answer(base_img, want_file=True)
    if img_ok is None and use_sudo:
        img_ok = (
            CommandManager.current()
            .run(
                ['test', '-f', str(base_img)],
                sudo=True,
                check=False,
                capture=True,
            )
            .code
            == 0
        )
    if img_ok is not None:
        report.check(img_ok, 'Base image cache', str(base_img))
    else:
        report.check(
            None, 'Base image cache', f'skipped without --sudo ({base_img})'
        )

    vm_out, vm_defined = probe_vm_state(cfg, use_sudo=use_sudo)
    ip = get_ip_cached(cfg)
    cached_ip = ip
    if ip and vm_defined is False:
        ip = None

    ssh = ProbeOutcome(False, 'VM/IP not ready', '')
    if ip:
        ssh = probe_ssh_ready(cfg, ip)

    vm_display = vm_out
    vm_defined_effective = vm_defined
    if vm_out.ok is None and ssh.ok:
        vm_display = ProbeOutcome(
            True,
            f'{cfg.vm.name} reachable over SSH (libvirt state unavailable without --sudo)',
            vm_out.diag,
        )
        vm_defined_effective = True

    report.check(vm_display.ok, 'VM state', vm_display.detail)

    share_mappings: list[tuple[str, str]] = []
    if vm_defined is True:
        share_mappings = vm_share_mappings(cfg, use_sudo=use_sudo)
    if vm_defined is True and share_mappings:
        report.check(
            True,
            'VM shared folders',
            f'{len(share_mappings)} mapping(s) configured (use --detail to inspect host paths)',
            counted=False,
        )
    elif vm_defined_effective is True:
        if vm_defined is None:
            share_detail = 'guest is reachable, but host mappings need privileged VM checks'
        else:
            share_detail = 'none detected'
            if not use_sudo:
                share_detail = 'none detected or unavailable without --sudo'
        report.check(None, 'VM shared folders', share_detail, counted=False)
    elif vm_defined is None:
        report.check(
            None,
            'VM shared folders',
            'unverified without privileged VM checks',
            counted=False,
        )
    else:
        report.check(None, 'VM shared folders', 'VM not defined', counted=False)

    # TODO: we probably want to clean up the detail that is shown here, but do want more than just
    # the path that is shared. We want what mode it is shared in, which VMs if is shared with, what its access is.
    # It could be the case that it is shared with more than 1 VM in different modes, maybe we only print the first
    # and then that there are more, and show them all if --detail is given.
    cwd_share = probe_cwd_shared_with_vm(cfg, path)
    report.check(
        cwd_share.ok,
        'Current directory shared',
        cwd_share.detail,
        counted=False,
    )

    # Config drift check: compare saved VM config against actual libvirt state
    if vm_defined is True:
        reg = load_store(path)
        drift = saved_vm_drift_report(cfg, reg, use_sudo=use_sudo)
        if drift.available:
            if drift.ok is True:
                # TODO: if we don't have sudo or we can only do a partial
                # check, we should inform the user about that here. (e.g.
                # firewall drift)
                report.check(True, 'Config drift', 'in sync')
            else:
                # drift.ok is False here (drift detected)
                report.check(
                    False,
                    'Config drift',
                    f'{len(drift.items)} mismatch(es) detected',
                )
                if detail:
                    report.lines.append('Config Drift Details:')
                    for item in drift.items:
                        report.lines.append(
                            f'  - {item.key}: expected={item.expected}, actual={item.actual}'
                        )
        else:
            # drift.available is False here (unavailable)
            report.check(None, 'Config drift', drift.diag or 'unavailable')
    else:
        report.check(None, 'Config drift', 'VM not defined')

    ip_ok = bool(ip) and (vm_defined_effective is not False)
    if vm_display.ok is not None:
        report.bump(ip_ok)
    if cached_ip and vm_defined is False:
        report.lines.append(
            status_line(
                False,
                'Cached VM IP',
                f'{cached_ip} (stale: VM not defined)',
            )
        )
    elif ip and ssh.ok:
        report.lines.append(status_line(True, 'Cached VM IP', ip))
    elif ip and vm_defined is None:
        report.lines.append(
            status_line(
                None,
                'Cached VM IP',
                f'{ip} (not verified without privileged VM checks)',
            )
        )
    else:
        report.lines.append(
            status_line(bool(ip), 'Cached VM IP', ip or 'no cached IP yet')
        )

    report.check(bool(ssh.ok), 'SSH readiness', ssh.detail, counted=True)

    if ip and ssh.ok:
        prov = probe_provisioned(cfg, ip)
    else:
        prov = ProbeOutcome(
            None,
            'waiting for SSH'
            if cfg.provision.enabled
            else 'disabled in config',
            '',
        )
    report.check(prov.ok, 'Provisioning', prov.detail)

    lines.append('')
    lines.append(f'📊 Progress: {report.done}/{report.total} checks complete')
    if not use_sudo:
        lines.append(
            'ℹ️ Some privileged checks are skipped/limited without --sudo.'
        )

    if detail:
        lines.append('')
        lines.append('🔬 Detailed Diagnostics')
        lines.append('')
        lines.append('Host')
        lines.append(
            f'- required missing: {", ".join(missing) if missing else "(none)"}'
        )
        lines.append(
            f'- optional missing: {", ".join(missing_opt) if missing_opt else "(none)"}'
        )
        lines.append(f'- runtime environment: {env.detail}')
        if env.diag:
            lines.append('- runtime diagnostics:')
            lines.append('```text')
            lines.append(clip(env.diag))
            lines.append('```')
        lines.append('')

        # The summary probes above already captured their raw command output
        # in ProbeOutcome.diag, so detail rendering reuses it instead of
        # re-running the same (often privileged) commands.
        mgr = CommandManager.current()
        net_xml = mgr.run(
            virsh_cmd('net-dumpxml', cfg.network.name),
            sudo=use_sudo and virsh_needs_sudo(),
            check=False,
            capture=True,
        )
        lines.append(f'Network ({cfg.network.name})')
        lines.append('```text')
        lines.append(clip(net.diag or '(no output)'))
        lines.append('```')
        if net_xml.code == 0 and net_xml.stdout.strip():
            lines.append('```xml')
            lines.append(clip(net_xml.stdout, max_lines=80))
            lines.append('```')
        lines.append('')

        lines.append(f'Firewall (inet {effective_firewall_table(cfg)})')
        if cfg.firewall.enabled:
            lines.append('```text')
            lines.append(clip(fw.diag or '(no output)'))
            lines.append('```')
        else:
            lines.append('- disabled in config')
        lines.append('')

        lines.append('Image')
        img_stat = mgr.run(
            ['ls', '-lh', str(base_img)],
            sudo=use_sudo and sudo_allowed(),
            check=False,
            capture=True,
        )
        lines.append('```text')
        lines.append(
            clip(
                (img_stat.stdout + '\n' + img_stat.stderr).strip()
                or '(no output)'
            )
        )
        lines.append('```')
        lines.append('')

        lines.append(f'VM ({cfg.vm.name})')
        if vm_out.diag:
            lines.append(vm_out.diag)
        vm_detail_cmds = [
            virsh_cmd('domiflist', cfg.vm.name),
            virsh_cmd('domifaddr', cfg.vm.name),
        ]
        vm_detail_cmds.append(virsh_cmd('net-dhcp-leases', cfg.network.name))
        for cmd in vm_detail_cmds:
            vm_raw = mgr.run(
                cmd,
                sudo=use_sudo and virsh_needs_sudo(),
                check=False,
                capture=True,
            )
            lines.append(
                _command_output_block(cmd, vm_raw.stdout, vm_raw.stderr)
            )
        lines.append('Filesystem shares')
        if share_mappings:
            for src, tag in share_mappings:
                lines.append(f'- host_src: {src or "(none)"}')
                lines.append(f'  tag: {tag or "(none)"}')
        else:
            lines.append('- none detected')
        lines.append('')

        ip_file = Path(cfg.paths.state_dir) / cfg.vm.name / f'{cfg.vm.name}.ip'
        lines.append('Cache')
        lines.append(f'- ip file: {ip_file}')
        if ip_file.exists():
            lines.append(
                f'- ip value: {ip_file.read_text(encoding="utf-8").strip() or "(empty)"}'
            )
        else:
            lines.append('- ip value: (missing)')
        lines.append('')

        lines.append('SSH probe')
        if ssh.diag:
            lines.append('```text')
            lines.append(clip(ssh.diag))
            lines.append('```')
        else:
            lines.append('- no probe output')
        lines.append('')

        lines.append('Provision probe')
        if prov.diag:
            lines.append('```text')
            lines.append(clip(prov.diag))
            lines.append('```')
        else:
            lines.append('- no probe output')

        cfg_arg = shlex.quote(str(path))
        next_steps: list[str] = []
        if missing:
            next_steps.append(f'aivm host install_deps --config {cfg_arg}')
        if net.ok is False:
            next_steps.append(f'aivm host net create --config {cfg_arg}')
        if cfg.firewall.enabled and fw.ok is not True:
            next_steps.append(f'aivm host fw apply --config {cfg_arg}')
        if (not img_ok) and (vm_out.ok is not True):
            next_steps.append(f'aivm host image_fetch --config {cfg_arg}')
        if not vm_out.ok:
            next_steps.append(f'aivm vm create --config {cfg_arg}')
        if vm_out.ok and not ip:
            next_steps.append(f'aivm vm wait_ip --config {cfg_arg}')
        if vm_out.ok and ip and not ssh.ok:
            next_steps.append(f'aivm vm status --config {cfg_arg}')
        if prov.ok is False:
            next_steps.append(f'aivm vm provision --config {cfg_arg}')
        if next_steps:
            lines.append('')
            lines.append('🛠️ Suggested Next Commands')
            for next_cmd in next_steps:
                lines.append(f'- `{next_cmd}`')
    return '\n'.join(lines)


def render_global_status(store_cfg_path: Path) -> str:
    """Render global status when no single VM context is resolved.

    ``store_cfg_path`` is required rather than defaulted: resolving the store
    here would ignore ``--config`` and describe a file the caller never asked
    about.
    """
    lines: list[str] = ['🧭 AIVM Global Status', '']
    missing, missing_opt = check_commands()
    host_ok = len(missing) == 0
    host_detail = (
        'all required commands found'
        if host_ok
        else f'missing: {", ".join(missing)}'
    )
    if missing_opt:
        host_detail += f' (optional missing: {", ".join(missing_opt)})'
    lines.append(status_line(host_ok, 'Host dependencies', host_detail))
    env = probe_runtime_environment()
    lines.append(status_line(env.ok, 'Runtime environment', env.detail))

    reg = load_store(store_cfg_path)
    lines.append(status_line(True, 'Config store', str(store_cfg_path)))
    lines.append('')
    lines.append('📦 Managed Resources')
    lines.append(f'- VMs: {len(reg.vms)}')
    lines.append(f'- Folder attachments: {len(reg.attachments)}')
    if reg.vms:
        vm_names = ', '.join(sorted(v.name for v in reg.vms[:8]))
        extra = '' if len(reg.vms) <= 8 else f' (+{len(reg.vms) - 8} more)'
        lines.append(f'- VM names: {vm_names}{extra}')

    lines.append('')
    lines.append('ℹ️ No VM context resolved for this directory.')
    lines.append(
        'Use `aivm status --vm <name>`, or run `aivm config init` then '
        '`aivm vm create` to bootstrap a managed VM.'
    )
    return '\n'.join(lines)
