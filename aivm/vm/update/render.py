"""Plan rendering for VM update operations."""

from __future__ import annotations

from ...commands import CommandManager
from ...config import AgentVMConfig
from ...runtime import pin_locale, virsh_cmd
from ..tpm import TPM_XML
from .models import VMUpdateDrift
from .util import _bytes_to_gib


def _preview_vm_update(cfg: AgentVMConfig) -> None:
    """Preview inspection without inventing results from skipped commands."""
    print(f'DRYRUN: would inspect VM {cfg.vm.name} and reconcile config drift.')
    print('Live drift is unknown: dry-run does not execute host or guest probes.')
    mgr = CommandManager.current()
    # The real detector tries these without sudo, then retries if required.
    for verb in ('dominfo', 'domstate', 'dumpxml'):
        mgr.request(
            pin_locale(virsh_cmd(verb, cfg.vm.name)), role='read',
            summary=f'Inspect {cfg.vm.name} ({verb}; retry with sudo if needed)',
        ).preview()
    print(f'DRYRUN: desired hardware: {cfg.vm.cpus} CPUs, '
          f'{cfg.vm.ram_mb} MiB RAM, {cfg.vm.disk_gb} GiB disk; '
          'would inspect the disk path/size before changing hardware (no disk shrink).')
    print('DRYRUN: would check virtiofs configuration, guest fd guard when running, '
          'and the managed firewall; apply only detected drift.')
    if cfg.vm.tpm == 'emulator':
        for args in (('dumpxml', cfg.vm.name, '--inactive'), ('domcapabilities',)):
            mgr.request(
                virsh_cmd(*args), role='read',
                summary='Inspect persistent TPM / host capabilities (sudo if required)',
            ).preview()
        print(f'DRYRUN: would add {TPM_XML} only if absent, after verifying a '
              'shut-off VM, no managed save, and advertised emulator TPM 2.0 / '
              'tpm-crb support (if version reporting is absent, verify host '
              'TPM 2.0 with swtpm socket --tpm2 --print-capabilities). '
              'Would preserve UUID, disks and other devices, '
              'then redefine with virsh define --validate.')
    print('DRYRUN: restart requirements depend on detected drift and VM power state; '
          'no changes or config writes performed.')


def _print_vm_update_plan(cfg: AgentVMConfig, drift: VMUpdateDrift) -> None:
    print(f'Planned VM update for {cfg.vm.name}:')
    if drift.tpm_add:
        print('  - TPM: add emulator TPM 2.0 (VM must be shut off)')
    if drift.cpus is not None:
        cur, want = drift.cpus
        print(f'  - cpus: {cur} -> {want}')
    if drift.ram_mb is not None:
        cur, want = drift.ram_mb
        print(f'  - ram_mb: {cur} -> {want}')
    if drift.disk_bytes is not None:
        cur, want = drift.disk_bytes
        print(
            f'  - disk_gb: {_bytes_to_gib(cur):.2f} GiB -> {_bytes_to_gib(want):.2f} GiB ({drift.disk_path})'
        )
    if drift.virtiofs_binary:
        mode_label = drift.virtiofsd_mode or 'disabled'
        print(
            f'  - virtiofsd binary path (inode-file-handles={mode_label}): '
            f'{len(drift.virtiofs_binary)} <filesystem> device(s) to update'
        )
        for d in drift.virtiofs_binary:
            cur_path = d.current or '(default)'
            new_path = d.desired or '(default)'
            print(f'      tag={d.tag}: {cur_path} -> {new_path}')
    if drift.fd_guard is not None:
        print(
            f'  - virtiofs fd guard (guest): {drift.fd_guard.action} '
            f'({drift.fd_guard.reason})'
        )
    if drift.firewall is not None:
        if drift.firewall.action == 'remove':
            print(
                '  - firewall: remove managed table '
                f'({drift.firewall.reason})'
            )
        else:
            current = (
                '(missing)'
                if drift.firewall.current_tcp_ports is None
                else repr(drift.firewall.current_tcp_ports)
            )
            print(
                '  - firewall: reconcile managed policy '
                f'(tcp ports {current} -> {drift.firewall.desired_tcp_ports}; '
                f'{drift.firewall.reason})'
            )
