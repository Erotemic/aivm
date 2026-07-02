"""VM create/start orchestration for system-libvirt lifecycle flows."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..privilege import virsh_needs_sudo
from ..runtime import current_libvirt_uri, runtime_is_session, virsh_cmd
from ..util import CmdError, which
from .cloudinit import _write_cloud_init
from .disk import _ensure_disk
from .domain import _destroy_and_undefine_vm, vm_exists
from .images import fetch_image
from .ports import SSH_FORWARD_HOST, allocate_ssh_forward_port

log = logger

def _session_network_arg(ssh_forward_port: int) -> str:
    """Build the ``--network`` value for a session-runtime VM.

    Session mode uses libvirt user-mode networking backed by passt with
    guest SSH forwarded to a localhost port. virt-install 4.1 has no
    first-class suboptions for ``<backend>``/``<portForward>``, so the
    device XML is completed through its per-device xpath overrides.
    """
    return ','.join(
        [
            'type=user',
            'model.type=virtio',
            'xpath1.set=./backend/@type=passt',
            'xpath2.set=./portForward/@proto=tcp',
            f'xpath3.set=./portForward/@address={SSH_FORWARD_HOST}',
            f'xpath4.set=./portForward/range/@start={ssh_forward_port}',
            'xpath5.set=./portForward/range/@to=22',
        ]
    )

def build_virt_install_cmd(
    cfg: AgentVMConfig,
    *,
    vm_disk: Path | str,
    seed_iso: Path | str,
    share_source_dir: str = '',
    share_tag: str = '',
    ssh_forward_port: int | None = None,
) -> list[str]:
    """Build the full virt-install argv for the active runtime.

    The connection URI follows the active runtime; session mode swaps the
    managed-network NIC for passt user-mode networking with an SSH port
    forward (``ssh_forward_port`` is required in that case).
    """
    # Always define VMs with shared memory backing so virtiofs can be
    # attached later without requiring a VM recreate.
    extra = ['--memorybacking', 'source.type=memfd,access.mode=shared']
    source_dir = str(share_source_dir or '').strip()
    tag = str(share_tag or '').strip()
    if source_dir:
        if not tag:
            raise RuntimeError(
                'share_tag is required when share_source_dir is provided.'
            )
        extra += [
            '--filesystem',
            f'source={source_dir},target={tag},driver.type=virtiofs',
        ]

    if runtime_is_session():
        if ssh_forward_port is None:
            raise RuntimeError(
                'ssh_forward_port is required for session-runtime VMs.'
            )
        network_arg = _session_network_arg(ssh_forward_port)
    else:
        network_arg = f'network={cfg.network.name},model=virtio'

    # These VMs are for agent development workflows, not secure-boot or TPM
    # validation. Keep UEFI for modern Ubuntu boot, but make the firmware
    # profile explicit so nested hosts do not inherit heavier defaults that
    # have proven flaky and so serial console output is more useful.
    boot_opts = 'uefi,loader.secure=no,bios.useserial=on'
    cmd = [
        'virt-install',
        # Pin the runtime's daemon explicitly; a bare virt-install would
        # otherwise pick its own default connection.
        '--connect',
        current_libvirt_uri(),
        '--name',
        cfg.vm.name,
        '--memory',
        str(cfg.vm.ram_mb),
        '--vcpus',
        str(cfg.vm.cpus),
        '--cpu',
        'host-passthrough',
        '--import',
        '--os-variant',
        'ubuntu24.04',
        '--disk',
        f'path={vm_disk},format=qcow2,bus=virtio',
        '--disk',
        f'path={seed_iso},device=cdrom',
        '--network',
        network_arg,
        '--graphics',
        'none',
        '--noautoconsole',
        '--rng',
        '/dev/urandom',
        '--tpm',
        'none',
        *extra,
    ]
    # Prefer UEFI consistently, but do not let libvirt auto-enable
    # secure-boot related firmware features for general-purpose
    # development guests.
    cmd += ['--boot', boot_opts]
    return cmd

def _is_missing_uefi_firmware_error(ex: Exception) -> bool:
    text = str(ex).lower()
    return "did not find any uefi binary path for arch 'x86_64'" in text

def _is_missing_virtiofsd_error(ex: Exception) -> bool:
    return 'unable to find a satisfying virtiofsd' in str(ex).lower()

def _is_guest_memory_allocation_error(ex: Exception) -> bool:
    text = str(ex).lower()
    return "cannot set up guest memory 'pc.ram': cannot allocate memory" in text

def _is_missing_kvm_error(ex: Exception) -> bool:
    """Detect creates that fell back to TCG because /dev/kvm is unusable.

    Without KVM, virt-install warns "KVM acceleration not available" and the
    --cpu host-passthrough profile then fails on the qemu (TCG) domain type.
    Seen on session-runtime hosts where the user lacks kvm group access, and
    when a stale session daemon cached capabilities from before access was
    granted.
    """
    text = str(ex).lower()
    return (
        'kvm acceleration not available' in text
        or "cpu mode 'host-passthrough' for x86_64 qemu domain" in text
    )

def _is_passt_crash_error(ex: Exception) -> bool:
    """Detect libvirt failing to start the passt user-networking backend."""
    text = str(ex).lower()
    return 'passt' in text and (
        'unexpected fatal signal' in text
        or 'died unexpectedly' in text
        or 'pid file open: permission denied' in text
    )

def _passt_crash_failure_message() -> str:
    return (
        'VM creation failed because the passt user-networking backend '
        'could not start when libvirt launched it.\n'
        'On Ubuntu 24.04 this is a known packaging bug: the '
        'usr.bin.passt AppArmor profile denies passt mmap of its own '
        'binary (SIGSEGV under libvirt; works standalone) and denies its '
        'pid file under /run/user/.\n'
        'Fix: inside the profile in /etc/apparmor.d/usr.bin.passt add\n'
        '  /usr/bin/passt{,.avx2} mr,\n'
        '  owner /run/user/[0-9]*/libvirt/qemu/run/passt/* rw,\n'
        'then reload it '
        '(`sudo apparmor_parser -r /etc/apparmor.d/usr.bin.passt`), or '
        'update to a passt/apparmor package that includes the fix.'
    )

def _missing_kvm_failure_message() -> str:
    return (
        'VM creation failed because KVM hardware acceleration is not '
        'available to this user.\n'
        'Check /dev/kvm access (usually kvm group membership): run '
        '`aivm host rootless check`, or `sudo usermod -aG kvm $USER` and '
        'log out/in.\n'
        'If access was granted after libvirt started, restart the per-user '
        'daemon so it re-probes capabilities: `pkill -u $USER libvirtd; '
        'rm -rf ~/.cache/libvirt/qemu/capabilities`.'
    )

def _virtiofsd_failure_message(source_dir: str) -> str:
    return (
        'VM creation failed because virtiofsd is not available on this host, '
        f'but a shared folder was requested (source={source_dir}).\n'
        'Install virtiofs support on the host (e.g. package providing '
        '`virtiofsd`, often `qemu-system-common` or `virtiofsd`), or disable '
        'folder sharing for this run.'
    )

def _memory_allocation_failure_message(cfg: AgentVMConfig) -> str:
    return (
        'VM creation failed because QEMU could not allocate guest RAM on the host.\n'
        f'Requested resources: ram_mb={cfg.vm.ram_mb}, cpus={cfg.vm.cpus}.\n'
        'This is common on nested/low-memory hosts. Try lowering VM resources '
        '(for example ram_mb=2048 and cpus=2) and retry.'
    )

def _failed_command_name(ex: Exception) -> str | None:
    if isinstance(ex, FileNotFoundError):
        name = ex.filename
        return str(name) if name else None
    if not isinstance(ex, CmdError):
        return None
    cmd = ex.cmd
    if isinstance(cmd, str):
        parts = cmd.split()
    else:
        parts = [str(p) for p in cmd]
    if not parts:
        return None
    if parts[0] == 'sudo' and len(parts) > 1:
        return parts[1]
    return parts[0]

def _is_missing_command_error(ex: Exception) -> bool:
    if isinstance(ex, FileNotFoundError):
        return True
    if not isinstance(ex, CmdError):
        return False
    if ex.result.code == 127:
        return True
    text = f'{ex.result.stderr}\n{ex.result.stdout}'.lower()
    return 'command not found' in text

def create_or_start_vm(
    cfg: AgentVMConfig,
    *,
    dry_run: bool = False,
    recreate: bool = False,
    share_source_dir: str = '',
    share_tag: str = '',
) -> None:
    """Ensure a VM exists and is running, creating/redefining when needed.

    Behavior summary:
    * existing running VM: no-op
    * existing stopped VM: start
    * recreate requested: destroy/undefine then define again
    * missing VM: create from base image + cloud-init artifacts
    """
    log.trace(
        'create_or_start_vm vm={} dry_run={} recreate={} share_source_dir={} share_tag={}',
        cfg.vm.name,
        dry_run,
        recreate,
        share_source_dir or '(none)',
        share_tag or '(none)',
    )
    log.debug('Creating or starting VM {}', cfg.vm.name)
    cfg = cfg.expanded_paths()
    mgr = CommandManager.current()

    with mgr.intent(
        f'Ensure VM {cfg.vm.name} exists and is running',
        why=(
            'Reuse an existing VM when possible, otherwise create or '
            'recreate the libvirt domain and boot it for the requested task.'
        ),
        role='modify',
    ):
        if vm_exists(cfg, dry_run=dry_run):
            if not recreate:
                with mgr.step(
                    'Ensure existing VM is running',
                    why=(
                        'Inspect the current domain state and start, resume, '
                        'or no-op the existing VM based on its current state.'
                    ),
                    approval_scope=f'vm-start:{cfg.vm.name}',
                ):
                    st = (
                        mgr.submit(
                            virsh_cmd('domstate', cfg.vm.name),
                            sudo=virsh_needs_sudo(),
                            role='read',
                            check=False,
                            capture=True,
                            eager=True,
                            summary=f'Inspect runtime state for VM {cfg.vm.name}',
                        )
                        .stdout.strip()
                        .lower()
                    )
                    if 'running' in st or 'idle' in st or 'blocked' in st:
                        log.info(
                            'VM already running: {} (state={})',
                            cfg.vm.name,
                            st,
                        )
                        return
                    if 'paused' in st or 'pmsuspended' in st:
                        if dry_run:
                            log.info('DRYRUN: virsh resume {}', cfg.vm.name)
                            return
                        log.info(
                            'VM {} is {}; resuming instead of starting',
                            cfg.vm.name,
                            st,
                        )
                        mgr.submit(
                            virsh_cmd('resume', cfg.vm.name),
                            sudo=virsh_needs_sudo(),
                            role='modify',
                            check=True,
                            capture=True,
                            summary=f'Resume {st} VM {cfg.vm.name}',
                        )
                        log.info('VM resumed: {}', cfg.vm.name)
                        return
                    if 'in shutdown' in st or 'shutting down' in st:
                        raise RuntimeError(
                            f'VM {cfg.vm.name!r} is currently shutting down '
                            f'(state={st!r}). Wait for it to finish, or run '
                            f'`aivm vm destroy {cfg.vm.name}` to force it off, '
                            f'then retry.'
                        )
                    if 'shut off' in st or 'crashed' in st or st == '':
                        if dry_run:
                            log.info('DRYRUN: virsh start {}', cfg.vm.name)
                            return
                        mgr.submit(
                            virsh_cmd('start', cfg.vm.name),
                            sudo=virsh_needs_sudo(),
                            role='modify',
                            check=True,
                            capture=True,
                            summary=f'Start existing VM {cfg.vm.name}',
                        )
                        log.info('VM started: {}', cfg.vm.name)
                        return
                    raise RuntimeError(
                        f'VM {cfg.vm.name!r} is in unexpected state '
                        f'{st!r}; refusing to start or resume. Inspect with '
                        f'`virsh domstate {cfg.vm.name}` and recover manually.'
                    )
            if dry_run:
                log.info('DRYRUN: virsh destroy/undefine {}', cfg.vm.name)
            else:
                _destroy_and_undefine_vm(cfg.vm.name)

        base_img = fetch_image(cfg, dry_run=dry_run)
        try:
            ci = _write_cloud_init(cfg, dry_run=dry_run)
        except Exception as ex:
            if _is_missing_command_error(ex):
                missing = _failed_command_name(ex)
                hint = (
                    f'Missing required host command: `{missing}`. '
                    if missing
                    else ''
                )
                raise RuntimeError(
                    f'Failed to build cloud-init artifacts for VM `{cfg.vm.name}`. '
                    f'{hint}Run `aivm host install_deps` and retry.'
                ) from ex
            raise

        vm_disk = _ensure_disk(
            cfg, base_img, dry_run=dry_run, recreate=recreate
        )
        seed_iso = ci['seed_iso']

        source_dir = str(share_source_dir or '').strip()
        ssh_forward_port: int | None = None
        if runtime_is_session():
            if which('passt') is None:
                raise RuntimeError(
                    'Session-runtime VMs need `passt` for user-mode '
                    'networking, but it is not installed. Install the '
                    '`passt` package (or run `aivm host rootless check` '
                    'for the full readiness report) and retry.'
                )
            ssh_forward_port = allocate_ssh_forward_port(cfg, dry_run=dry_run)
        cmd = build_virt_install_cmd(
            cfg,
            vm_disk=vm_disk,
            seed_iso=seed_iso,
            share_source_dir=share_source_dir,
            share_tag=share_tag,
            ssh_forward_port=ssh_forward_port,
        )
        if dry_run:
            log.info('DRYRUN: {}', ' '.join(cmd))
            return
        try:
            first = CommandManager.current().run(
                cmd,
                sudo=virsh_needs_sudo(),
                role='modify',
                check=False,
                capture=True,
            )
        except CmdError as ex:
            # Some call sites/tests may still raise even when check=False.
            first = ex.result
        if first.code != 0:
            err = CmdError(cmd, first)
            if source_dir and _is_missing_virtiofsd_error(err):
                raise RuntimeError(
                    _virtiofsd_failure_message(source_dir)
                ) from err
            if _is_guest_memory_allocation_error(err):
                raise RuntimeError(
                    _memory_allocation_failure_message(cfg)
                ) from err
            if _is_missing_kvm_error(err):
                raise RuntimeError(_missing_kvm_failure_message()) from err
            if _is_passt_crash_error(err):
                raise RuntimeError(_passt_crash_failure_message()) from err
            if _is_missing_uefi_firmware_error(err):
                log.warning(
                    'UEFI firmware not available on host. Retrying VM create with non-UEFI boot.'
                )
                cmd_no_uefi = list(cmd)
                try:
                    idx = cmd_no_uefi.index('--boot')
                    del cmd_no_uefi[idx : idx + 2]
                except ValueError:
                    pass
                try:
                    CommandManager.current().run(
                        cmd_no_uefi, sudo=virsh_needs_sudo(), check=True, capture=True
                    )
                except CmdError as ex2:
                    if source_dir and _is_missing_virtiofsd_error(ex2):
                        raise RuntimeError(
                            _virtiofsd_failure_message(source_dir)
                        ) from ex2
                    if _is_guest_memory_allocation_error(ex2):
                        raise RuntimeError(
                            _memory_allocation_failure_message(cfg)
                        ) from ex2
                    raise
            else:
                raise err
        log.info('VM created: {}', cfg.vm.name)
