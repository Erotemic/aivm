"""VM create/start orchestration for system-libvirt lifecycle flows."""

from __future__ import annotations

from loguru import logger

from ..commands import CommandManager
from ..privilege import virsh_needs_sudo
from ..runtime import virsh_system_cmd
from ..config import AgentVMConfig
from ..util import CmdError
from .cloudinit import _write_cloud_init
from .disk import _ensure_disk
from .domain import _destroy_and_undefine_vm, vm_exists
from .images import fetch_image

log = logger

def _is_missing_uefi_firmware_error(ex: Exception) -> bool:
    text = str(ex).lower()
    return "did not find any uefi binary path for arch 'x86_64'" in text

def _is_missing_virtiofsd_error(ex: Exception) -> bool:
    return 'unable to find a satisfying virtiofsd' in str(ex).lower()

def _is_guest_memory_allocation_error(ex: Exception) -> bool:
    text = str(ex).lower()
    return "cannot set up guest memory 'pc.ram': cannot allocate memory" in text

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
                            virsh_system_cmd('domstate', cfg.vm.name),
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
                            virsh_system_cmd('resume', cfg.vm.name),
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
                            virsh_system_cmd('start', cfg.vm.name),
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

        # Always define VMs with shared memory backing so virtiofs can be attached
        # later without requiring a VM recreate.
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

        # These VMs are for agent development workflows, not secure-boot or TPM
        # validation. Keep UEFI for modern Ubuntu boot, but make the firmware
        # profile explicit so nested hosts do not inherit heavier defaults that
        # have proven flaky and so serial console output is more useful.
        boot_opts = 'uefi,loader.secure=no,bios.useserial=on'
        cmd = [
            'virt-install',
            # Pin the system daemon; unprivileged virt-install would
            # otherwise default to the per-user qemu:///session.
            '--connect',
            'qemu:///system',
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
            f'network={cfg.network.name},model=virtio',
            '--graphics',
            'none',
            '--noautoconsole',
            '--rng',
            '/dev/urandom',
            '--tpm',
            'none',
            *extra,
        ]
        # Prefer UEFI consistently, but do not let libvirt auto-enable secure-boot
        # related firmware features for general-purpose development guests.
        cmd += ['--boot', boot_opts]
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
