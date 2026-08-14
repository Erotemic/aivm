"""VM attachment CLI command implementations.

This module owns both the kwconf CLI surface for ``aivm vm attach``,
``aivm vm detach``, and the persistent-host-replay commands, and the
business logic those commands invoke. kwconf classes are the
programmatic entry point as well — call ``VMAttachCLI.main(argv=False,
host_src=..., yes=True, ...)`` from Python instead of going through a
separate Request/Result layer.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Literal

import kwconf
from loguru import logger as log

from ..attachments.guest import _ensure_attachment_available_in_guest
from ..attachments.ownership import (
    attachment_owner_for_context,
    require_attachment_mutation_permission,
)
from ..attachments.persistent import (
    _cleanup_persistent_host_replay_artifacts,
    _install_persistent_host_bind_replay,
    _persistent_attachment_records_for_vm,
    _prepare_persistent_attachment_host_and_vm,
    _reconcile_persistent_attachments_in_guest,
    _reconcile_persistent_host_binds,
    _sync_persistent_attachment_manifest_on_host,
    _sync_persistent_host_replay_manifest,
)
from ..attachments.persistent.identity import (
    PersistentSourceIdentityRefresh,
    refresh_persistent_source_identities,
)
from ..attachments.resolve import (
    ATTACHMENT_ACCESS_RO,
    ATTACHMENT_MODE_DIRECT_VIRTIOFS,
    ATTACHMENT_MODE_PERSISTENT,
    ATTACHMENT_MODE_SHARED_ROOT,
    _normalize_attachment_access,
    _normalize_attachment_mode,
    _resolve_attachment,
    logical_absolute_path,
)
from ..attachments.safety import (
    AttachmentSafetyReport,
    attachment_safety_preflight,
    warn_shared_home_attachment,
)
from ..attachments.session import (
    _record_attachment,
    _resolve_ip_for_ssh_ops,
)
from ..attachments.shared_root import (
    _detach_shared_root_guest_bind,
    _detach_shared_root_host_bind,
    _ensure_shared_root_host_bind,
    _ensure_shared_root_vm_mapping,
)
from ..commands import CommandManager, SudoUnavailableError
from ..config import AgentVMConfig
from ..config_scopes import ResolvedVMContext
from ..config_store import (
    AttachmentEntry,
    Store,
    find_attachment_for_vm,
    find_attachments_for_vm_path,
    load_store,
    remove_attachment,
    update_store,
)
from ..errors import AIVMError, CommandControlError
from ..machine_store import (
    MachineResourceLockScope,
    current_machine_group_gid,
    machine_resource_locks,
)
from ..scoped_store import resolve_store_scope
from ..services import (
    load_cfg_with_path,
    load_vm_context_with_path,
    maybe_offer_create_ssh_identity,
    record_vm,
    resolve_context_for_code,
)
from ..status import probe_vm_state
from ..vm import (
    attach_vm_share,
    detach_vm_share,
    refresh_cloud_init_seed_for_next_boot,
    vm_share_mappings,
)
from ..vm.drift import attachment_has_mapping as drift_attachment_has_mapping
from ..vm.share import ResolvedAttachment
from ..vm.share import (
    align_attachment_tag_with_mappings as drift_align_attachment_tag_with_mappings,
)
from ._common import _BaseCommand


@dataclass(frozen=True)
class VMAttachRequest:
    """Inputs for attaching/registering a host directory to a VM."""

    config_opt: str | None
    vm_opt: str
    host_src: Path
    guest_dst: str = ''
    mode: str = ''
    access: str = ''
    dry_run: bool = False
    yes: bool = False
    admin_override: bool = False
    owner_principal: str = ''


@dataclass(frozen=True)
class VMDetachRequest:
    """Inputs for detaching/unregistering a host directory from a VM."""

    config_opt: str | None
    vm_opt: str
    host_src: Path
    dry_run: bool = False
    yes: bool = False
    admin_override: bool = False
    owner_principal: str = ''


@dataclass(frozen=True)
class VMPersistentHostReplayRequest:
    """Inputs for replaying host-side persistent bind mounts."""

    config_opt: str | None
    vm_opt: str
    dry_run: bool = False
    trust_current_paths: bool = False
    admin_override: bool = False


@dataclass(frozen=True)
class VMInstallPersistentHostReplayServiceRequest:
    """Inputs for installing the persistent host replay systemd service."""

    config_opt: str | None
    vm_opt: str
    dry_run: bool = False


def _validate_host_directory(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        raise AIVMError(f'host_src must be an existing directory: {path}')


def _resolve_attach_context(
    request: VMAttachRequest, host_src: Path
) -> tuple[ResolvedVMContext, Path]:
    """Resolve the target VM and invoking principal for an attach request."""
    if request.config_opt:
        return load_vm_context_with_path(
            request.config_opt, vm_opt=request.vm_opt, host_src=host_src
        )
    if request.vm_opt:
        return load_vm_context_with_path(
            None, vm_opt=request.vm_opt, host_src=host_src
        )
    return resolve_context_for_code(
        config_opt=None,
        vm_opt='',
        host_src=host_src,
    )


def _print_attach_refusal(
    report: AttachmentSafetyReport, host_src: Path, vm_name: str
) -> None:
    """Explain why the safety preflight declined the attachment."""
    if report.sensitive_hits:
        print(
            f'Aborted: declined to attach sensitive path {host_src} to VM {vm_name}.'
        )
    else:
        print(
            f'Aborted: declined to add overlapping attachment {host_src} to VM {vm_name}.'
        )


def _ensure_attachment_in_vm_definition(
    cfg: AgentVMConfig,
    attachment: ResolvedAttachment,
    host_src: Path,
    *,
    yes: bool,
) -> tuple[ResolvedAttachment, bool, bool]:
    """Expose the attachment in the VM definition when the VM exists.

    For ``shared`` mode this attaches the virtiofs mapping if it is missing.
    For ``shared-root``/``persistent`` modes on a stopped VM it prepares the
    host-side export and root mapping now so the next boot has it; when the
    VM is running that work happens during guest reconciliation instead.

    Returns the (possibly tag-realigned) attachment plus
    ``(vm_defined, vm_running)``.
    """
    # probe_vm_state escalates to sudo internally only when the unprivileged
    # read is inconclusive, so one call covers both cases.
    vm_out, vm_defined_probe = probe_vm_state(cfg, use_sudo=True)
    vm_defined = bool(vm_defined_probe)
    if not vm_defined:
        return attachment, False, False
    vm_running = vm_out.ok is True
    if attachment.mode == ATTACHMENT_MODE_DIRECT_VIRTIOFS:
        mappings = vm_share_mappings(cfg)
        attachment = drift_align_attachment_tag_with_mappings(
            attachment, host_src, mappings
        )
        if not drift_attachment_has_mapping(cfg, attachment, mappings):
            attach_vm_share(
                cfg,
                attachment.source_dir,
                attachment.tag,
                dry_run=False,
                read_only=(attachment.access == ATTACHMENT_ACCESS_RO),
            )
    elif (
        attachment.mode
        in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}
        and not vm_running
    ):
        mgr = CommandManager.current()
        with mgr.intent(
            f'Attach and reconcile {attachment.mode.value!r} mapping',
            why='Ensure the requested host folder is exposed to the VM before the next guest session uses it.',
            role='modify',
        ):
            if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
                _prepare_persistent_attachment_host_and_vm(
                    cfg,
                    attachment,
                    dry_run=False,
                    vm_running=False,
                )
            else:
                _ensure_shared_root_host_bind(
                    cfg,
                    attachment,
                    yes=yes,
                    dry_run=False,
                )
                _ensure_shared_root_vm_mapping(
                    cfg,
                    yes=yes,
                    dry_run=False,
                    vm_running=False,
                )
    return attachment, vm_defined, vm_running


def _reconcile_attachment_in_running_guest(
    cfg: AgentVMConfig,
    cfg_path: Path,
    attachment: ResolvedAttachment,
    host_src: Path,
    *,
    yes: bool,
) -> None:
    """Reconcile a newly recorded attachment inside the running guest."""
    if maybe_offer_create_ssh_identity(
        cfg,
        yes=yes,
        prompt_reason=(
            'Generate a dedicated SSH keypair so aivm can reconcile '
            'the running VM guest attachment state.'
        ),
    ):
        record_vm(
            cfg,
            cfg_path,
            reason=(
                f'Persist newly generated SSH identity paths for VM '
                f'{cfg.vm.name} before guest attachment reconciliation.'
            ),
        )
    log.info(
        'VM {} is running; reconciling attachment in guest: {} (mode={} access={})',
        cfg.vm.name,
        attachment.guest_dst,
        attachment.mode,
        attachment.access,
    )
    ip = _resolve_ip_for_ssh_ops(
        cfg,
        yes=yes,
        purpose='Query VM networking state before reconciling attached folder.',
    )
    # Look up the persisted record (matched by resolved host_path) so
    # any aliases recorded earlier are also surfaced as guest symlinks.
    reg_for_aliases = load_store(cfg_path)
    saved = find_attachment_for_vm(
        reg_for_aliases,
        host_src,
        cfg.vm.name,
        owner_principal_id=(attachment.owner_principal_id or None),
    )
    aliases = list(saved.host_lexical_paths) if saved else []
    _ensure_attachment_available_in_guest(
        cfg,
        host_src,
        attachment,
        ip,
        yes=yes,
        dry_run=False,
        ensure_shared_root_host_side=(
            attachment.mode
            in {ATTACHMENT_MODE_SHARED_ROOT, ATTACHMENT_MODE_PERSISTENT}
        ),
        mirror_home=bool(cfg.vm.mirror_shared_home_folders),
        host_lexical_paths=aliases,
    )
    if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
        _reconcile_persistent_attachments_in_guest(
            cfg,
            cfg_path,
            ip,
            dry_run=False,
        )


def _print_attach_result(
    cfg: AgentVMConfig,
    cfg_path: Path,
    reg_path: Path,
    attachment: ResolvedAttachment,
    host_src: Path,
    *,
    vm_defined: bool,
    vm_running: bool,
) -> None:
    """Summarize what the attach accomplished and what happens next."""
    mounted_modes = {
        ATTACHMENT_MODE_PERSISTENT,
        ATTACHMENT_MODE_DIRECT_VIRTIOFS,
        ATTACHMENT_MODE_SHARED_ROOT,
    }
    print(
        f'Attached {host_src} to VM {cfg.vm.name} ({attachment.mode} mode, access={attachment.access})'
    )
    if vm_running and attachment.mode in mounted_modes:
        print(f'Mounted in running VM at {attachment.guest_dst}')
    elif vm_running:
        print(f'Guest clone ready at {attachment.guest_dst}')
    elif vm_defined:
        if attachment.mode in mounted_modes:
            print(
                f'VM {cfg.vm.name} is not running; share will mount when VM is running and attach/ssh/code is used.'
            )
        else:
            print(
                f'VM {cfg.vm.name} is not running; guest clone will be created when VM is running and attach/ssh/code is used.'
            )
    print(f'Updated config store: {cfg_path}')
    print(f'Updated attachments: {reg_path}')


#: Modes whose host-side setup stages the folder under the VM's export root
#: with a bind mount, which only root can create. ``shared`` maps the folder
#: to the guest directly and ``git`` never shares it at all, so neither needs
#: any host privilege.
_ROOT_REQUIRING_ATTACH_MODES = frozenset(
    {ATTACHMENT_MODE_PERSISTENT, ATTACHMENT_MODE_SHARED_ROOT}
)


@contextmanager
def _attach_privilege_guidance(
    mode: str, owner_principal_id: str
) -> Iterator[None]:
    """Name both ways out when a mode's host setup needs unavailable root.

    A host account without sudo -- the normal state of every ordinary user
    on a shared workstation -- can attach in ``shared`` mode all day and
    cannot create a ``persistent`` one at all. On its own the failure is a
    bare "could not obtain sudo credentials", which says nothing about
    which knob to turn.

    Attached to the failure rather than probed up front, deliberately: a
    preflight would have to guess at sudo capability, and that guess costs
    a ``sudo -n true`` on every attach while still being wrong on a host
    with a NOPASSWD rule scoped to one command. Here there is no guess ---
    escalation has already been shown to be impossible.
    """
    try:
        yield
    except SudoUnavailableError as ex:
        if mode not in _ROOT_REQUIRING_ATTACH_MODES:
            raise
        identity = owner_principal_id or '<your-access-identity>'
        raise AIVMError(
            f'{ex}\n'
            f"\nAttachment mode '{mode}' stages this folder under the VM "
            'export root with a host bind mount, and only root can create '
            'one. Two ways forward:\n'
            f'  * attach with `--mode {ATTACHMENT_MODE_DIRECT_VIRTIOFS}`, which maps '
            'the folder straight into the guest over virtiofs and needs no '
            'host privileges;\n'
            '  * or ask a host administrator to declare it for you:\n'
            f'      sudo aivm vm attach <path> --owner_principal {identity} '
            '--admin_override'
        ) from ex


def run_vm_attach(request: VMAttachRequest) -> int:
    """Attach/register a host directory to an existing managed VM.

    Phases: resolve the target config and attachment, run the safety
    preflight, expose the mapping in the VM definition, record the
    attachment, then reconcile the running guest if there is one.
    """
    host_src = logical_absolute_path(request.host_src)
    _validate_host_directory(host_src)
    context, cfg_path = _resolve_attach_context(request, host_src)
    cfg = context.effective_cfg
    owner_principal_id = attachment_owner_for_context(context, cfg_path)
    attachment = _resolve_attachment(
        cfg,
        cfg_path,
        host_src,
        request.guest_dst,
        request.mode,
        request.access,
        owner_principal_id=owner_principal_id,
        administrative_override=bool(request.admin_override),
        administrative_owner_principal_id=request.owner_principal,
    )

    existing_reg = load_store(cfg_path)
    warn_shared_home_attachment(
        host_src,
        shared_vm=(
            sum(
                1
                for item in existing_reg.principals
                if item.vm_name == cfg.vm.name
            )
            > 1
        ),
    )
    ok, report = attachment_safety_preflight(
        host_src,
        existing_attachments=existing_reg.attachments,
        vm_name=cfg.vm.name,
        yes=bool(request.yes),
        dry_run=bool(request.dry_run),
    )
    if request.dry_run:
        print(
            f'DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {attachment.guest_dst} ({attachment.mode} mode, access={attachment.access})'
        )
        return 0
    if not ok:
        _print_attach_refusal(report, host_src, cfg.vm.name)
        return 2

    record_vm(
        cfg,
        cfg_path,
        reason=(
            f'Persist resolved VM/network metadata before attaching '
            f'{host_src} to {cfg.vm.name}.'
        ),
    )
    with _attach_privilege_guidance(
        attachment.mode, attachment.owner_principal_id
    ):
        attachment, vm_defined, vm_running = (
            _ensure_attachment_in_vm_definition(
                cfg, attachment, host_src, yes=bool(request.yes)
            )
        )
        reg_path = _record_attachment(
            cfg,
            cfg_path,
            host_src=host_src,
            mode=attachment.mode,
            access=attachment.access,
            guest_dst=attachment.guest_dst,
            tag=attachment.tag,
            owner_principal_id=attachment.owner_principal_id,
        )
        if attachment.mode == ATTACHMENT_MODE_PERSISTENT:
            _sync_persistent_attachment_manifest_on_host(
                cfg,
                cfg_path,
                dry_run=False,
            )
            _sync_persistent_host_replay_manifest(cfg, cfg_path, dry_run=False)
            _reconcile_persistent_host_binds(
                cfg, cfg_path, dry_run=False, vm_running=vm_running
            )
            if vm_defined and not vm_running:
                refresh_cloud_init_seed_for_next_boot(cfg, dry_run=False)
    if vm_running:
        _reconcile_attachment_in_running_guest(
            cfg, cfg_path, attachment, host_src, yes=bool(request.yes)
        )
    _print_attach_result(
        cfg,
        cfg_path,
        reg_path,
        attachment,
        host_src,
        vm_defined=vm_defined,
        vm_running=vm_running,
    )
    return 0


def _detach_shared_root_attachment(
    cfg: AgentVMConfig,
    resolved: ResolvedAttachment,
    *,
    vm_running: bool,
    yes: bool,
) -> tuple[bool, bool, bool]:
    """Tear down guest and host bind mounts for a shared-root attachment.

    Both halves are attempted independently; failures are logged rather than
    raised so a partial detach keeps the store record and can be retried.

    Returns ``(guest_bind_detached, host_bind_detached, failed)``.
    """
    detached_guest = False
    detached_host = False
    failed = False
    if vm_running:
        try:
            ip = _resolve_ip_for_ssh_ops(
                cfg,
                yes=yes,
                purpose='Query VM networking state before detaching shared-root guest mount.',
            )
            _detach_shared_root_guest_bind(
                cfg,
                ip,
                resolved,
                dry_run=False,
            )
            detached_guest = True
        # A declined prompt is the user answering the question, not a step
        # that went wrong. Best-effort recovery must not continue past it.
        except CommandControlError:
            raise
        except Exception as ex:
            failed = True
            log.warning(
                'Could not detach shared-root guest bind mount for VM {} at {}: {}',
                cfg.vm.name,
                resolved.guest_dst,
                ex,
            )
    if resolved.tag:
        try:
            _detach_shared_root_host_bind(
                cfg,
                resolved,
                yes=yes,
                dry_run=False,
            )
            detached_host = True
        except CommandControlError:
            raise
        except Exception as ex:
            failed = True
            log.warning(
                'Could not detach shared-root host bind mount for VM {} source={} guest_dst={} token={}: {}',
                cfg.vm.name,
                resolved.source_dir,
                resolved.guest_dst,
                resolved.tag,
                ex,
            )
    else:
        failed = True
        log.warning(
            'Skipping shared-root host bind cleanup for VM {} source={} because attachment token is missing.',
            cfg.vm.name,
            resolved.source_dir,
        )
    return detached_guest, detached_host, failed


def _remove_attachment_record(
    cfg: AgentVMConfig,
    cfg_path: Path,
    attachment: AttachmentEntry,
) -> bool:
    """Remove one exact owner-scoped record under the store lock."""
    removed = False

    def mutate(reg: Store) -> None:
        nonlocal removed
        removed = remove_attachment(
            reg,
            host_path=attachment.host_path,
            vm_name=cfg.vm.name,
            owner_principal_id=attachment.owner_principal_id,
        )

    update_store(
        mutate,
        cfg_path,
        reason=(
            f'Remove attachment record for {attachment.host_path} from VM '
            f'{cfg.vm.name} (owner={attachment.owner_principal_id or "legacy"}).'
        ),
    )
    return removed


def _set_attachment_state(
    cfg: AgentVMConfig,
    cfg_path: Path,
    attachment: AttachmentEntry,
    *,
    state: str,
) -> AttachmentEntry:
    """Persist one exact attachment lifecycle state under the store lock."""
    updated: AttachmentEntry | None = None

    def mutate(reg: Store) -> None:
        nonlocal updated
        for item in reg.attachments:
            if (
                item.vm_name == cfg.vm.name
                and item.host_path == attachment.host_path
                and item.owner_principal_id == attachment.owner_principal_id
            ):
                item.state = state
                updated = item
                return
        raise AIVMError(
            f'Attachment record disappeared while transitioning to {state!r}: '
            f'{attachment.host_path}'
        )

    update_store(
        mutate,
        cfg_path,
        reason=(
            f'Mark attachment {attachment.host_path} on VM {cfg.vm.name} '
            f'as {state} before external cleanup.'
        ),
    )
    assert updated is not None
    return updated


def _detach_persistent_attachment(
    cfg: AgentVMConfig,
    cfg_path: Path,
    attachment: AttachmentEntry,
    resolved: ResolvedAttachment,
    *,
    vm_running: bool,
    yes: bool,
) -> bool:
    """Convergently remove persistent host and guest exposure.

    The record remains as ``detaching`` until host pruning and any live guest
    unmount both succeed. Retrying resumes from that durable desired state.
    """
    if attachment.state != 'detaching':
        attachment = _set_attachment_state(
            cfg, cfg_path, attachment, state='detaching'
        )
    try:
        _sync_persistent_attachment_manifest_on_host(
            cfg, cfg_path, dry_run=False
        )
        _sync_persistent_host_replay_manifest(cfg, cfg_path, dry_run=False)
        if vm_running:
            ip = _resolve_ip_for_ssh_ops(
                cfg,
                yes=yes,
                purpose=(
                    'Query VM networking state before reconciling persistent '
                    'attachment removal.'
                ),
            )
            _reconcile_persistent_attachments_in_guest(
                cfg,
                cfg_path,
                ip,
                dry_run=False,
                reconcile_host=False,
            )
        _reconcile_persistent_host_binds(
            cfg, cfg_path, dry_run=False, vm_running=vm_running
        )
        records = _persistent_attachment_records_for_vm(cfg, cfg_path)
        if not any(record.enabled for record in records):
            _cleanup_persistent_host_replay_artifacts(
                cfg, cfg_path, dry_run=False, force=True
            )
    except CommandControlError:
        raise
    except Exception as ex:
        log.warning(
            'Persistent detach remains resumable for VM {} source={} '
            'guest_dst={} token={}: {}',
            cfg.vm.name,
            resolved.source_dir,
            resolved.guest_dst,
            resolved.tag,
            ex,
        )
        return True

    _remove_attachment_record(cfg, cfg_path, attachment)
    # Refresh the unprivileged canonical manifest after finalizing the store.
    # Root replay artifacts were already removed while the detaching record
    # still made this operation resumable. If other active records remain,
    # keep their approved manifest and binds converged.
    _sync_persistent_attachment_manifest_on_host(cfg, cfg_path, dry_run=False)
    remaining = _persistent_attachment_records_for_vm(cfg, cfg_path)
    if any(record.enabled for record in remaining):
        _sync_persistent_host_replay_manifest(cfg, cfg_path, dry_run=False)
        _reconcile_persistent_host_binds(
            cfg, cfg_path, dry_run=False, vm_running=vm_running
        )
    return False


def _print_detach_result(
    cfg: AgentVMConfig,
    cfg_path: Path,
    att: AttachmentEntry,
    host_src: Path,
    mode: str,
    *,
    vm_defined: bool | None,
    vm_running: bool,
    detached_share: bool,
    detached_shared_root_host_bind: bool,
    detached_shared_root_guest_bind: bool,
) -> None:
    """Summarize what the detach accomplished per attachment mode."""
    print(f'Detached {host_src} from VM {cfg.vm.name} ({mode} mode)')
    if mode == ATTACHMENT_MODE_DIRECT_VIRTIOFS and vm_defined is True:
        if detached_share:
            print('Detached virtiofs mapping from VM definition.')
        elif att.tag:
            print(
                'No matching virtiofs mapping found in VM definition (already absent).'
            )
    if mode == ATTACHMENT_MODE_SHARED_ROOT:
        if detached_shared_root_host_bind:
            print('Detached shared-root host bind mount.')
        if vm_running and detached_shared_root_guest_bind:
            print('Detached shared-root guest bind mount.')
    if mode == ATTACHMENT_MODE_PERSISTENT:
        print(
            'Removed persistent attachment intent and refreshed the guest replay manifest.'
        )
    if vm_running and mode == ATTACHMENT_MODE_DIRECT_VIRTIOFS:
        print(
            f'If the guest still has {att.guest_dst or host_src} mounted, unmount it inside the VM manually.'
        )
    print(f'Updated config store: {cfg_path}')


class _DetachLockScope:
    """Serialize one machine-store attachment teardown with VM state."""

    def __init__(self, cfg_path: Path, vm_name: str) -> None:
        self.inner: MachineResourceLockScope | None = None
        scope = resolve_store_scope(str(cfg_path))
        if scope.is_machine:
            assert scope.machine_layout is not None
            self.inner = machine_resource_locks(
                scope.machine_layout,
                group_gid=current_machine_group_gid(scope.machine_layout),
                include_store=True,
                vms=[vm_name],
            )

    def __enter__(self) -> None:
        if self.inner is not None:
            self.inner.__enter__()
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self.inner is None:
            return False
        return self.inner.__exit__(exc_type, exc, tb)


def _run_vm_detach_locked(
    request: VMDetachRequest,
    host_src: Path,
    context: ResolvedVMContext,
    cfg_path: Path,
) -> int:
    """Resolve and execute one detach while its machine VM lock is held."""
    cfg = context.effective_cfg
    current_owner = attachment_owner_for_context(context, cfg_path)
    reg = load_store(cfg_path)
    requested_owner = str(request.owner_principal or '').strip()
    att: AttachmentEntry | None = None
    if requested_owner and not request.admin_override:
        raise AIVMError(
            '--owner_principal requires --admin_override when targeting an '
            'attachment owner explicitly.'
        )
    if requested_owner:
        targeted = [
            item
            for item in find_attachments_for_vm_path(reg, host_src, cfg.vm.name)
            if item.owner_principal_id == requested_owner
        ]
        if len(targeted) != 1:
            raise AIVMError(
                f'No unique attachment record for owner {requested_owner!r} '
                f'matches {host_src} on VM {cfg.vm.name!r}.'
            )
        att = targeted[0]
        require_attachment_mutation_permission(
            reg,
            att,
            current_principal_id=current_owner,
            administrative_override=True,
        )
    else:
        att = find_attachment_for_vm(
            reg,
            host_src,
            cfg.vm.name,
            owner_principal_id=(current_owner if current_owner else None),
        )
        if att is None and current_owner:
            foreign = find_attachments_for_vm_path(reg, host_src, cfg.vm.name)
            if len(foreign) > 1:
                owners = ', '.join(
                    sorted(
                        item.owner_principal_id or '(legacy)'
                        for item in foreign
                    )
                )
                raise AIVMError(
                    'Multiple attachment owners match this host path. Retry '
                    f'with --owner_principal. Owners: {owners}'
                )
            if foreign:
                att = foreign[0]
                require_attachment_mutation_permission(
                    reg,
                    att,
                    current_principal_id=current_owner,
                    administrative_override=bool(request.admin_override),
                )
    if att is None:
        print(
            f'No attachment found for {host_src} on VM {cfg.vm.name}. '
            'Nothing to do.'
        )
        return 0
    if request.dry_run:
        print(
            f'DRYRUN: would detach {host_src} from VM {cfg.vm.name} '
            f'({att.mode} mode, owner={att.owner_principal_id or "legacy"})'
        )
        return 0

    # probe_vm_state escalates to sudo internally only when the unprivileged
    # read is inconclusive, so one call covers both cases.
    vm_out, vm_defined = probe_vm_state(cfg, use_sudo=True)
    vm_running = bool(vm_out.ok)
    mode = _normalize_attachment_mode(att.mode)
    resolved = ResolvedAttachment(
        vm_name=cfg.vm.name,
        mode=mode,
        access=_normalize_attachment_access(att.access),
        source_dir=att.host_path,
        guest_dst=att.guest_dst or att.host_path,
        tag=att.tag,
        owner_principal_id=att.owner_principal_id,
    )

    detached_share = False
    detached_shared_root_host_bind = False
    detached_shared_root_guest_bind = False
    detach_failed = False
    if (
        mode == ATTACHMENT_MODE_DIRECT_VIRTIOFS
        and vm_defined is True
        and att.tag
    ):
        detached_share = detach_vm_share(
            cfg,
            att.host_path,
            att.tag,
            dry_run=False,
            read_only=(resolved.access == ATTACHMENT_ACCESS_RO),
        )
    elif mode == ATTACHMENT_MODE_SHARED_ROOT:
        (
            detached_shared_root_guest_bind,
            detached_shared_root_host_bind,
            detach_failed,
        ) = _detach_shared_root_attachment(
            cfg, resolved, vm_running=vm_running, yes=bool(request.yes)
        )
    elif mode == ATTACHMENT_MODE_PERSISTENT:
        detach_failed = _detach_persistent_attachment(
            cfg,
            cfg_path,
            att,
            resolved,
            vm_running=vm_running,
            yes=bool(request.yes),
        )

    if detach_failed:
        log.error(
            'Detach cleanup was incomplete for {} on VM {}; preserving config record so detach can be retried.',
            host_src,
            cfg.vm.name,
        )
        return 2

    if mode != ATTACHMENT_MODE_PERSISTENT:
        _remove_attachment_record(cfg, cfg_path, att)

    _print_detach_result(
        cfg,
        cfg_path,
        att,
        host_src,
        mode,
        vm_defined=vm_defined,
        vm_running=vm_running,
        detached_share=detached_share,
        detached_shared_root_host_bind=detached_shared_root_host_bind,
        detached_shared_root_guest_bind=detached_shared_root_guest_bind,
    )
    return 0


def run_vm_detach(request: VMDetachRequest) -> int:
    """Detach one saved attachment through a serialized, resumable teardown."""
    host_src = logical_absolute_path(request.host_src)
    context, cfg_path = resolve_context_for_code(
        config_opt=request.config_opt,
        vm_opt=request.vm_opt,
        host_src=host_src,
    )
    cfg = context.effective_cfg
    with _DetachLockScope(cfg_path, cfg.vm.name):
        return _run_vm_detach_locked(request, host_src, context, cfg_path)


def _print_persistent_identity_refresh(
    report: PersistentSourceIdentityRefresh, *, dry_run: bool
) -> None:
    prefix = 'DRYRUN: would trust' if dry_run else 'Trusted'
    for host_path in report.refreshed:
        print(f'{prefix} current persistent source object: {host_path}')
    for host_path in report.unchanged:
        print(f'Persistent source identity already current: {host_path}')
    for host_path, detail in report.unavailable:
        log.warning(
            'Could not refresh persistent source identity for {}: {}',
            host_path,
            detail,
        )
    if report.skipped_foreign:
        log.warning(
            'Skipped {} persistent attachment(s) owned by another access '
            'identity; use --admin_override only when intentionally '
            'reauthorizing those paths.',
            len(report.skipped_foreign),
        )


def run_persistent_host_replay(
    request: VMPersistentHostReplayRequest,
) -> int:
    """Replay host binds, optionally reauthorizing the current path objects."""
    if request.trust_current_paths:
        context, cfg_path = load_vm_context_with_path(
            request.config_opt, vm_opt=request.vm_opt
        )
        cfg = context.effective_cfg
        owner = attachment_owner_for_context(context, cfg_path)
        report = refresh_persistent_source_identities(
            cfg,
            cfg_path,
            current_principal_id=owner,
            administrative_override=bool(request.admin_override),
            dry_run=bool(request.dry_run),
        )
        _print_persistent_identity_refresh(
            report, dry_run=bool(request.dry_run)
        )
    else:
        cfg, cfg_path = load_cfg_with_path(
            request.config_opt, vm_opt=request.vm_opt
        )
    _sync_persistent_attachment_manifest_on_host(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
    )
    unavailable = _reconcile_persistent_host_binds(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
        vm_running=None,
    )
    if request.dry_run:
        print(
            f'DRYRUN: would replay host-side persistent bind mounts for VM {cfg.vm.name}'
        )
    else:
        suffix = (
            f' with {len(unavailable)} unavailable source(s) left unmounted'
            if unavailable
            else ''
        )
        print(
            f'Replayed host-side persistent bind mounts for VM {cfg.vm.name}{suffix}'
        )
    return 0


def run_install_persistent_host_replay_service(
    request: VMInstallPersistentHostReplayServiceRequest,
) -> int:
    """Install and enable a host systemd service for persistent bind replay."""
    cfg, cfg_path = load_cfg_with_path(
        request.config_opt, vm_opt=request.vm_opt
    )
    _sync_persistent_attachment_manifest_on_host(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
    )
    _install_persistent_host_bind_replay(
        cfg,
        cfg_path,
        dry_run=bool(request.dry_run),
    )
    if request.dry_run:
        print(
            f'DRYRUN: would install the persistent host replay service for VM {cfg.vm.name}'
        )
    else:
        print(
            f'Installed and enabled the persistent host replay service for VM {cfg.vm.name}'
        )
    return 0


class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    host_src: str = kwconf.Value(
        '.', position=1, help='Host directory to attach.'
    )
    guest_dst: str = kwconf.Value('', help='Guest mount path override.')
    mode: Literal['', 'direct-virtiofs', 'shared-root', 'persistent', 'git'] = (
        kwconf.Value(
            '',
            help=(
                'Attachment mode: persistent, shared-root, git, or direct-virtiofs (default: saved mode or persistent; mode changes require detach+reattach). direct-virtiofs gives the folder its own virtiofs device and so consumes one of the guest PCIe slots -- prefer it only when a per-folder device is actually needed, such as when you have no host sudo.'
            ),
        )
    )
    access: Literal['', 'rw', 'ro'] = kwconf.Value(
        '',
        help=(
            'Attachment access: rw or ro (default: saved access or rw). ro is supported for direct-virtiofs, shared-root, and persistent modes.'
        ),
    )
    dry_run: bool = kwconf.Flag(False,
        short_alias=['n'],
        help='Print actions without running.')
    admin_override: bool = kwconf.Flag(
        False,
        help="Allow a trusted host administrator to update another principal's attachment.",
    )
    owner_principal: str = kwconf.Value(
        '',
        help=(
            'Access identity that owns the attachment, with --admin_override. '
            'Disambiguates an existing record, and declares a new attachment '
            "on that identity's behalf when it has none for this path -- how "
            'an administrator sets up a root-requiring mode for a host user '
            'who has no sudo.'
        ),
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        log.trace(
            'VMAttachCLI.main host_src={} vm={} guest_dst={} mode={} access={} dry_run={} yes={}',
            args.host_src,
            args.vm,
            args.guest_dst,
            args.mode,
            args.access,
            bool(args.dry_run),
            bool(args.yes),
        )
        return run_vm_attach(
            VMAttachRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src),
                guest_dst=args.guest_dst,
                mode=args.mode,
                access=args.access,
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
                admin_override=bool(args.admin_override),
                owner_principal=args.owner_principal,
            )
        )


class VMDetachCLI(_BaseCommand):
    """Detach/unregister a host directory from a managed VM."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    host_src: str = kwconf.Value(
        '.', position=1, help='Host directory to detach.'
    )
    dry_run: bool = kwconf.Flag(False,
        short_alias=['n'],
        help='Print actions without running.')
    admin_override: bool = kwconf.Flag(
        False,
        help="Allow a trusted host administrator to detach another principal's attachment.",
    )
    owner_principal: str = kwconf.Value(
        '',
        help='Owner principal id to target with --admin_override when a host path is ambiguous.',
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_vm_detach(
            VMDetachRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                host_src=Path(args.host_src),
                dry_run=bool(args.dry_run),
                yes=bool(args.yes),
                admin_override=bool(args.admin_override),
                owner_principal=args.owner_principal,
            )
        )


class VMPersistentHostReplayCLI(_BaseCommand):
    """Replay host-side persistent bind mounts from the saved manifest."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(False,
        short_alias=['n'],
        help='Print actions without running.')
    trust_current_paths: bool = kwconf.Flag(
        False,
        help=(
            'Explicitly trust the filesystem objects currently present at '
            'saved persistent host paths and refresh their pinned identities '
            'before replay. This is the recovery escape hatch for legitimate '
            'remount/reboot identity changes; use --dry_run to preview.'
        ),
    )
    admin_override: bool = kwconf.Flag(
        False,
        help=(
            'With --trust_current_paths, also reauthorize persistent paths '
            'owned by other access identities.'
        ),
    )

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        if args.admin_override and not args.trust_current_paths:
            raise AIVMError(
                '--admin_override on persistent-host-replay is only valid '
                'with --trust_current_paths.'
            )
        return run_persistent_host_replay(
            VMPersistentHostReplayRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                dry_run=bool(args.dry_run),
                trust_current_paths=bool(args.trust_current_paths),
                admin_override=bool(args.admin_override),
            )
        )


class VMInstallPersistentHostReplayServiceCLI(_BaseCommand):
    """Install and enable a host systemd service for persistent bind replay."""

    vm: str = kwconf.Value('', help='Optional VM name override.')
    dry_run: bool = kwconf.Flag(False,
        short_alias=['n'],
        help='Print actions without running.')

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        return run_install_persistent_host_replay_service(
            VMInstallPersistentHostReplayServiceRequest(
                config_opt=args.config,
                vm_opt=args.vm,
                dry_run=bool(args.dry_run),
            )
        )
