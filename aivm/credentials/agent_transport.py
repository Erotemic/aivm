"""Connection-time capability transport for independent ssh-agent grants."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..commands import CommandManager
from ..config_scopes import ResolvedVMContext
from ..errors import AIVMError, VMNotRunningError
from ..scoped_store import load_scope_store, resolve_store_scope
from ..status import probe_ssh_ready
from ..vm.connectivity import get_ip_cached, wait_for_ip
from . import agent
from .agent_guest import (
    RepositoryVerificationNetworkError,
    probe_forwarded_agent,
    probe_repository_access,
    reconcile_guest_agent_credentials,
)
from .agent_schema import AGENT_CREDENTIAL_STATE_ACTIVE


@dataclass(frozen=True)
class AgentForwarding:
    """Prepared connection capability for one VM principal."""

    socket_path: Path
    credential_count: int
    fingerprints: tuple[str, ...]
    repository_warning: str = ''


@dataclass(frozen=True)
class AgentGrantForwardingReadiness:
    """Result of opportunistically activating a new grant in the guest."""

    forwarding: AgentForwarding | None
    ip: str | None
    deferred_reason: str = ''

    @property
    def verified(self) -> bool:
        return self.forwarding is not None


def prepare_agent_forwarding(
    context: ResolvedVMContext,
    store_path: Path,
    ip: str,
    *,
    manager: CommandManager,
    verify_repository_id: str | None = None,
) -> AgentForwarding | None:
    """Prepare host agent, public guest routing, and forwarding preflight.

    The guest-key credential collection is not an input.  This connection seam
    considers only independently created ``agent_credentials`` records.
    """
    scope = resolve_store_scope(str(store_path))
    store = load_scope_store(scope)
    principal_id = context.principal.id if scope.is_machine else ''
    vm_name = context.effective_cfg.vm.name
    records = agent.list_agent_credentials(store, vm_name, principal_id)
    active = tuple(
        record
        for record in records
        if record.state == AGENT_CREDENTIAL_STATE_ACTIVE
    )
    if not active:
        return None

    status = agent.ensure_agent_state(
        store,
        vm_name,
        principal_id,
        manager=manager,
    )
    public_keys: dict[str, str] = {}
    fingerprints: list[str] = []
    for record in active:
        public_text, fingerprint = agent.validated_agent_public_key(record, manager=manager)
        public_keys[record.id] = public_text
        fingerprints.append(fingerprint)

    reconcile_guest_agent_credentials(
        context.effective_cfg,
        ip,
        credentials=active,
        public_keys=public_keys,
        manager=manager,
    )
    expected = tuple(fingerprints)
    probe_forwarded_agent(
        context.effective_cfg,
        ip,
        socket_path=status.socket_path,
        expected_fingerprints=expected,
        manager=manager,
    )
    repository_warning = ''
    if verify_repository_id is not None:
        verified_record = next(
            (record for record in active if record.id == verify_repository_id),
            None,
        )
        if verified_record is None:
            raise AIVMError(
                'Cannot verify ssh-agent repository routing because active '
                f'credential {verify_repository_id!r} was not found.'
            )
        try:
            probe_repository_access(
                context.effective_cfg,
                ip,
                socket_path=status.socket_path,
                credential=verified_record,
                manager=manager,
            )
        except RepositoryVerificationNetworkError as ex:
            repository_warning = str(ex)
    return AgentForwarding(
        socket_path=status.socket_path,
        credential_count=len(active),
        fingerprints=expected,
        repository_warning=repository_warning,
    )


def prepare_agent_grant_forwarding(
    context: ResolvedVMContext,
    store_path: Path,
    *,
    credential_id: str,
    manager: CommandManager,
    discovery_timeout_s: int = 12,
) -> AgentGrantForwardingReadiness:
    """Activate a newly granted ssh-agent credential when the guest is ready.

    Provider authority and the dedicated host agent are already durable before
    this helper runs.  A stopped or still-booting VM therefore defers guest
    activation instead of making credential creation depend on VM availability.
    When SSH is ready, reuse the normal foreground-session preparation path to
    reconcile public selectors, prove the forwarded fingerprints, and verify
    repository authentication through the generated Git/SSH route end to end.
    """
    cfg = context.effective_cfg
    ip = get_ip_cached(cfg)
    ssh = probe_ssh_ready(cfg, ip) if ip else None
    if ssh is None or not ssh.ok:
        try:
            ip = wait_for_ip(
                cfg,
                timeout_s=discovery_timeout_s,
                dry_run=False,
            )
        except (VMNotRunningError, TimeoutError) as ex:
            return AgentGrantForwardingReadiness(
                forwarding=None,
                ip=None,
                deferred_reason=str(ex),
            )
        ssh = probe_ssh_ready(cfg, ip)

    if not ssh.ok:
        return AgentGrantForwardingReadiness(
            forwarding=None,
            ip=ip,
            deferred_reason=(
                f'VM {cfg.vm.name} is reachable at {ip}, but SSH is not ready yet.'
            ),
        )
    if ip is None:
        raise AIVMError(
            f'VM {cfg.vm.name} reported ready SSH without a resolved IP address.'
        )

    forwarding = prepare_agent_forwarding(
        context,
        store_path,
        ip,
        manager=manager,
        verify_repository_id=credential_id,
    )
    if forwarding is None:
        raise AIVMError(
            'The ssh-agent grant is active, but foreground credential '
            'preparation found no active ssh-agent credentials.'
        )
    return AgentGrantForwardingReadiness(
        forwarding=forwarding,
        ip=ip,
    )

