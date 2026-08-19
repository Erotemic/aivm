"""Connection-time capability transport for independent host-agent grants."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..commands import CommandManager
from ..config_scopes import ResolvedVMContext
from ..scoped_store import load_scope_store, resolve_store_scope
from . import agent
from .agent_guest import (
    probe_forwarded_agent,
    reconcile_guest_agent_credentials,
)
from .agent_schema import AGENT_CREDENTIAL_STATE_ACTIVE


@dataclass(frozen=True)
class AgentForwarding:
    """Prepared connection capability for one VM principal."""

    socket_path: Path
    credential_count: int
    fingerprints: tuple[str, ...]


def prepare_agent_forwarding(
    context: ResolvedVMContext,
    store_path: Path,
    ip: str,
    *,
    manager: CommandManager,
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
    return AgentForwarding(
        socket_path=status.socket_path,
        credential_count=len(active),
        fingerprints=expected,
    )
