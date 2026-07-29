"""Logical desired-state models for the AIVM config store."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import (
    AgentVMConfig,
    BehaviorConfig,
    FirewallConfig,
    NetworkConfig,
)
from ..legacy.pre_0_6_0 import compatibility_surface
from ..credentials.schema import (
    CREDENTIAL_ACCESS_READ,
    CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    CREDENTIAL_STATE_PENDING,
    CredentialAccess,
    CredentialKind,
    CredentialState,
)


@dataclass
class VMEntry:
    name: str
    network_name: str
    cfg: AgentVMConfig


@dataclass
class NetworkEntry:
    name: str
    network: NetworkConfig = field(default_factory=NetworkConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)


ATTACHMENT_SYSTEM_OWNER = 'system'


@dataclass
class AttachmentEntry:
    host_path: str
    vm_name: str
    owner_principal_id: str = ''
    mode: str = 'shared'
    access: str = 'rw'
    guest_dst: str = ''
    tag: str = ''
    state: str = 'active'
    source_dev: int = 0
    source_ino: int = 0
    host_lexical_paths: list[str] = field(default_factory=list)


@dataclass
class CredentialEntry:
    id: str
    vm_name: str
    principal_id: str = ''
    kind: CredentialKind = CREDENTIAL_KIND_GITHUB_DEPLOY_KEY
    provider_host: str = 'github.com'
    owner: str = ''
    repository: str = ''
    access: CredentialAccess = CREDENTIAL_ACCESS_READ
    provider_key_id: str = ''
    provider_key_title: str = ''
    key_fingerprint: str = ''
    state: CredentialState = CREDENTIAL_STATE_PENDING
    # False when AIVM installed and verified this credential but never
    # administered it at the provider, because the account it uses is not an
    # admin of the repository. Such a key was added by a human out of band, so
    # AIVM has no provider key id and cannot revoke it -- see
    # `aivm vm creds abandon`.
    provider_managed: bool = True


@dataclass
class PrincipalEntry:
    """One host user's persisted identity inside a managed VM."""

    id: str
    vm_name: str
    host_user: str
    host_uid: int
    host_gid: int
    guest_user: str
    ssh_public_key: str = ''
    state: str = 'pending'


@compatibility_surface
@dataclass
class Store:
    schema_version: int = 8
    # ``legacy`` is the released per-user document. ``machine`` is the new
    # host-wide desired-state document; user selection and SSH paths live in a
    # separate profile file.
    store_kind: str = 'legacy'
    active_vm: str = ''
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    defaults: AgentVMConfig | None = None
    networks: list[NetworkEntry] = field(default_factory=list)
    vms: list[VMEntry] = field(default_factory=list)
    attachments: list[AttachmentEntry] = field(default_factory=list)
    credentials: list[CredentialEntry] = field(default_factory=list)
    principals: list[PrincipalEntry] = field(default_factory=list)
    # Private optimistic-concurrency metadata populated by load_store().
    # It is deliberately excluded from repr/equality and never serialized.
    _source_path: str = field(default='', repr=False, compare=False)
    _source_fingerprint: str = field(default='', repr=False, compare=False)
