"""Logical desired-state models for the AIVM config store."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import (
    AgentVMConfig,
    BehaviorConfig,
    FirewallConfig,
    NetworkConfig,
)
from ..credentials.schema import (
    CREDENTIAL_ACCESS_READ,
    CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    CREDENTIAL_STATE_PENDING,
    CredentialAccess,
    CredentialKind,
    CredentialState,
)
from ..legacy.pre_0_6_0 import compatibility_surface


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

#: Mode assumed for a stored attachment that names none. Spelled here rather
#: than imported from :class:`aivm.vm.share.AttachmentMode` to keep the store
#: models free of any dependency on the VM layer; ``test_config_store_schema``
#: holds the two spellings together. This is also the historical meaning of a
#: record written before the mode had a name: one virtiofs device per folder.
DEFAULT_ATTACHMENT_MODE = 'direct-virtiofs'


@dataclass
class AttachmentEntry:
    host_path: str
    vm_name: str
    owner_principal_id: str = ''
    mode: str = DEFAULT_ATTACHMENT_MODE
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
class AgentCredentialEntry:
    """One host-only repository grant owned by agent credentials.

    This collection is intentionally separate from :class:`CredentialEntry`.
    Its private key material belongs only to the host-side agent subsystem and
    must never be installed through the guest-key credential path.
    """

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


# The highest store schema this build reads and writes. A shared machine
# store may be edited by several aivm versions; parse refuses machine
# documents newer than this so an older build cannot silently re-render the
# store and drop fields a newer principal wrote.
STORE_SCHEMA_VERSION = 12


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
    agent_credentials: list[AgentCredentialEntry] = field(default_factory=list)
    principals: list[PrincipalEntry] = field(default_factory=list)
    # Private optimistic-concurrency metadata populated by load_store().
    # It is deliberately excluded from repr/equality and never serialized.
    _source_path: str = field(default='', repr=False, compare=False)
    _source_fingerprint: str = field(default='', repr=False, compare=False)
