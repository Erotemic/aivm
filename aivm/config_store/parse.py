"""Parse TOML text into the logical AIVM config store model."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast

from ..config import AgentVMConfig, FirewallConfig, NetworkConfig
from ..credentials.schema import (
    CREDENTIAL_ACCESS_READ,
    CREDENTIAL_KIND_GITHUB_DEPLOY_KEY,
    CREDENTIAL_STATE_PENDING,
    VALID_CREDENTIAL_ACCESS,
    VALID_CREDENTIAL_KINDS,
    VALID_CREDENTIAL_STATES,
    CredentialAccess,
    CredentialKind,
    CredentialState,
)
from ..credentials.validation import (
    CredentialValidationError,
    validate_credential_identity,
    validate_key_fingerprint,
    validate_metadata_text,
    validate_provider_key_id,
)
from ..legacy.pre_0_6_0 import compatibility_surface
from ..legacy.pre_0_6_0.schema import (
    apply_mirror_home_to_defaults,
    apply_mirror_home_to_vm,
    mirror_home_from_behavior,
    parse_host_lexical_paths,
)
from ..legacy.pre_0_6_0.schema import (
    finalize_schema_version as finalize_pre_0_6_0_schema_version,
)
from .models import (
    STORE_SCHEMA_VERSION,
    AttachmentEntry,
    CredentialEntry,
    NetworkEntry,
    PrincipalEntry,
    Store,
    VMEntry,
)

_VALID_PRINCIPAL_STATES = {'pending', 'active', 'disabled', 'error', 'legacy'}
_VALID_STORE_KINDS = {'legacy', 'machine'}


def _parse_store_header(raw: dict[str, object], reg: Store) -> int:
    """Parse the document header and return the declared schema version."""
    schema_version_raw = raw.get('schema_version', 5)
    if not isinstance(schema_version_raw, (str, bytes, bytearray, int, float)):
        raise TypeError(
            'schema_version must be an integer-compatible scalar, '
            f'not {type(schema_version_raw).__name__}'
        )
    parsed_schema_version = int(schema_version_raw)
    reg.schema_version = parsed_schema_version
    store_kind = str(raw.get('store_kind', 'legacy') or 'legacy').strip()
    if store_kind not in _VALID_STORE_KINDS:
        allowed = ', '.join(sorted(_VALID_STORE_KINDS))
        raise ValueError(
            f'Invalid store_kind {store_kind!r}; expected one of: {allowed}'
        )
    reg.store_kind = store_kind
    if (
        store_kind == 'machine'
        and parsed_schema_version > STORE_SCHEMA_VERSION
    ):
        # The shared document may be edited by several aivm versions. An
        # older build re-rendering a newer document would silently drop the
        # fields it does not know, for every principal on the machine.
        raise ValueError(
            f'Unsupported machine store schema version '
            f'{parsed_schema_version}; this build supports up to '
            f'{STORE_SCHEMA_VERSION}. Upgrade aivm before using this store.'
        )
    reg.active_vm = str(raw.get('active_vm', '')).strip()
    behavior_raw = raw.get('behavior')
    if isinstance(behavior_raw, dict):
        for key, value in behavior_raw.items():
            if not isinstance(key, str):
                raise TypeError(
                    'behavior field names must be strings, '
                    f'not {type(key).__name__}'
                )
            if key == 'mirror_shared_home_folders':
                # Pre-schema-6 location; lifted by the legacy shims.
                continue
            if hasattr(reg.behavior, key):
                setattr(reg.behavior, key, value)
    return parsed_schema_version


def _norm_dir(path: str | Path) -> str:
    p = Path(path).expanduser()
    try:
        return str(p.resolve())
    except Exception:
        return str(p.absolute())


def _cfg_from_dict(raw: dict[str, object]) -> AgentVMConfig:
    cfg = AgentVMConfig()
    for section in (
        'vm',
        'network',
        'firewall',
        'image',
        'provision',
        'tools',
        'paths',
        'virtiofs',
    ):
        body = raw.get(section, None)
        if isinstance(body, dict):
            obj = getattr(cfg, section)
            if section == 'tools':
                obj.update(body)
                continue
            for k, v in body.items():
                if hasattr(obj, str(k)):
                    setattr(obj, str(k), v)
    verbosity_val = raw.get('verbosity')
    if verbosity_val is not None:
        cfg.verbosity = int(verbosity_val)  # type: ignore
    return cfg


def _nonnegative_int_field(
    item: dict[str, object], key: str, *, default: int = 0
) -> int:
    value = item.get(key, default)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as ex:
            raise ValueError(f'invalid integer field {key}: {value!r}') from ex
    raise ValueError(f'invalid integer field {key}: {value!r}')


def _attachment_from_dict(
    item: dict[str, object], *, vm_name: str | None = None
) -> AttachmentEntry | None:
    """Parse one attachment record from either supported TOML shape.

    Legacy configs store attachments as top-level ``[[attachments]]`` records
    and must include ``vm_name``.  The future split-friendly schema stores
    attachments under the owning ``[[vms]]`` record as
    ``[[vms.attachments]]``; those records inherit the VM name from their
    parent.  The in-memory model remains flat for now so existing attachment
    and drift code continues to work unchanged.
    """
    host_path = str(item.get('host_path', '')).strip()
    inherited_vm_name = str(vm_name or '').strip()
    explicit_vm_name = str(item.get('vm_name', '')).strip()
    if (
        inherited_vm_name
        and explicit_vm_name
        and explicit_vm_name != inherited_vm_name
    ):
        raise ValueError(
            'nested VM attachment vm_name mismatch: '
            f'expected {inherited_vm_name!r}, got {explicit_vm_name!r}'
        )
    owner = inherited_vm_name or explicit_vm_name
    if not host_path or not owner:
        return None
    return AttachmentEntry(
        host_path=_norm_dir(host_path),
        vm_name=owner,
        owner_principal_id=str(item.get('owner_principal_id', '')).strip(),
        mode=str(item.get('mode', 'shared') or 'shared'),
        access=str(item.get('access', 'rw') or 'rw'),
        guest_dst=str(item.get('guest_dst', '')).strip(),
        tag=str(item.get('tag', '')).strip(),
        state=str(item.get('state', 'active') or 'active').strip(),
        source_dev=_nonnegative_int_field(item, 'source_dev'),
        source_ino=_nonnegative_int_field(item, 'source_ino'),
        host_lexical_paths=parse_host_lexical_paths(item),
    )


def _credential_from_dict(
    item: dict[str, object], *, vm_name: str
) -> CredentialEntry:
    values = {
        'id': str(item.get('id', '')).strip(),
        'principal_id': str(item.get('principal_id', '')).strip(),
        'kind': str(
            item.get('kind', CREDENTIAL_KIND_GITHUB_DEPLOY_KEY) or ''
        ).strip(),
        'provider_host': str(
            item.get('provider_host', 'github.com') or ''
        ).strip(),
        'owner': str(item.get('owner', '')).strip(),
        'repository': str(item.get('repository', '')).strip(),
        'access': str(item.get('access', CREDENTIAL_ACCESS_READ) or '').strip(),
        'provider_key_id': str(item.get('provider_key_id', '')).strip(),
        'provider_key_title': str(item.get('provider_key_title', '')).strip(),
        'key_fingerprint': str(item.get('key_fingerprint', '')).strip(),
        'state': str(item.get('state', CREDENTIAL_STATE_PENDING) or '').strip(),
    }
    required = (
        'id',
        'kind',
        'provider_host',
        'owner',
        'repository',
        'access',
        'provider_key_title',
        'key_fingerprint',
        'state',
    )
    missing = [name for name in required if not values[name]]
    if missing:
        raise ValueError(
            f'VM {vm_name!r} credential is missing required field(s): '
            + ', '.join(missing)
        )
    if values['kind'] not in VALID_CREDENTIAL_KINDS:
        raise ValueError(
            f'VM {vm_name!r} credential {values["id"]!r} has unsupported '
            f'kind {values["kind"]!r}'
        )
    if values['access'] not in VALID_CREDENTIAL_ACCESS:
        raise ValueError(
            f'VM {vm_name!r} credential {values["id"]!r} has invalid '
            f'access {values["access"]!r}'
        )
    if values['state'] not in VALID_CREDENTIAL_STATES:
        raise ValueError(
            f'VM {vm_name!r} credential {values["id"]!r} has invalid '
            f'state {values["state"]!r}'
        )
    try:
        repo = validate_credential_identity(
            vm_name=vm_name,
            cred_id=values['id'],
            provider_host=values['provider_host'],
            owner=values['owner'],
            repository=values['repository'],
            principal_id=values['principal_id'],
        )
        provider_key_id = validate_provider_key_id(values['provider_key_id'])
        provider_key_title = validate_metadata_text(
            'provider_key_title', values['provider_key_title']
        )
        key_fingerprint = validate_key_fingerprint(values['key_fingerprint'])
    except CredentialValidationError as ex:
        raise ValueError(
            f'VM {vm_name!r} credential {values["id"]!r} is invalid: {ex}'
        ) from ex
    return CredentialEntry(
        id=values['id'],
        vm_name=vm_name,
        principal_id=values['principal_id'],
        kind=cast(CredentialKind, values['kind']),
        provider_host=repo.host,
        owner=repo.owner,
        repository=repo.name,
        access=cast(CredentialAccess, values['access']),
        provider_key_id=provider_key_id,
        provider_key_title=provider_key_title,
        key_fingerprint=key_fingerprint,
        state=cast(CredentialState, values['state']),
        provider_managed=bool(item.get('provider_managed', True)),
    )


def _principal_from_dict(
    item: dict[str, object], *, vm_name: str
) -> PrincipalEntry:
    values = {
        'id': str(item.get('id', '')).strip(),
        'host_user': str(item.get('host_user', '')).strip(),
        'guest_user': str(item.get('guest_user', '')).strip(),
        'ssh_public_key': str(item.get('ssh_public_key', '')).strip(),
        'state': str(item.get('state', 'pending') or 'pending').strip(),
    }
    missing = [
        name for name in ('id', 'host_user', 'guest_user') if not values[name]
    ]
    if missing:
        raise ValueError(
            f'VM {vm_name!r} principal is missing required field(s): '
            + ', '.join(missing)
        )
    state = values['state']
    if state not in _VALID_PRINCIPAL_STATES:
        allowed = ', '.join(sorted(_VALID_PRINCIPAL_STATES))
        raise ValueError(
            f'VM {vm_name!r} principal {values["id"]!r} has invalid '
            f'state {state!r}; expected one of: {allowed}'
        )
    host_uid_raw = item.get('host_uid', -1)
    host_gid_raw = item.get('host_gid', -1)
    if not isinstance(host_uid_raw, (int, str)) or not isinstance(
        host_gid_raw, (int, str)
    ):
        raise ValueError(
            f'VM {vm_name!r} principal {values["id"]!r} has non-integer '
            'host_uid/host_gid'
        )
    try:
        host_uid = int(host_uid_raw)
        host_gid = int(host_gid_raw)
    except ValueError as ex:
        raise ValueError(
            f'VM {vm_name!r} principal {values["id"]!r} has non-integer '
            'host_uid/host_gid'
        ) from ex
    return PrincipalEntry(
        id=values['id'],
        vm_name=vm_name,
        host_user=values['host_user'],
        host_uid=host_uid,
        host_gid=host_gid,
        guest_user=values['guest_user'],
        ssh_public_key=values['ssh_public_key'],
        state=state,
    )


@compatibility_surface
def parse_store_toml(text: str) -> Store:
    """Parse a canonical AIVM desired-state TOML document."""
    raw = tomllib.loads(text)
    reg = Store()
    parsed_schema_version = _parse_store_header(raw, reg)
    legacy_mirror_home = mirror_home_from_behavior(raw)
    defaults_raw = raw.get('defaults', None)
    if isinstance(defaults_raw, dict):
        reg.defaults = _cfg_from_dict(defaults_raw).expanded_paths()
    apply_mirror_home_to_defaults(reg, legacy_mirror_home)

    for item in raw.get('networks', []):
        if not isinstance(item, dict):
            continue
        net = NetworkConfig()
        fw = FirewallConfig()
        net_raw = item.get('network', None)
        if isinstance(net_raw, dict):
            for k, v in net_raw.items():
                if hasattr(net, k):
                    setattr(net, k, v)
        fw_raw = item.get('firewall', None)
        if isinstance(fw_raw, dict):
            for k, v in fw_raw.items():
                if hasattr(fw, k):
                    setattr(fw, k, v)
        name = str(item.get('name', '')).strip()
        if not name:
            name = str(net.name or '').strip()
        if not name:
            continue
        net.name = name
        reg.networks.append(NetworkEntry(name=name, network=net, firewall=fw))

    for item in raw.get('vms', []):
        if not isinstance(item, dict):
            continue
        name = str(item.get('name', '')).strip()
        if not name:
            continue
        cfg = _cfg_from_dict(item).expanded_paths()
        cfg.vm.name = name
        apply_mirror_home_to_vm(cfg, item, legacy_mirror_home)
        network_name = str(item.get('network_name', '')).strip()
        if not network_name:
            network_name = str(cfg.network.name or '').strip()
        if not network_name:
            network_name = 'aivm-net'
        reg.vms.append(VMEntry(name=name, network_name=network_name, cfg=cfg))

        for att_raw in item.get('attachments', []):
            if not isinstance(att_raw, dict):
                continue
            att = _attachment_from_dict(att_raw, vm_name=name)
            if att is not None:
                reg.attachments.append(att)

        seen_credential_ids: set[str] = set()
        seen_credential_scopes: set[tuple[str, str, str, str]] = set()
        for cred_raw in item.get('credentials', []):
            if not isinstance(cred_raw, dict):
                raise ValueError(
                    f'VM {name!r} credential entry must be a table/object'
                )
            cred = _credential_from_dict(cred_raw, vm_name=name)
            if cred.id in seen_credential_ids:
                raise ValueError(
                    f'VM {name!r} has duplicate credential id {cred.id!r}'
                )
            scope = (
                cred.principal_id,
                cred.provider_host.lower(),
                cred.owner.lower(),
                cred.repository.lower(),
            )
            if scope in seen_credential_scopes:
                raise ValueError(
                    f'VM {name!r} has duplicate credential scope '
                    f'{cred.principal_id or "legacy"}:'
                    f'{cred.provider_host}/{cred.owner}/{cred.repository}'
                )
            seen_credential_ids.add(cred.id)
            seen_credential_scopes.add(scope)
            reg.credentials.append(cred)

        seen_principal_ids: set[str] = set()
        seen_host_users: set[str] = set()
        for principal_raw in item.get('principals', []):
            if not isinstance(principal_raw, dict):
                raise ValueError(
                    f'VM {name!r} principal entry must be a table/object'
                )
            principal = _principal_from_dict(principal_raw, vm_name=name)
            if principal.id in seen_principal_ids:
                raise ValueError(
                    f'VM {name!r} has duplicate principal id {principal.id!r}'
                )
            if principal.host_user in seen_host_users:
                raise ValueError(
                    f'VM {name!r} has duplicate principal host user '
                    f'{principal.host_user!r}'
                )
            seen_principal_ids.add(principal.id)
            seen_host_users.add(principal.host_user)
            reg.principals.append(principal)

    for item in raw.get('attachments', []):
        if not isinstance(item, dict):
            continue
        att = _attachment_from_dict(item)
        if att is not None:
            reg.attachments.append(att)
    finalize_pre_0_6_0_schema_version(
        reg,
        parsed_schema_version=parsed_schema_version,
        mirror_home=legacy_mirror_home,
    )
    if reg.credentials:
        reg.schema_version = max(reg.schema_version, 8)
    if reg.principals or reg.store_kind == 'machine':
        reg.schema_version = max(reg.schema_version, 9)
    if any(att.owner_principal_id for att in reg.attachments):
        reg.schema_version = max(reg.schema_version, 10)
    if any(cred.principal_id for cred in reg.credentials):
        reg.schema_version = max(reg.schema_version, 11)
    return reg
