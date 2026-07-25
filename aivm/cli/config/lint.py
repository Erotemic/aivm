"""``aivm config lint`` — surface unknown/typo'd keys in the config store."""

from __future__ import annotations

import sys
import tomllib
from dataclasses import fields
from pathlib import Path
from typing import Any, cast

from ...config import (
    FirewallConfig,
    ImageConfig,
    NetworkConfig,
    PathsConfig,
    ProvisionConfig,
    VirtiofsConfig,
    VMConfig,
)
from ...config_store import load_config_document
from ...credentials.schema import (
    VALID_CREDENTIAL_ACCESS,
    VALID_CREDENTIAL_KINDS,
    VALID_CREDENTIAL_STATES,
)
from ...credentials.validation import (
    CredentialValidationError,
    validate_credential_identity,
    validate_key_fingerprint,
    validate_metadata_text,
    validate_provider_key_id,
)
from ...services import cfg_path
from .._common import _BaseCommand


class ConfigLintCLI(_BaseCommand):
    """Lint config store for unknown/unused keys and sections."""

    @classmethod
    def main(cls, argv: bool = True, **kwargs: Any) -> int:
        args = cls.cli(argv=argv, data=kwargs)
        path = cfg_path(args.config)
        loaded = load_config_document(path)
        if not loaded.sources:
            print(f'Config store not found: {path}', file=sys.stderr)
            return 2
        problems = _lint_store_text(loaded.source_text or path.read_text(encoding='utf-8'))
        label = path if loaded.layout != 'split' else f'{path.parent} (split layout)'
        if not problems:
            print(f'✅ Config lint passed: {label}')
            return 0
        print(f'❌ Config lint found {len(problems)} issue(s): {label}')
        for item in problems:
            print(f'  - {item}')
        return 2


def _field_names(cls: type[Any]) -> set[str]:
    """Small helper for dataclass-backed lint allow-lists."""
    return {f.name for f in fields(cast(Any, cls))}


def _lint_store_file(path: Path) -> list[str]:
    """Return schema/shape problems for the config store file."""
    return _lint_store_text(path.read_text(encoding='utf-8'))


def _lint_store_text(text: str) -> list[str]:
    """Return schema/shape problems for a canonical config document.

    Lint focuses on unknown or structurally invalid keys so users can catch
    typos and stale fields after format evolution.
    """
    raw = tomllib.loads(text)
    problems: list[str] = []

    allowed_top = {
        'schema_version',
        'active_vm',
        'behavior',
        'defaults',
        'networks',
        'vms',
        'attachments',
    }
    for key in sorted(raw.keys()):
        if key not in allowed_top:
            problems.append(f'unknown top-level key: {key!r}')

    allowed_vm_record = {
        'name',
        'network_name',
        'verbosity',
        'vm',
        'image',
        'provision',
        'paths',
        'virtiofs',
        'attachments',
        'credentials',
    }
    section_allowed: dict[str, set[str]] = {
        'vm': _field_names(VMConfig),
        'network': _field_names(NetworkConfig),
        'firewall': _field_names(FirewallConfig),
        'image': _field_names(ImageConfig),
        'provision': _field_names(ProvisionConfig),
        'paths': _field_names(PathsConfig),
        'virtiofs': _field_names(VirtiofsConfig),
    }
    behavior = raw.get('behavior', None)
    if behavior is not None:
        if not isinstance(behavior, dict):
            problems.append('top-level key "behavior" should be a table/object')
        else:
            allowed_behavior = {
                'yes_sudo',
                'auto_approve_readonly_sudo',
                'verbose',
                'privilege_mode',
            }
            # mirror_shared_home_folders moved to VMConfig in schema 6;
            # tolerate the legacy key here so older files lint cleanly
            # and are migrated on parse.
            legacy_behavior = {'mirror_shared_home_folders'}
            for key in sorted(behavior.keys()):
                if key in allowed_behavior or key in legacy_behavior:
                    continue
                problems.append(f'behavior unknown key: {key!r}')
    defaults = raw.get('defaults', None)
    if defaults is not None:
        if not isinstance(defaults, dict):
            problems.append('top-level key "defaults" should be a table/object')
        else:
            allowed_defaults_record = {
                'verbosity',
                'vm',
                'network',
                'firewall',
                'image',
                'provision',
                'paths',
                'virtiofs',
            }
            for key in sorted(defaults.keys()):
                if key not in allowed_defaults_record:
                    problems.append(f'defaults unknown key/section: {key!r}')
            for sec_name, allowed in section_allowed.items():
                sec = defaults.get(sec_name, None)
                if sec is None:
                    continue
                if not isinstance(sec, dict):
                    problems.append(
                        f'defaults.{sec_name} should be a table/object'
                    )
                    continue
                sec = cast(dict[str, object], sec)
                for key in sorted(str(key) for key in sec.keys()):
                    if key not in allowed:
                        problems.append(
                            f'defaults.{sec_name} unknown key: {key!r}'
                        )

    networks = raw.get('networks', [])
    if isinstance(networks, list):
        allowed_network_record = {'name', 'network', 'firewall'}
        for idx, item in enumerate(networks):
            if not isinstance(item, dict):
                problems.append(f'networks[{idx}] is not a table/object')
                continue
            item = cast(dict[str, object], item)
            for key in sorted(str(key) for key in item.keys()):
                if key not in allowed_network_record:
                    problems.append(
                        f'networks[{idx}] unknown key/section: {key!r}'
                    )
            net_sec = item.get('network')
            if net_sec is not None:
                if not isinstance(net_sec, dict):
                    problems.append(
                        f'networks[{idx}].network should be a table/object'
                    )
                else:
                    net_sec = cast(dict[str, object], net_sec)
                    for key in sorted(str(key) for key in net_sec.keys()):
                        if key not in _field_names(NetworkConfig):
                            problems.append(
                                f'networks[{idx}].network unknown key: {key!r}'
                            )
            fw_sec = item.get('firewall')
            if fw_sec is not None:
                if not isinstance(fw_sec, dict):
                    problems.append(
                        f'networks[{idx}].firewall should be a table/object'
                    )
                else:
                    fw_sec = cast(dict[str, object], fw_sec)
                    for key in sorted(str(key) for key in fw_sec.keys()):
                        if key not in _field_names(FirewallConfig):
                            problems.append(
                                f'networks[{idx}].firewall unknown key: {key!r}'
                            )
    elif networks is not None:
        problems.append('top-level key "networks" should be an array of tables')

    allowed_attachment = {
        'host_path',
        'vm_name',
        'mode',
        'access',
        'guest_dst',
        'tag',
        'host_lexical_paths',
        # Legacy schema-6 singular form. Still accepted by the parser with a
        # deprecation warning; allow it here so lint doesn't reject existing
        # configs that haven't been rewritten yet.
        'host_lexical_path',
    }
    allowed_credential = {
        'id',
        'kind',
        'provider_host',
        'owner',
        'repository',
        'access',
        'provider_key_id',
        'provider_key_title',
        'key_fingerprint',
        'state',
    }
    vms = raw.get('vms', [])
    if isinstance(vms, list):
        for idx, item in enumerate(vms):
            if not isinstance(item, dict):
                problems.append(f'vms[{idx}] is not a table/object')
                continue
            item = cast(dict[str, object], item)
            for key in sorted(str(key) for key in item.keys()):
                if key not in allowed_vm_record:
                    problems.append(f'vms[{idx}] unknown key/section: {key!r}')
            for sec_name, allowed in section_allowed.items():
                sec = item.get(sec_name)
                if sec is None:
                    continue
                if not isinstance(sec, dict):
                    problems.append(
                        f'vms[{idx}].{sec_name} should be a table/object'
                    )
                    continue
                for key in sorted(str(key) for key in sec.keys()):
                    if key not in allowed:
                        problems.append(
                            f'vms[{idx}].{sec_name} unknown key: {key!r}'
                        )
            nested_atts = item.get('attachments', [])
            if isinstance(nested_atts, list):
                for att_idx, att in enumerate(nested_atts):
                    if not isinstance(att, dict):
                        problems.append(
                            f'vms[{idx}].attachments[{att_idx}] is not a table/object'
                        )
                        continue
                    att = cast(dict[str, object], att)
                    for key in sorted(str(key) for key in att.keys()):
                        if key not in allowed_attachment:
                            problems.append(
                                f'vms[{idx}].attachments[{att_idx}] unknown key: {key!r}'
                            )
            elif nested_atts is not None:
                problems.append(
                    f'vms[{idx}].attachments should be an array of tables'
                )
            nested_creds = item.get('credentials', [])
            if isinstance(nested_creds, list):
                seen_cred_ids: set[str] = set()
                seen_cred_scopes: set[tuple[str, str, str]] = set()
                required_credential = {
                    'id',
                    'kind',
                    'provider_host',
                    'owner',
                    'repository',
                    'access',
                    'provider_key_title',
                    'key_fingerprint',
                    'state',
                }
                for cred_idx, cred in enumerate(nested_creds):
                    label = f'vms[{idx}].credentials[{cred_idx}]'
                    if not isinstance(cred, dict):
                        problems.append(f'{label} is not a table/object')
                        continue
                    cred = cast(dict[str, object], cred)
                    for key in sorted(str(key) for key in cred.keys()):
                        if key not in allowed_credential:
                            problems.append(f'{label} unknown key: {key!r}')
                    missing = sorted(
                        key
                        for key in required_credential
                        if not str(cred.get(key, '')).strip()
                    )
                    if missing:
                        problems.append(
                            f'{label} missing required key(s): '
                            + ', '.join(missing)
                        )
                    kind = str(cred.get('kind', '')).strip()
                    if kind and kind not in VALID_CREDENTIAL_KINDS:
                        problems.append(f'{label} unsupported kind: {kind!r}')
                    access = str(cred.get('access', '')).strip()
                    if access and access not in VALID_CREDENTIAL_ACCESS:
                        problems.append(f'{label} invalid access: {access!r}')
                    state = str(cred.get('state', '')).strip()
                    if state and state not in VALID_CREDENTIAL_STATES:
                        problems.append(f'{label} invalid state: {state!r}')
                    cred_id = str(cred.get('id', '')).strip()
                    if cred_id:
                        if cred_id in seen_cred_ids:
                            problems.append(
                                f'{label} duplicate credential id: {cred_id!r}'
                            )
                        seen_cred_ids.add(cred_id)
                    scope = (
                        str(cred.get('provider_host', '')).strip().lower(),
                        str(cred.get('owner', '')).strip().lower(),
                        str(cred.get('repository', '')).strip().lower(),
                    )
                    if all(scope):
                        if scope in seen_cred_scopes:
                            problems.append(
                                f'{label} duplicate credential scope: '
                                + '/'.join(scope)
                            )
                        seen_cred_scopes.add(scope)
                    if not missing:
                        try:
                            validate_credential_identity(
                                vm_name=str(item.get('name', '')).strip(),
                                cred_id=cred_id,
                                provider_host=str(
                                    cred.get('provider_host', '')
                                ),
                                owner=str(cred.get('owner', '')),
                                repository=str(cred.get('repository', '')),
                            )
                            validate_provider_key_id(
                                str(cred.get('provider_key_id', ''))
                            )
                            validate_metadata_text(
                                'provider_key_title',
                                str(cred.get('provider_key_title', '')),
                            )
                            validate_key_fingerprint(
                                str(cred.get('key_fingerprint', ''))
                            )
                        except CredentialValidationError as ex:
                            problems.append(f'{label} invalid credential: {ex}')
            elif nested_creds is not None:
                problems.append(
                    f'vms[{idx}].credentials should be an array of tables'
                )
    elif vms is not None:
        problems.append('top-level key "vms" should be an array of tables')

    atts = raw.get('attachments', [])
    if isinstance(atts, list):
        for idx, item in enumerate(atts):
            if not isinstance(item, dict):
                problems.append(f'attachments[{idx}] is not a table/object')
                continue
            item = cast(dict[str, object], item)
            for key in sorted(str(key) for key in item.keys()):
                if key not in allowed_attachment:
                    problems.append(f'attachments[{idx}] unknown key: {key!r}')
    elif atts is not None:
        problems.append(
            'top-level key "attachments" should be an array of tables'
        )

    return problems
