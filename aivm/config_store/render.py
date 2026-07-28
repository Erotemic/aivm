"""Render the logical AIVM config store model as TOML."""

from __future__ import annotations

from dataclasses import asdict

from .models import AttachmentEntry, CredentialEntry, PrincipalEntry, Store


def _toml_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('"', '\\"')


def _emit_toml_kv(lines: list[str], key: str, val: object) -> None:
    if isinstance(val, bool):
        lines.append(f'{key} = {"true" if val else "false"}')
    elif isinstance(val, int):
        lines.append(f'{key} = {val}')
    elif isinstance(val, list):
        parts = [f'"{_toml_escape(str(item))}"' for item in val]
        lines.append(f'{key} = [{", ".join(parts)}]')
    else:
        lines.append(f'{key} = "{_toml_escape(str(val))}"')


def _emit_attachment(
    lines: list[str], att: AttachmentEntry, *, include_vm_name: bool
) -> None:
    lines.append(f'host_path = "{_toml_escape(att.host_path)}"')
    if include_vm_name:
        lines.append(f'vm_name = "{_toml_escape(att.vm_name)}"')
    if att.owner_principal_id:
        lines.append(
            f'owner_principal_id = "{_toml_escape(att.owner_principal_id)}"'
        )
    lines.append(f'mode = "{_toml_escape(att.mode)}"')
    lines.append(f'access = "{_toml_escape(att.access)}"')
    lines.append(f'guest_dst = "{_toml_escape(att.guest_dst)}"')
    lines.append(f'tag = "{_toml_escape(att.tag)}"')
    if att.host_lexical_paths:
        parts = [
            f'"{_toml_escape(p)}"' for p in att.host_lexical_paths
        ]
        lines.append(f'host_lexical_paths = [{", ".join(parts)}]')


def _emit_credential(lines: list[str], cred: CredentialEntry) -> None:
    lines.append(f'id = "{_toml_escape(cred.id)}"')
    if cred.principal_id:
        lines.append(
            f'principal_id = "{_toml_escape(cred.principal_id)}"'
        )
    for key in (
        'kind',
        'provider_host',
        'owner',
        'repository',
        'access',
        'provider_key_id',
        'provider_key_title',
        'key_fingerprint',
        'state',
    ):
        lines.append(f'{key} = "{_toml_escape(str(getattr(cred, key)))}"')
    # Emitted only when false so ordinary credentials -- and the stores that
    # hold them -- render exactly as they did before this field existed.
    if not cred.provider_managed:
        lines.append('provider_managed = false')


def _emit_principal(lines: list[str], principal: PrincipalEntry) -> None:
    for key in (
        'id',
        'host_user',
        'host_uid',
        'host_gid',
        'guest_user',
        'ssh_public_key',
        'state',
    ):
        _emit_toml_kv(lines, key, getattr(principal, key))


def _section_items(
    reg: Store, section: str, body: dict[str, object]
) -> list[tuple[str, object]]:
    """Return serialized fields for one config section.

    Machine stores deliberately omit caller identity and user-owned paths.
    Those values are materialized from the selected principal and profile at
    runtime.
    """
    items = list(body.items())
    if reg.store_kind != 'machine':
        return items
    if section == 'vm':
        return [(key, val) for key, val in items if key != 'user']
    if section == 'paths':
        return [(key, val) for key, val in items if key == 'base_dir']
    return items


def _emit_defaults(lines: list[str], reg: Store) -> None:
    """Append ``[defaults.*]`` tables for ``reg`` to ``lines``."""
    if reg.defaults is None:
        return
    d = asdict(reg.defaults)
    verbosity = int(d.get('verbosity', 1))
    if verbosity != 1:
        lines.append('[defaults]')
        lines.append(f'verbosity = {verbosity}')
        lines.append('')
    for section in (
        'vm',
        'network',
        'firewall',
        'image',
        'provision',
        'paths',
        'virtiofs',
    ):
        body = d.get(section, {})
        if not isinstance(body, dict):
            continue
        lines.append(f'[defaults.{section}]')
        for k, v in _section_items(reg, section, body):
            _emit_toml_kv(lines, k, v)
        lines.append('')



def render_store_toml(
    reg: Store, *, attachment_style: str = 'legacy'
) -> str:
    """Render a Store as TOML.

    ``attachment_style='legacy'`` preserves the current top-level
    ``[[attachments]]`` layout.  ``attachment_style='nested'`` emits
    attachments under their owning ``[[vms]]`` record as
    ``[[vms.attachments]]``.  The nested style is the schema stepping stone
    for split config fragments whose literal concatenation forms the canonical
    desired-state document.
    """
    if attachment_style not in {'legacy', 'nested'}:
        raise ValueError(
            "attachment_style must be either 'legacy' or 'nested', "
            f'not {attachment_style!r}'
        )

    lines: list[str] = [f'schema_version = {reg.schema_version}']
    if reg.store_kind == 'machine':
        lines.append('store_kind = "machine"')
        lines.append('')
    else:
        lines.append(f'active_vm = "{_toml_escape(reg.active_vm)}"')
        lines.append('')
        lines.append('[behavior]')
        _emit_toml_kv(lines, 'yes_sudo', bool(reg.behavior.yes_sudo))
        _emit_toml_kv(
            lines,
            'auto_approve_readonly_sudo',
            bool(reg.behavior.auto_approve_readonly_sudo),
        )
        _emit_toml_kv(lines, 'verbose', int(reg.behavior.verbose))
        _emit_toml_kv(
            lines,
            'privilege_mode',
            str(reg.behavior.privilege_mode or 'as-needed'),
        )
        _emit_toml_kv(
            lines,
            'credential_directory_permission_policy',
            str(reg.behavior.credential_directory_permission_policy or 'warn'),
        )
        lines.append('')

    _emit_defaults(lines, reg)

    for net in sorted(reg.networks, key=lambda n: n.name):
        lines.append('[[networks]]')
        lines.append(f'name = "{_toml_escape(net.name)}"')
        net_d = asdict(net.network)
        lines.append('[networks.network]')
        for k, v in net_d.items():
            if k == 'name':
                continue
            _emit_toml_kv(lines, k, v)
        fw_d = asdict(net.firewall)
        lines.append('[networks.firewall]')
        for k, v in fw_d.items():
            _emit_toml_kv(lines, k, v)
        lines.append('')

    vm_names = {vm.name for vm in reg.vms}
    for vm in sorted(reg.vms, key=lambda v: v.name):
        lines.append('[[vms]]')
        lines.append(f'name = "{_toml_escape(vm.name)}"')
        lines.append(f'network_name = "{_toml_escape(vm.network_name)}"')
        d = asdict(vm.cfg)
        verbosity = int(d.get('verbosity', 1))
        if verbosity != 1:
            lines.append(f'verbosity = {verbosity}')
        for section in ('vm', 'image', 'provision', 'paths', 'virtiofs'):
            body = d.get(section, {})
            if not isinstance(body, dict):
                continue
            lines.append(f'[vms.{section}]')
            for k, v in _section_items(reg, section, body):
                _emit_toml_kv(lines, k, v)

        if attachment_style == 'nested':
            nested = sorted(
                (att for att in reg.attachments if att.vm_name == vm.name),
                key=lambda a: (a.host_path, a.guest_dst, a.tag),
            )
            for att in nested:
                lines.append('[[vms.attachments]]')
                _emit_attachment(lines, att, include_vm_name=False)
        nested_creds = sorted(
            (cred for cred in reg.credentials if cred.vm_name == vm.name),
            key=lambda cred: cred.id,
        )
        for cred in nested_creds:
            lines.append('[[vms.credentials]]')
            _emit_credential(lines, cred)
        nested_principals = sorted(
            (item for item in reg.principals if item.vm_name == vm.name),
            key=lambda item: (item.host_user, item.id),
        )
        for principal in nested_principals:
            lines.append('[[vms.principals]]')
            _emit_principal(lines, principal)
        lines.append('')

    legacy_atts = reg.attachments
    if attachment_style == 'nested':
        # Keep orphaned attachment records serializable.  Normal stores should
        # not have these, but preserving them avoids data loss during manual
        # repair or transition states.
        legacy_atts = [
            att for att in reg.attachments if att.vm_name not in vm_names
        ]

    for att in sorted(legacy_atts, key=lambda a: (a.host_path, a.vm_name)):
        lines.append('[[attachments]]')
        _emit_attachment(lines, att, include_vm_name=True)
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def render_store_root_toml(reg: Store) -> str:
    """Render only singleton/global config tables for split layout.

    The result is intended for ``~/.config/aivm/config.toml``.  It may define
    schema/global behavior, but it intentionally emits no defaults,
    ``[[networks]]``, ``[[vms]]``, or ``[[attachments]]`` records so it can be
    concatenated with split fragments.  Defaults live in ``defaults.toml``.
    """
    root = Store(
        schema_version=reg.schema_version,
        store_kind=reg.store_kind,
        active_vm=reg.active_vm,
        behavior=reg.behavior,
        defaults=None,
    )
    return render_store_toml(root, attachment_style='nested')


def render_store_defaults_toml(reg: Store) -> str:
    """Render only ``[defaults.*]`` tables for split layout."""
    lines: list[str] = []
    _emit_defaults(lines, reg)
    if not lines:
        return '# No AIVM defaults are configured yet.\n'
    return '\n'.join(lines).rstrip() + '\n'


def render_store_networks_toml(reg: Store) -> str:
    """Render only ``[[networks]]`` records for split layout."""
    lines: list[str] = []
    for net in sorted(reg.networks, key=lambda n: n.name):
        lines.append('[[networks]]')
        lines.append(f'name = "{_toml_escape(net.name)}"')
        net_d = asdict(net.network)
        lines.append('[networks.network]')
        for k, v in net_d.items():
            if k == 'name':
                continue
            _emit_toml_kv(lines, k, v)
        fw_d = asdict(net.firewall)
        lines.append('[networks.firewall]')
        for k, v in fw_d.items():
            _emit_toml_kv(lines, k, v)
        lines.append('')
    if not lines:
        return '# No AIVM networks are configured yet.\n'
    return '\n'.join(lines).rstrip() + '\n'


def render_store_vm_toml(reg: Store, vm_name: str) -> str:
    """Render one ``[[vms]]`` record plus nested attachments.

    This is the fragment format used by ``vms/{vm_name}.toml``.  Parsed alone,
    it is a list with one VM; concatenated with root/network fragments, it is a
    normal canonical AIVM desired-state document.
    """
    matches = [vm for vm in reg.vms if vm.name == vm_name]
    if not matches:
        raise KeyError(f'VM not found in store: {vm_name}')
    vm = matches[0]
    lines: list[str] = []
    lines.append('[[vms]]')
    lines.append(f'name = "{_toml_escape(vm.name)}"')
    lines.append(f'network_name = "{_toml_escape(vm.network_name)}"')
    d = asdict(vm.cfg)
    verbosity = int(d.get('verbosity', 1))
    if verbosity != 1:
        lines.append(f'verbosity = {verbosity}')
    for section in ('vm', 'image', 'provision', 'paths', 'virtiofs'):
        body = d.get(section, {})
        if not isinstance(body, dict):
            continue
        lines.append(f'[vms.{section}]')
        for k, v in _section_items(reg, section, body):
            _emit_toml_kv(lines, k, v)

    nested = sorted(
        (att for att in reg.attachments if att.vm_name == vm.name),
        key=lambda a: (a.host_path, a.guest_dst, a.tag),
    )
    for att in nested:
        lines.append('[[vms.attachments]]')
        _emit_attachment(lines, att, include_vm_name=False)
    nested_creds = sorted(
        (cred for cred in reg.credentials if cred.vm_name == vm.name),
        key=lambda cred: cred.id,
    )
    for cred in nested_creds:
        lines.append('[[vms.credentials]]')
        _emit_credential(lines, cred)
    nested_principals = sorted(
        (item for item in reg.principals if item.vm_name == vm.name),
        key=lambda item: (item.host_user, item.id),
    )
    for principal in nested_principals:
        lines.append('[[vms.principals]]')
        _emit_principal(lines, principal)
    lines.append('')
    return '\n'.join(lines).rstrip() + '\n'
