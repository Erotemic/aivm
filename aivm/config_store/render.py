"""Render the logical AIVM config store model as TOML."""

from __future__ import annotations

from dataclasses import asdict

from .models import Store


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


def render_store_toml(reg: Store) -> str:
    """Render a Store using the legacy monolithic attachment layout."""
    lines: list[str] = [f'schema_version = {reg.schema_version}']
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
        'mirror_shared_home_folders',
        bool(reg.behavior.mirror_shared_home_folders),
    )
    lines.append('')

    if reg.defaults is not None:
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
            for k, v in body.items():
                _emit_toml_kv(lines, k, v)
            lines.append('')

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
            for k, v in body.items():
                _emit_toml_kv(lines, k, v)
        lines.append('')

    for att in sorted(reg.attachments, key=lambda a: (a.host_path, a.vm_name)):
        lines.append('[[attachments]]')
        lines.append(f'host_path = "{_toml_escape(att.host_path)}"')
        lines.append(f'vm_name = "{_toml_escape(att.vm_name)}"')
        lines.append(f'mode = "{_toml_escape(att.mode)}"')
        lines.append(f'access = "{_toml_escape(att.access)}"')
        lines.append(f'guest_dst = "{_toml_escape(att.guest_dst)}"')
        lines.append(f'tag = "{_toml_escape(att.tag)}"')
        if att.host_lexical_path:
            lines.append(
                f'host_lexical_path = "{_toml_escape(att.host_lexical_path)}"'
            )
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'
