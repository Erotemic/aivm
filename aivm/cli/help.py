"""CLI help and command-tree rendering utilities."""

from __future__ import annotations

import textwrap

import scriptconfig as scfg

from ._common import _BaseCommand, _cfg_path


class PlanCLI(_BaseCommand):
    """Show the recommended end-to-end setup command sequence."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        path = _cfg_path(args.config)
        steps = textwrap.dedent(f"""
        🗺️  AgentVM Plan
        📄 Config: {path}

        Suggested flow:

        1. 🔎 Preflight checks
           aivm host doctor --config {path}
           aivm status --config {path}
           aivm status --config {path} --detail
        2. 🌐 Host network
           aivm host net create --config {path}
        3. 🔥 Optional firewall isolation (recommended)
           aivm host fw apply --config {path}
        4. 📦 Base image
           aivm host image_fetch --config {path}
        5. 🖥️ VM lifecycle
           aivm vm up --config {path}
           aivm vm wait_ip --config {path}
        6. 🔑 Access
           aivm vm ssh_config --config {path}   # VS Code Remote-SSH
        7. 🧰 Optional provisioning (docker + dev tools)
           aivm vm provision --config {path}
        8. 🧩 Optional settings sync from host user profile
           aivm vm sync_settings --config {path}
        9. 🧑‍💻 Optional VS Code one-shot open (share + remote launch)
           aivm vm code --config {path} --host_src . --sync_settings
        """).strip()
        print(steps)
        return 0


class HelpTreeCLI(_BaseCommand):
    """Print the expanded aivm command tree."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        cls.cli(argv=argv, data=kwargs)
        from .main import AgentVMModalCLI

        print(_render_command_tree(AgentVMModalCLI))
        return 0


class HelpModalCLI(scfg.ModalCLI):
    """Help and discovery commands."""

    plan = PlanCLI
    tree = HelpTreeCLI


def _iter_modal_members(
    modal_cls: type[scfg.ModalCLI],
) -> list[tuple[str, type]]:
    members: list[tuple[str, type]] = []
    for name, val in modal_cls.__dict__.items():
        if name.startswith('_'):
            continue
        if not isinstance(val, type):
            continue
        if issubclass(val, scfg.ModalCLI) or issubclass(val, scfg.DataConfig):
            members.append((name, val))
    return members


def _short_help_line(cls: type) -> str:
    doc = (getattr(cls, '__doc__', '') or '').strip()
    if not doc:
        return ''
    return doc.splitlines()[0].strip()


def _render_command_tree(
    modal_cls: type[scfg.ModalCLI], prefix: str = 'aivm'
) -> str:
    root_help = _short_help_line(modal_cls)
    root_line = f'{prefix} - {root_help}' if root_help else prefix
    lines: list[str] = [root_line]

    def walk(cls: type[scfg.ModalCLI], parent: str, indent: str) -> None:
        members = _iter_modal_members(cls)
        for idx, (name, subcls) in enumerate(members):
            last = idx == len(members) - 1
            branch = '└── ' if last else '├── '
            path = f'{parent} {name}'
            help_line = _short_help_line(subcls)
            if help_line:
                lines.append(f'{indent}{branch}{path} - {help_line}')
            else:
                lines.append(f'{indent}{branch}{path}')
            if issubclass(subcls, scfg.ModalCLI):
                walk(subcls, path, indent + ('    ' if last else '│   '))

    walk(modal_cls, prefix, '')
    return '\n'.join(lines)
