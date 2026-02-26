from __future__ import annotations

from ._common import *  # noqa: F401,F403

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
