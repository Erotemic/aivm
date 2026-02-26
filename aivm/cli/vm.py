from __future__ import annotations

from ._common import *  # noqa: F401,F403

class VMUpCLI(_BaseCommand):
    """Create the VM if needed, or start it if already defined."""

    recreate = scfg.Value(False, isflag=True, help="Destroy and recreate if it exists.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg, cfg_path = _load_cfg_with_path(args.config)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose=f"Create/start/redefine VM '{cfg.vm.name}' and libvirt resources.",
        )
        create_or_start_vm(cfg, dry_run=args.dry_run, recreate=args.recreate)
        if not args.dry_run:
            _record_vm(cfg, cfg_path)
        return 0

class VMWaitIPCLI(_BaseCommand):
    """Wait for and print the VM IPv4 address."""

    timeout = scfg.Value(360, type=int, help="Timeout seconds.")
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose="Query VM networking state via virsh to resolve VM IP.",
        )
        print(
            wait_for_ip(
                _load_cfg(args.config), timeout_s=args.timeout, dry_run=args.dry_run
            )
        )
        return 0

class VMStatusCLI(_BaseCommand):
    """Show VM lifecycle status and cached IP information."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(yes=bool(args.yes), purpose="Inspect VM state via virsh.")
        print(vm_status(_load_cfg(args.config)))
        return 0

class VMDestroyCLI(_BaseCommand):
    """Destroy and undefine the VM and associated storage."""

    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        _confirm_sudo_block(
            yes=bool(args.yes), purpose="Destroy/undefine VM and attached storage."
        )
        destroy_vm(_load_cfg(args.config), dry_run=args.dry_run)
        return 0

class VMSshConfigCLI(_BaseCommand):
    """Print an SSH config stanza for easy VM access."""

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        print(mk_ssh_config(_load_cfg(args.config)))
        return 0

class VMProvisionCLI(_BaseCommand):
    """Provision the VM with optional developer packages."""

    vm = scfg.Value(
        "",
        help="Optional VM name override when no local config file is present.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        if args.config is not None or _cfg_path(None).exists():
            cfg = _load_cfg(args.config)
        else:
            cfg, _ = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt=args.vm,
                host_src=Path.cwd(),
            )
        _confirm_sudo_block(
            yes=bool(args.yes),
            purpose="Query VM networking state before SSH provisioning.",
        )
        provision(cfg, dry_run=args.dry_run)
        return 0

class VMSyncSettingsCLI(_BaseCommand):
    """Copy host user settings/files into the VM user home."""

    paths = scfg.Value(
        "",
        help=(
            "Optional comma-separated host paths to sync. "
            "Defaults to [sync].paths from config."
        ),
    )
    overwrite = scfg.Value(
        True,
        isflag=True,
        help="Overwrite existing files in VM (default true).",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        cfg = _load_cfg(args.config)
        if args.dry_run:
            ip = "0.0.0.0"
        else:
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose="Query VM networking state before settings sync.",
            )
            ip = get_ip_cached(cfg) or wait_for_ip(cfg, timeout_s=360, dry_run=False)
            wait_for_ssh(cfg, ip, timeout_s=300, dry_run=False)
        chosen_paths = _parse_sync_paths_arg(args.paths) if args.paths else None
        result = sync_settings(
            cfg,
            ip,
            paths=chosen_paths,
            overwrite=bool(args.overwrite),
            dry_run=args.dry_run,
        )
        print("🧩 Settings sync summary")
        print(f"  copied: {len(result.copied)}")
        print(f"  skipped_missing: {len(result.skipped_missing)}")
        print(f"  skipped_exists: {len(result.skipped_exists)}")
        print(f"  failed: {len(result.failed)}")
        for k in ("copied", "skipped_missing", "skipped_exists", "failed"):
            for item in getattr(result, k):
                print(f"  - {k}: {item}")
        if result.failed:
            return 2
        return 0

class VMCodeCLI(_BaseCommand):
    """Open a host project folder in VS Code attached to the VM via Remote-SSH."""

    host_src = scfg.Value(
        ".",
        help="Host project directory to share and open (default: current directory).",
    )
    vm = scfg.Value(
        "",
        help="VM name override for selecting config from global registry.",
    )
    guest_dst = scfg.Value(
        "",
        help="Guest mount path override (default: config share.guest_dst).",
    )
    recreate_if_needed = scfg.Value(
        False,
        isflag=True,
        help="Recreate VM if existing definition lacks the requested share mapping.",
    )
    ensure_firewall = scfg.Value(
        True,
        isflag=True,
        help="Apply firewall rules when firewall.enabled=true.",
    )
    sync_settings = scfg.Value(
        False,
        isflag=True,
        help="Sync host settings files into VM before launching VS Code.",
    )
    sync_paths = scfg.Value(
        "",
        help=(
            "Optional comma-separated paths used when --sync_settings is set. "
            "Defaults to [sync].paths."
        ),
    )
    force = scfg.Value(
        False,
        isflag=True,
        help="Force attaching folder even if already attached to a different VM.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        session = _prepare_attached_session(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=Path(args.host_src).resolve(),
            guest_dst_opt=args.guest_dst,
            recreate_if_needed=bool(args.recreate_if_needed),
            ensure_firewall_opt=bool(args.ensure_firewall),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )
        cfg = session.cfg
        if args.dry_run:
            print(f"DRYRUN: would open {cfg.share.guest_dst} in VS Code via host {cfg.vm.name}")
            return 0
        ip = session.ip
        assert ip is not None

        do_sync = bool(args.sync_settings or cfg.sync.enabled)
        if do_sync:
            chosen_paths = (
                _parse_sync_paths_arg(args.sync_paths) if args.sync_paths else None
            )
            sync_result = sync_settings(
                cfg,
                ip,
                paths=chosen_paths,
                overwrite=cfg.sync.overwrite,
                dry_run=False,
            )
            if sync_result.failed:
                raise RuntimeError(
                    "Failed syncing one or more settings files:\n"
                    + "\n".join(sync_result.failed)
                )

        ssh_cfg = _upsert_ssh_config_entry(cfg, dry_run=False)

        if which("code") is None:
            raise RuntimeError(
                "VS Code CLI `code` not found in PATH. Install VS Code and enable the shell command."
            )
        remote_target = f"ssh-remote+{cfg.vm.name}"
        run_cmd(
            ["code", "--remote", remote_target, cfg.share.guest_dst],
            sudo=False,
            check=True,
            capture=False,
        )
        print(
            f"Opened VS Code remote folder {cfg.share.guest_dst} on host {cfg.vm.name}"
        )
        print(f"SSH entry updated in {ssh_cfg}")
        print(f"Folder registered in {session.reg_path} and {session.meta_path}")
        return 0

class VMSSHCLI(_BaseCommand):
    """SSH into the VM and start a shell in the mapped guest directory."""

    host_src = scfg.Value(
        ".",
        help="Host project directory to share and open (default: current directory).",
    )
    vm = scfg.Value(
        "",
        help="VM name override for selecting config from global registry.",
    )
    guest_dst = scfg.Value(
        "",
        help="Guest mount path override (default: mirrors host_src path).",
    )
    recreate_if_needed = scfg.Value(
        False,
        isflag=True,
        help="Recreate VM if existing definition lacks the requested share mapping.",
    )
    ensure_firewall = scfg.Value(
        True,
        isflag=True,
        help="Apply firewall rules when firewall.enabled=true.",
    )
    force = scfg.Value(
        False,
        isflag=True,
        help="Force attaching folder even if already attached to a different VM.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        session = _prepare_attached_session(
            config_opt=args.config,
            vm_opt=args.vm,
            host_src=Path(args.host_src).resolve(),
            guest_dst_opt=args.guest_dst,
            recreate_if_needed=bool(args.recreate_if_needed),
            ensure_firewall_opt=bool(args.ensure_firewall),
            force=bool(args.force),
            dry_run=bool(args.dry_run),
            yes=bool(args.yes),
        )
        cfg = session.cfg
        if args.dry_run:
            print(f"DRYRUN: would SSH to {cfg.vm.user}@<ip> and cd {cfg.share.guest_dst}")
            return 0

        ip = session.ip
        assert ip is not None
        ident = require_ssh_identity(cfg.paths.ssh_identity_file)
        remote_cmd = f"cd {shlex.quote(cfg.share.guest_dst)} && exec $SHELL -l"
        run_cmd(
            [
                "ssh",
                "-t",
                *ssh_base_args(ident, strict_host_key_checking="accept-new"),
                f"{cfg.vm.user}@{ip}",
                remote_cmd,
            ],
            sudo=False,
            check=True,
            capture=False,
        )
        print(f"Connected to {cfg.vm.user}@{ip} in {cfg.share.guest_dst}")
        print(f"Folder registered in {session.reg_path} and {session.meta_path}")
        return 0

class VMAttachCLI(_BaseCommand):
    """Attach/register a host directory to an existing managed VM."""

    vm = scfg.Value("", help="Optional VM name in global registry.")
    host_src = scfg.Value(".", help="Host directory to attach.")
    guest_dst = scfg.Value("", help="Guest mount path override.")
    force = scfg.Value(
        False,
        isflag=True,
        help="Allow attaching folder that is already attached to a different VM.",
    )
    dry_run = scfg.Value(False, isflag=True, help="Print actions without running.")

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        host_src = Path(args.host_src).resolve()
        if not host_src.exists() or not host_src.is_dir():
            raise RuntimeError(f"host_src must be an existing directory: {host_src}")

        if args.config:
            cfg, cfg_path = _load_cfg_with_path(args.config)
        elif args.vm:
            cfg, cfg_path = _select_cfg_for_vm_name(args.vm, reason="--vm")
        else:
            cfg, cfg_path = _resolve_cfg_for_code(
                config_opt=None,
                vm_opt="",
                host_src=host_src,
            )

        cfg.share.enabled = True
        cfg.share.host_src = str(host_src)
        cfg.share.guest_dst = _resolve_guest_dst(host_src, args.guest_dst)
        _ensure_share_tag_len(cfg, host_src, set())

        if args.dry_run:
            print(
                f"DRYRUN: would attach {host_src} to VM {cfg.vm.name} at {cfg.share.guest_dst}"
            )
            return 0

        save(cfg_path, cfg)
        if vm_exists(cfg):
            _confirm_sudo_block(
                yes=bool(args.yes),
                purpose=f"Inspect VM '{cfg.vm.name}' share mappings and attach folder if needed.",
            )
            mappings = vm_share_mappings(cfg)
            requested_src = str(Path(cfg.share.host_src).resolve())
            existing_tags = {tag for _, tag in mappings if tag}
            _ensure_share_tag_len(cfg, host_src, existing_tags)
            for src, tag in mappings:
                if src == requested_src and tag:
                    cfg.share.tag = tag
                    break
            if not vm_has_share(cfg):
                for src, tag in mappings:
                    if tag == cfg.share.tag and src != requested_src:
                        cfg.share.tag = _auto_share_tag_for_path(
                            host_src, existing_tags
                        )
                        break
                if not vm_has_share(cfg):
                    attach_vm_share(cfg, dry_run=False)
                    save(cfg_path, cfg)
        reg_path, meta_path = _record_attachment(
            cfg,
            cfg_path,
            host_src=host_src,
            force=bool(args.force),
        )
        print(f"Attached {host_src} to VM {cfg.vm.name} (shared mode)")
        print(f"Updated config: {cfg_path}")
        print(f"Updated registry: {reg_path}")
        print(f"Updated directory metadata: {meta_path}")
        return 0

class VMListCLI(_BaseCommand):
    """List managed VM records (VM-focused view)."""

    section = scfg.Value(
        "vms",
        help="One of: all, vms, networks, folders (default: vms).",
    )

    @classmethod
    def main(cls, argv=True, **kwargs):
        args = cls.cli(argv=argv, data=kwargs)
        from .main import ListCLI

        return ListCLI.main(argv=False, section=args.section, config=args.config)

class CodeCLI(VMCodeCLI):
    """Top-level shortcut for `aivm vm code`."""

class AttachCLI(VMAttachCLI):
    """Top-level shortcut for `aivm vm attach`."""

class SSHCLI(VMSSHCLI):
    """Top-level shortcut for `aivm vm ssh`."""

class VMModalCLI(scfg.ModalCLI):
    """VM lifecycle subcommands."""

    list = VMListCLI
    up = VMUpCLI
    wait_ip = VMWaitIPCLI
    status = VMStatusCLI
    destroy = VMDestroyCLI
    ssh_config = VMSshConfigCLI
    provision = VMProvisionCLI
    ssh = VMSSHCLI
    sync_settings = VMSyncSettingsCLI
    attach = VMAttachCLI
    code = VMCodeCLI
