"""Cloud-init artifact generation for lifecycle operations."""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

from loguru import logger

from ..commands import CommandManager
from ..config import AgentVMConfig
from ..detect import detect_host_timezone
from ..fdguard import (
    FDGUARD_BIN,
    FDGUARD_CONF,
    FDGUARD_SERVICE,
    FDGUARD_TIMER,
    fdguard_conf_text,
    fdguard_python,
    fdguard_service_unit,
    fdguard_timer_unit,
)
from ..persistent_replay import (
    PERSISTENT_ATTACHMENT_REPLAY_BIN,
    PERSISTENT_ATTACHMENT_REPLAY_SERVICE,
    persistent_replay_python,
    persistent_replay_service_unit,
)
from ..privilege import path_needs_sudo
from .host_access import _ensure_qemu_access
from .paths import _paths

log = logger

def _invoking_host_uid_gid() -> tuple[int, int]:
    """Resolve the host UID/GID to bake into the guest user account.

    Prefer the ``SUDO_UID``/``SUDO_GID`` pair only when both values are
    present and numeric. Treat them as an atomic identity pair so a partially
    sanitized sudo environment cannot accidentally combine a human UID with
    root's GID. Fall back to the current process IDs otherwise.
    """
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    if sudo_uid and sudo_uid.isdigit() and sudo_gid and sudo_gid.isdigit():
        return int(sudo_uid), int(sudo_gid)
    return os.getuid(), os.getgid()


def _cloud_init_instance_id_token_path(cfg: AgentVMConfig) -> Path:
    return _paths(cfg, dry_run=False)['state_dir'] / 'instance-id-token'

def _cloud_init_instance_id(cfg: AgentVMConfig) -> str:
    token_path = _cloud_init_instance_id_token_path(cfg)
    token = ''
    try:
        token = token_path.read_text(encoding='utf-8').strip()
    except FileNotFoundError:
        token = ''
    if token:
        return f'{cfg.vm.name}-{token}'
    return cfg.vm.name

def refresh_cloud_init_seed_for_next_boot(
    cfg: AgentVMConfig,
    *,
    dry_run: bool = False,
) -> None:
    """Force the next boot to see refreshed NoCloud instance metadata.

    This is used for stopped-VM persistent-attachment setup where we need the
    guest to replay cloud-init write_files/runcmd on the next boot so helper
    installation is guaranteed before boot-time persistent attachment replay.
    """
    token_path = _cloud_init_instance_id_token_path(cfg)
    if dry_run:
        log.info(
            'DRYRUN: would bump cloud-init instance-id token at {} and rebuild seed ISO',
            token_path,
        )
        return
    mgr = CommandManager.current()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = int(token_path.read_text(encoding='utf-8').strip() or '0')
    except Exception:
        current = 0
    next_token = str(current + 1)
    with mgr.intent(
        'Refresh cloud-init seed for next boot',
        why='Ensure the next boot reruns cloud-init helper installation for persistent attachments on an existing stopped VM.',
        role='modify',
    ):
        with mgr.step(
            'Bump cloud-init instance-id token',
            why='Change the NoCloud instance-id so the next boot replays the updated cloud-init write_files/runcmd payload.',
            approval_scope=f'cloud-init-refresh:{cfg.vm.name}',
        ):
            token_path.write_text(next_token + '\n', encoding='utf-8')
        _write_cloud_init(cfg, dry_run=False)

def _render_user_data_text(cfg: AgentVMConfig, *, pubkey: str) -> str:
    """Render the cloud-init ``user-data`` document for ``cfg``.

    Pure helper: takes config + SSH public key, returns the YAML body.
    All filesystem and command-side effects live in ``_write_cloud_init``.
    """
    ssh_pwauth = 'true' if cfg.vm.allow_password_login else 'false'
    lock_passwd = 'false' if cfg.vm.allow_password_login else 'true'
    passwd_block = ''
    sshd_pw = 'yes' if cfg.vm.allow_password_login else 'no'
    effective_tz = (cfg.vm.timezone or '').strip() or detect_host_timezone()
    timezone_line = (
        f'\n        timezone: {effective_tz}' if effective_tz else ''
    )
    sshd_kbd = 'yes' if cfg.vm.allow_password_login else 'no'

    uid_line = ''
    primary_group_line = ''
    matched_uid_gid_bootcmd = ''
    matched_uid_gid_runcmd = ''
    if cfg.vm.match_host_user_ids:
        host_uid, host_gid = _invoking_host_uid_gid()
        if host_uid != 0:
            uid_line = f'\n            uid: {host_uid}'
        if host_gid != 0:
            # Pre-create a group with the host GID before cloud-init's
            # users-groups module runs, then ask cloud-init to use that
            # numeric GID as the user's primary group. This avoids relying on
            # a post-hoc groupmod repair and prevents useradd from creating an
            # arbitrary guest-private GID. If the GID already exists in the
            # image, useradd can use it directly by number.
            primary_group_line = f'\n            primary_group: "{host_gid}"'
            group_script = (
                'set -eu; '
                f'target_gid={host_gid}; '
                f'group_name={json.dumps(cfg.vm.user)}; '
                'if ! getent group "$target_gid" >/dev/null; then '
                'if getent group "$group_name" >/dev/null; then '
                'groupmod -g "$target_gid" "$group_name"; '
                'else '
                'groupadd -g "$target_gid" "$group_name"; '
                'fi; '
                'fi'
            )
            matched_uid_gid_bootcmd = (
                f'\n          - [bash, -c, {json.dumps(group_script)}]'
            )
        if host_uid != 0:
            chown_owner = (
                f'{host_uid}:{host_gid}' if host_gid != 0 else f'{host_uid}'
            )
            matched_uid_gid_runcmd = (
                f'\n          - [bash, -c, "test -d /home/{cfg.vm.user} '
                f'&& chown -R {chown_owner} /home/{cfg.vm.user} '
                f'|| true"]'
            )

    # Guest-side virtiofs fd guard: keeps the host virtiofsd fd count bounded
    # by pruning virtiofs from updatedb sweeps and flushing guest
    # dentry/inode caches at a watermark. See aivm/fdguard.py.
    fdguard_write_files = ''
    fdguard_runcmd = ''
    if cfg.virtiofs.fd_guard:
        indent14 = ' ' * 14
        fdguard_write_files = (
            f'\n          - path: {FDGUARD_BIN}\n'
            '            permissions: "0755"\n'
            '            content: |\n'
            f'{textwrap.indent(fdguard_python().rstrip(), indent14)}\n'
            f'          - path: {FDGUARD_CONF}\n'
            '            permissions: "0644"\n'
            '            content: |\n'
            f'{textwrap.indent(fdguard_conf_text(cfg.virtiofs.fd_guard_threshold).rstrip(), indent14)}\n'
            f'          - path: /etc/systemd/system/{FDGUARD_SERVICE}\n'
            '            permissions: "0644"\n'
            '            content: |\n'
            f'{textwrap.indent(fdguard_service_unit().rstrip(), indent14)}\n'
            f'          - path: /etc/systemd/system/{FDGUARD_TIMER}\n'
            '            permissions: "0644"\n'
            '            content: |\n'
            f'{textwrap.indent(fdguard_timer_unit(cfg.virtiofs.fd_guard_interval_sec).rstrip(), indent14)}'
        )
        fdguard_runcmd = f'\n          - systemctl enable --now {FDGUARD_TIMER}'

    if cfg.vm.allow_password_login:
        if '\n' in cfg.vm.password:
            raise RuntimeError(
                'VM password must not contain newlines (cloud-init chpasswd format).'
            )
        password_yaml = json.dumps(cfg.vm.password)
        passwd_block = textwrap.dedent(
            f"""\
            chpasswd:
              expire: false
              users:
                - name: {cfg.vm.user}
                  password: {password_yaml}
                  type: text
            """
        )
        passwd_block = textwrap.indent(passwd_block.rstrip('\n'), '        ')

    return textwrap.dedent(
        f"""\
        #cloud-config
        users:
          - name: {cfg.vm.user}{uid_line}{primary_group_line}
            groups: [sudo]
            shell: /bin/bash
            sudo: ["ALL=(ALL) NOPASSWD:ALL"]
            lock_passwd: {lock_passwd}
            ssh_authorized_keys:
              - {pubkey}

        ssh_pwauth: {ssh_pwauth}
        disable_root: true{timezone_line}

{passwd_block}
        # cloud-localds already seeds NoCloud; repeating datasource keys in the
        # user-data blob only triggers cloud-init schema warnings.
        bootcmd:
          - [bash, -c, "systemctl mask systemd-networkd-wait-online.service NetworkManager-wait-online.service || true"]{matched_uid_gid_bootcmd}

        package_update: true
        packages:
          - openssh-server
          - ca-certificates
          - curl
          - git
          - rsync
          - python3
          - python3-venv
          - python3-pip
          - unattended-upgrades

        write_files:
          - path: /etc/ssh/sshd_config.d/99-aivm-hardening.conf
            permissions: "0644"
            content: |
              PasswordAuthentication {sshd_pw}
              PermitRootLogin no
              KbdInteractiveAuthentication {sshd_kbd}
              X11Forwarding no
              AllowTcpForwarding yes
              GatewayPorts no
          - path: {PERSISTENT_ATTACHMENT_REPLAY_BIN}
            permissions: "0755"
            content: |
{textwrap.indent(persistent_replay_python().rstrip(), '              ')}
          - path: /etc/systemd/system/{PERSISTENT_ATTACHMENT_REPLAY_SERVICE}
            permissions: "0644"
            content: |
{textwrap.indent(persistent_replay_service_unit().rstrip(), '              ')}{fdguard_write_files}

        runcmd:
          - systemctl mask --now systemd-networkd-wait-online.service NetworkManager-wait-online.service || true
          - systemctl daemon-reload
          - systemctl enable {PERSISTENT_ATTACHMENT_REPLAY_SERVICE}
          - systemctl enable --now ssh
          - systemctl enable --now unattended-upgrades || true{matched_uid_gid_runcmd}{fdguard_runcmd}
        """
    )


def _write_cloud_init(
    cfg: AgentVMConfig, *, dry_run: bool = False
) -> dict[str, Path]:
    """Render and materialize cloud-init artifacts for a VM definition.

    Returns the host paths of generated artifacts, including the seed ISO used
    by ``virt-install``. The generated config intentionally enables guest sudo
    for agent workflows.
    """
    cfg = cfg.expanded_paths()
    p = _paths(cfg, dry_run=dry_run)
    ci_dir = p['ci_dir']
    user_data = ci_dir / 'user-data'
    meta_data = ci_dir / 'meta-data'
    network_config = ci_dir / 'network-config'
    seed_iso = ci_dir / f'{cfg.vm.name}-seed.iso'

    pubkey_path = (
        Path(cfg.paths.ssh_pubkey_path) if cfg.paths.ssh_pubkey_path else None
    )
    if not pubkey_path or not pubkey_path.exists():
        raise RuntimeError(
            f'Missing SSH public key. Set paths.ssh_pubkey_path in config (got: {cfg.paths.ssh_pubkey_path})'
        )
    pubkey = pubkey_path.read_text(encoding='utf-8').strip()

    cloud = _render_user_data_text(cfg, pubkey=pubkey)

    meta = textwrap.dedent(
        f"""\
        instance-id: {_cloud_init_instance_id(cfg)}
        local-hostname: {cfg.vm.name}
        """
    )
    netcfg = textwrap.dedent(
        """\
        version: 2
        ethernets:
          all-en:
            match:
              name: "en*"
            dhcp4: true
            optional: true
          all-eth:
            match:
              name: "eth*"
            dhcp4: true
            optional: true
        """
    )

    if dry_run:
        log.info(
            'DRYRUN: write cloud-init (+network-config) + cloud-localds {}',
            seed_iso,
        )
        return {
            'user_data': user_data,
            'meta_data': meta_data,
            'network_config': network_config,
            'seed_iso': seed_iso,
        }

    _ensure_qemu_access(cfg, dry_run=False)
    mgr = CommandManager.current()
    use_sudo = path_needs_sudo(ci_dir)
    with mgr.intent(
        'Generate cloud-init artifacts',
        why=(
            'VM creation needs cloud-init user-data, metadata, network config, '
            'and a seed ISO before virt-install can define the guest.'
        ),
        role='modify',
    ):
        with mgr.step(
            'Write cloud-init files and build seed ISO',
            why=(
                'Materialize the rendered cloud-init files on the host and pack '
                'them into a NoCloud seed image for the VM.'
            ),
            approval_scope=f'cloud-init:{cfg.vm.name}',
        ):
            mgr.submit(
                ['mkdir', '-p', str(ci_dir)],
                sudo=use_sudo,
                role='modify',
                check=True,
                capture=True,
                summary='Create cloud-init artifact directory',
            )
            mgr.submit(
                ['bash', '-c', f"cat > {user_data} <<'EOF'\n{cloud}\nEOF"],
                sudo=use_sudo,
                role='modify',
                check=True,
                capture=True,
                summary='Write cloud-init user-data',
            )
            mgr.submit(
                ['bash', '-c', f"cat > {meta_data} <<'EOF'\n{meta}\nEOF"],
                sudo=use_sudo,
                role='modify',
                check=True,
                capture=True,
                summary='Write cloud-init meta-data',
            )
            mgr.submit(
                [
                    'bash',
                    '-c',
                    f"cat > {network_config} <<'EOF'\n{netcfg}\nEOF",
                ],
                sudo=use_sudo,
                role='modify',
                check=True,
                capture=True,
                summary='Write cloud-init network config',
            )
            # libvirt's dynamic-ownership DAC relabeling chowns the seed ISO
            # to libvirt-qemu at domain start, so a rebuild for an existing
            # VM may find it non-user-writable inside a user-owned tree.
            # cloud-localds truncates the target in place; unlinking first
            # only needs directory write, which use_sudo already reflects.
            mgr.submit(
                ['rm', '-f', str(seed_iso)],
                sudo=use_sudo,
                role='modify',
                check=True,
                capture=True,
                summary='Remove stale seed ISO before rebuild',
            )
            mgr.submit(
                [
                    'cloud-localds',
                    '-v',
                    '-N',
                    str(network_config),
                    str(seed_iso),
                    str(user_data),
                    str(meta_data),
                ],
                sudo=use_sudo,
                role='modify',
                check=True,
                capture=True,
                summary='Build NoCloud seed ISO from cloud-init files',
            )
    return {
        'user_data': user_data,
        'meta_data': meta_data,
        'network_config': network_config,
        'seed_iso': seed_iso,
    }
