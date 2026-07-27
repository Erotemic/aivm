# Command approval audit

Generated inventory of every command submission affected by the
"a write is the guard" policy in `docs/source/design.rst`. Purpose is wholesale
review: confirm or correct the **Proposed** column, then the code change is
mechanical.

## How to read this, and how much to trust it

The **Basis** column says *why* a disposition was proposed. It matters more than
the disposition, because the three bases are not equally trustworthy:

- **rule** — a positive match: a known read-only verb inside an inspection
  helper, or a directory creation under an aivm-owned path. Evidence-based.
  Skim these.
- **unsure** (marked **?**) — something matched, but weakly: a read verb in a
  function whose purpose is unclear, or a write that might be bookkeeping.
  **Review these.**
- **default** — nothing matched, so it fell through to `user`. This is *not* a
  judgment that the command writes user-owned state; it is the absence of a
  judgment. **Review these too if you want completeness.**

So the answer to "do I only need to call out the **?** rows" is: those plus the
`default` rows. The `default` rows fail safe — being wrong there costs an
unnecessary prompt rather than a missing one — but they were never recognized,
only assumed. A `default` row that is really a read keeps a prompt it should not
have and stays at `INFO` when it should drop to `--verbose 2`.

## Dispositions

- **read** — inspects only. Declare `role='read'`. No prompt, and the command
  drops to `--verbose 2`. Many of these are undeclared today and default to
  `modify`, which is why they are in this table at all.
- **tool** — a write to aivm's own regenerable bookkeeping. Declare the
  ownership exemption. No prompt.
- **user** — a write to state the user owns, including the guest. Prompts.
  These need no marking; `user` is the default.
- **scrutiny** — unresolved. Written into an aivm-owned directory, but the
  content leaves that directory and becomes guest state. See open questions.

## Totals

| Disposition | Sites |
|---|---|
| read (misclassified today) | 29 |
| tool (exempt, must be declared) | 24 |
| user (prompts) | 91 |
| **total affected** | **144** |

### Basis

| Basis | Sites | Trust |
|---|---|---|
| reviewed (decided by the maintainer) | 28 | settled |
| rule (positive match) | 19 | skim |
| unsure (**?**) | 11 | review |
| default (fell through to `user`) | 86 | review for completeness |

Of the 190 total command submissions in `aivm/`, 46
already declare `role='read'` and are unaffected.

## What changes in the code

1. `CommandSpec` gains an ownership field defaulting to `user`.
2. `_command_needs_approval` returns True for any `modify` whose ownership is
   not `tool`, replacing the `spec.sudo or _is_system_libvirt_mutation(spec)`
   test.
3. `_is_system_libvirt_mutation` is deleted; hypervisor control is subsumed.
4. `test_unprivileged_libvirt_mutation_keeps_approval_contract` encodes the
   overturned rule and is rewritten.
5. Each **read** row below declares `role='read'`; each **tool** row declares
   the exemption. **user** rows change nothing.

## Resolved: cloud-init is `tool`

All six sites meet the bookkeeping bar. `ci_dir` is `base_dir / 'cloud-init'`,
an aivm-owned path. The content is rendered entirely from ``cfg`` by
``_render_user_data_text`` and friends -- password, SSH authorization, network
and timezone all come from config the user already wrote. Nobody hand-edits
``user-data``; deleting the directory and re-running produces identical output.

The earlier worry -- "the artifact becomes the guest" -- does not survive
inspection, because writing the file is not what reaches the guest. At create
time the seed is consumed by ``virt-install``, itself a guarded write. The
artifacts sit inert until something boots a VM with them.

### But the act that reaches the guest is not in this table

``refresh_cloud_init_seed_for_next_boot`` (`aivm/vm/cloudinit.py:70`, called
from `aivm/cli/vm_attach.py:403`) rewrites cloud-init for an **existing** VM and
bumps a NoCloud instance-id so the next boot replays the payload. That bump is
what changes guest state, and it is a bare ``token_path.write_text(...)`` at
`aivm/vm/cloudinit.py:105`, with a ``Path.mkdir`` beside it at line 89.

Neither goes through ``CommandManager``. They are not logged as commands, carry
no role or ownership, and cannot be prompted. The consequential half of the
cloud-init flow is invisible to this policy -- which is why the six audited
commands looked more dangerous than they are, and the real one was not on the
list at all.

## Open question: writes that never reach CommandManager

The policy governs commands. Direct filesystem mutation from Python bypasses it
completely, and there are **38** such call sites across `aivm/` --
``write_text``, ``write_bytes``, ``mkdir``, ``shutil.copy/move/rmtree``,
``os.replace``, ``unlink`` -- concentrated in `config_store/io.py` (14),
`fdguard.py` (4), and `attachments/persistent/transport.py` (4).

Most are legitimately aivm's own state, and `config_store/io.py` writing the
config store is the tool's whole job. But the instance-id bump shows the
category is not uniformly safe, and nothing currently distinguishes them.

Deciding this is separate from the table below and probably wants its own pass.
The options are roughly: route consequential filesystem writes through the
manager so they inherit visibility and approval; or define a narrow rule for
which direct writes are permissible and audit against it the way this table
audits commands.

## Findings this audit surfaced

**Read probes are invalidating the probe cache.** 56 of 190 submissions
declare no role and inherit the `modify` default. `_execute_one` bumps
`mutation_generation` for every `modify`, and probe caches key on that counter,
so a plain `aivm status` invalidates the cache a dozen times over commands that
only report. Declaring these `read` is required by the approval policy anyway;
the cache behaviour is a second reason.

**`aivm status --sudo` is missing read-only auto-approval.** Same cause:
`auto_approve_readonly_sudo` applies only when the effective role is `read`, and
these probes are `modify` by default. Several are sudo probes, so today they
consume approval on a command that only reports.

**Grouping and classification are one backlog.** Almost every undeclared site is
also ungrouped, so this table and the "not grouped into an explicit step"
warning are the same work seen from two directions. Wrapping a call site in
`mgr.step(...)` with `role='read'` settles both.

**The exemption stayed narrow.** Only 24 of 144
affected sites look like genuine aivm-owned bookkeeping, which is a good sign
for the policy's bar: most writes really are to the user's host or the guest.

## Review method

Generated by `dev/devcheck/scan_command_sites.py`, which AST-walks
`aivm/**/*.py` for `.run(...)` / `.submit(...)` calls on a command manager and
records the declared `role`, `sudo`, `check`, `summary`, and any enclosing
`mgr.intent(...)` / `mgr.step(...)` role. Dispositions are then proposed from
the command text and enclosing function name. Regenerate after editing code
rather than hand-maintaining this file.

## Sites

### `aivm/attachments/guest.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 94 | `_ensure_guest_symlink` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |
| 375 | `_git_repo_context` | `['git', '-C', str(host_src), 'rev-parse', '--show-toplevel']` | — | False | no | **read** **?** | unsure | read-only verb; enclosing function unclear |
| 421 | `_upsert_host_git_remote` | `[ 'git', '-C', str(repo_root), 'rev-parse', '--path-format=...` | — | False | no | **read** **?** | unsure | read-only verb; enclosing function unclear |
| 442 | `_upsert_host_git_remote` | `['git', '-C', str(repo_root), 'remote', 'get-url', remote_n...` | — | False | no | **read** **?** | unsure | read-only verb; enclosing function unclear |
| 483 | `_upsert_host_git_remote` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |
| 505 | `_ensure_guest_git_repo` | `[ 'ssh', *ssh_base_args(ident, strict_host_key_checking='ac...` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/attachments/persistent/host_bind.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 75 | `_install_persistent_host_bind_replay` | `['systemctl', 'daemon-reload']` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 82 | `_install_persistent_host_bind_replay` | `['systemctl', 'enable', service_name]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 154 | `_ensure_persistent_root_parent_dir` | `['mkdir', '-p', str(target)]` | modify | path_needs_sudo(target) | yes | **tool** | reviewed | persistent-root export dir under base_dir |
| 218 | `_ensure_persistent_root_host_bind` | `['mkdir', '-p', str(parent)]` | modify | path_needs_sudo(parent) | yes | **tool** | reviewed | bind staging parent under base_dir |
| 226 | `_ensure_persistent_root_host_bind` | `['mkdir', '-p', str(target)]` | modify | path_needs_sudo(target) | yes | **tool** | reviewed | bind staging target under base_dir |
| 233 | `_ensure_persistent_root_host_bind` | `['mount', '--bind', str(source), str(target)]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/attachments/persistent/manifest.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 123 | `_ensure_approved_state_directories` | `['bash', '-c', script]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/attachments/persistent/transport.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 88 | `_install_host_text_if_changed` | `install_dir_cmd` | modify | host_sudo | yes | **user** | default | no read or bookkeeping rule matched |
| 98 | `_install_host_text_if_changed` | `['rm', '-f', '--', str(target)]` | modify | host_sudo | yes | **user** | reviewed | removes an installed host system file |
| 106 | `_install_host_text_if_changed` | `['mkdir', '-p', str(target.parent)]` | modify | host_sudo | yes | **user** | reviewed | installs under host system config, not aivm-owned |
| 119 | `_install_host_text_if_changed` | `install_cmd` | modify | host_sudo | yes | **user** | default | no read or bookkeeping rule matched |
| 278 | `_run_guest_ssh_script_with_retry` | `cmd` | role | False | no | **user** | default | no read or bookkeeping rule matched |
| 331 | `_run_rsync_with_retry` | `cmd` | modify | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/attachments/session.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 529 | `_probe_vm_running_nonsudo` | `virsh_cmd('domstate', vm_name)` | — | False | no | **read** | rule | read-only verb in an inspection helper |

### `aivm/attachments/shared_root.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 91 | `_ensure_shared_root_parent_dir` | `['mkdir', '-p', str(target)]` | modify | path_needs_sudo(target) | yes | **tool** | reviewed | shared-root export parent under base_dir |
| 276 | `_ensure_host_bind_access` | `['mount', '-o', f'remount,bind,{desired}', str(target)]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 399 | `_ensure_shared_root_host_bind` | `['mkdir', '-p', str(parent_dir)]` | modify | path_needs_sudo(parent_dir) | yes | **tool** | reviewed | shared-root bind parent under base_dir |
| 407 | `_ensure_shared_root_host_bind` | `['mkdir', '-p', str(target)]` | modify | path_needs_sudo(target) | yes | **tool** | reviewed | shared-root bind target under base_dir |
| 447 | `_ensure_shared_root_host_bind` | `[ 'bash', '-c', Elided( repair_script, 'stale bind-target r...` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 468 | `_ensure_shared_root_host_bind` | `['mount', '--bind', source_dir, str(target)]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 671 | `_ensure_shared_root_guest_bind` | `mount_cmd` | modify | False | yes | **user** | default | no read or bookkeeping rule matched |
| 685 | `_ensure_shared_root_guest_bind` | `cmd` | modify | False | yes | **user** | default | no read or bookkeeping rule matched |
| 737 | `_detach_shared_root_host_bind` | `['umount', str(target)]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 775 | `_detach_shared_root_host_bind` | `['rmdir', str(target)]` | modify | path_needs_sudo(target.parent) | yes | **user** | default | no read or bookkeeping rule matched |
| 817 | `_detach_shared_root_guest_bind` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/cli/config/discover.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 41 | `main` | `virsh_cmd('list', '--all', '--name')` | — | False | no | **read** **?** | unsure | read-only verb; enclosing function unclear |
| 50 | `main` | `virsh_cmd('list', '--all', '--name')` | — | True | no | **read** **?** | unsure | read-only verb; enclosing function unclear |
| 114 | `_discover_vm_info` | `virsh_cmd('dominfo', vm_name)` | — | use_sudo | no | **read** **?** | unsure | read-only verb; enclosing function unclear |
| 137 | `_discover_vm_info` | `virsh_cmd('dumpxml', vm_name)` | — | use_sudo | no | **read** **?** | unsure | read-only verb; enclosing function unclear |

### `aivm/cli/config/editor.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 47 | `edit_path` | `[*command, str(path)]` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/cli/host_permissions.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 338 | `_adopt_one_tree` | `[ 'bash', '-c', Elided( _adopt_script(tree), f'python progr...` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 727 | `main` | `['usermod', '-aG', LIBVIRT_GROUP, user]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 786 | `main` | `['mkdir', '-p', str(base_dir)]` | modify | False | yes | **tool** | reviewed | creates base_dir itself |
| 795 | `main` | `['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(base_dir)]` | modify | False | yes | **user** | default | no read or bookkeeping rule matched |
| 807 | `main` | `['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(b)]` | modify | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/cli/vm_cache.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 162 | `main` | `cmd` | (modify) | False | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/cli/vm_connect.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 227 | `_start_remote_tunnel_session` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |
| 456 | `main` | `['code', '--remote', remote_target, session.share_guest_dst]` | — | False | no | **user** | default | no read or bookkeeping rule matched |
| 561 | `main` | `[ 'ssh', '-t', *ssh_base_args( ident, strict_host_key_check...` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/cli/vm_guard.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 198 | `main` | `cmd` | ('read' if action == 'status' else 'modify') | False | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/credentials/github.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 415 | `add_deploy_key` | `cmd` | modify | False | no | **user** | default | no read or bookkeeping rule matched |
| 452 | `delete_deploy_key` | `[ 'gh', 'repo', 'deploy-key', 'delete', str(key_id), *_repo...` | modify | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/credentials/guest.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 85 | `_submit_guest` | `_ssh_command(cfg, ip, script)` | 'read' if role == 'read' else 'modify' | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/credentials/keys.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 336 | `generate_host_key` | `['mkdir', '-m', '700', str(vm_directory)]` | modify | — | yes | **tool** | reviewed | aivm credential dir; the mkdir only |
| 342 | `generate_host_key` | `['mkdir', '-m', '700', str(credentials_directory)]` | modify | — | yes | **tool** | reviewed | aivm credential dir; the mkdir only |
| 347 | `generate_host_key` | `['mkdir', '-m', '700', str(directory)]` | modify | — | yes | **tool** | reviewed | aivm credential dir; the mkdir only |
| 356 | `generate_host_key` | `[ 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(...` | modify | — | yes | **user** | default | no read or bookkeeping rule matched |
| 373 | `generate_host_key` | `['chmod', '600', str(private_path)]` | modify | — | yes | **user** | default | no read or bookkeeping rule matched |
| 378 | `generate_host_key` | `['chmod', '644', str(public_path)]` | modify | — | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/credentials/setup.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 357 | `install_missing_credential_tools` | `step.cmd` | modify | step.sudo | yes | **user** | default | no read or bookkeeping rule matched |
| 401 | `authenticate_github` | `cmd` | modify | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/detect.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 106 | `detect_ssh_identity` | `['ssh', '-G', 'unknown@doesnt.exist']` | — | — | no | **user** | default | no read or bookkeeping rule matched |
| 212 | `existing_ipv4_routes` | `['ip', '-4', 'route', 'show']` | — | — | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/firewall.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 255 | `apply_firewall` | `['nft', 'delete', 'table', 'inet', table]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 265 | `apply_firewall` | `['nft', 'delete', 'table', 'inet', legacy]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 281 | `apply_firewall` | `['nft', '-f', '-']` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 336 | `read_firewall_tcp_ports` | `['nft', '--json', 'list', 'table', 'inet', table]` | — | use_sudo | no | **read** | rule | read-only verb in an inspection helper |
| 517 | `remove_firewall` | `['nft', 'delete', 'table', 'inet', table]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 527 | `remove_firewall` | `['nft', 'delete', 'table', 'inet', legacy]` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/host.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 48 | `check_commands_with_sudo` | `['sudo', '-n', 'true']` | — | — | no | **read** | rule | read-only verb in an inspection helper |
| 60 | `check_commands_with_sudo` | `['sudo', '-n', 'sh', '-c', f'command -v {shlex.quote(cmd)}']` | — | — | no | **read** | rule | read-only verb in an inspection helper |
| 172 | `install_deps_debian` | `_debian_noninteractive_cmd('apt-get', 'update', '-y')` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 180 | `install_deps_debian` | `_debian_apt_install_cmd(*pkgs)` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 190 | `install_deps_debian` | `_debian_apt_install_cmd('virtiofsd')` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |
| 199 | `install_deps_debian` | `['systemctl', 'enable', '--now', 'libvirtd']` | modify | True | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/net.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 31 | `_route_overlap` | `['ip', '-4', 'route', 'show']` | — | — | no | **user** | default | no read or bookkeeping rule matched |
| 139 | `ensure_network` | `virsh_cmd('net-destroy', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 147 | `ensure_network` | `virsh_cmd('net-undefine', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 155 | `ensure_network` | `virsh_cmd('net-define', tmp)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 164 | `ensure_network` | `virsh_cmd('net-autostart', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 172 | `ensure_network` | `virsh_cmd('net-start', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 211 | `destroy_network` | `virsh_cmd('net-destroy', name)` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 218 | `destroy_network` | `virsh_cmd('net-undefine', name)` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/services.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 156 | `maybe_offer_create_ssh_identity` | `['mkdir', '-p', str(default_priv.parent)]` | modify | False | yes | **user** | reviewed | creates the user's ~/.ssh; not aivm-owned |
| 163 | `maybe_offer_create_ssh_identity` | `['chmod', '700', str(default_priv.parent)]` | modify | False | yes | **user** | default | no read or bookkeeping rule matched |
| 170 | `maybe_offer_create_ssh_identity` | `[ 'ssh-keygen', '-q', '-t', 'ed25519', '-f', str(default_pr...` | modify | False | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/status.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 179 | `probe_runtime_environment` | `['systemd-detect-virt']` | — | False | no | **read** | rule | status reporting; inspects only |
| 265 | `probe_network` | `virsh_cmd('net-info', cfg.network.name)` | — | use_sudo and virsh_needs_sudo() | no | **read** | rule | status reporting; inspects only |
| 344 | `probe_firewall` | `['nft', 'list', 'table', 'inet', effective_firewall_table(c...` | — | use_sudo | no | **read** | rule | status reporting; inspects only |
| 394 | `probe_vm_state` | `dominfo_cmd` | — | False | no | **read** | rule | status reporting; inspects only |
| 410 | `probe_vm_state` | `dominfo_cmd` | — | True | no | **read** | rule | status reporting; inspects only |
| 447 | `probe_vm_state` | `domstate_cmd` | — | sudo_used | no | **read** | rule | status reporting; inspects only |
| 489 | `probe_ssh_ready` | `cmd` | — | False | no | **read** | rule | status reporting; inspects only |
| 560 | `probe_provisioned` | `cmd` | — | False | no | **read** | rule | status reporting; inspects only |
| 665 | `render_status` | `['test', '-f', str(base_img)]` | — | True | no | **read** | rule | status reporting; inspects only |
| 843 | `render_status` | `virsh_cmd('net-dumpxml', cfg.network.name)` | — | use_sudo and virsh_needs_sudo() | no | **read** | rule | status reporting; inspects only |
| 869 | `render_status` | `['ls', '-lh', str(base_img)]` | — | use_sudo and sudo_allowed() | no | **read** | rule | status reporting; inspects only |
| 894 | `render_status` | `cmd` | — | use_sudo and virsh_needs_sudo() | no | **read** | rule | status reporting; inspects only |

### `aivm/vm/cloudinit.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 362 | `_write_cloud_init` | `['mkdir', '-p', str(ci_dir)]` | modify | use_sudo | yes | **tool** | reviewed | ci_dir under base_dir; regenerated from config |
| 370 | `_write_cloud_init` | `[ 'bash', '-c', Elided( f"cat > {user_data} <<'EOF'\n{cloud...` | modify | use_sudo | yes | **tool** | reviewed | user-data rendered entirely from cfg |
| 385 | `_write_cloud_init` | `['bash', '-c', f"cat > {meta_data} <<'EOF'\n{meta}\nEOF"]` | modify | use_sudo | yes | **tool** | reviewed | meta-data rendered entirely from cfg |
| 393 | `_write_cloud_init` | `[ 'bash', '-c', f"cat > {network_config} <<'EOF'\n{netcfg}\...` | modify | use_sudo | yes | **tool** | reviewed | network-config rendered entirely from cfg |
| 410 | `_write_cloud_init` | `['rm', '-f', str(seed_iso)]` | modify | use_sudo | yes | **tool** | reviewed | removes the seed ISO before rebuilding it |
| 418 | `_write_cloud_init` | `[ 'cloud-localds', '-v', '-N', str(network_config), str(see...` | modify | use_sudo | yes | **tool** | reviewed | rebuilds the seed ISO from the files above |

### `aivm/vm/connectivity.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 300 | `wait_for_ssh` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/create.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 256 | `create_or_start_vm` | `virsh_cmd('resume', cfg.vm.name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 277 | `create_or_start_vm` | `virsh_cmd('start', cfg.vm.name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 335 | `create_or_start_vm` | `cmd` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 368 | `create_or_start_vm` | `cmd_no_uefi` | (modify) | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/disk.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 35 | `_ensure_disk` | `['rm', '-f', str(vm_disk)]` | — | use_sudo | no | **user** | reviewed | removes the VM disk; destroys guest data |
| 50 | `_ensure_disk` | `[ 'qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',...` | — | use_sudo | no | **user** | reviewed | qemu-img create makes the VM disk; not a read, not regenerable |

### `aivm/vm/domain.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 51 | `_destroy_and_undefine_vm` | `virsh_cmd('destroy', name)` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 82 | `_destroy_and_undefine_vm` | `cmd` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 253 | `shutdown_vm` | `virsh_cmd('resume', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 286 | `shutdown_vm` | `virsh_cmd('shutdown', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 342 | `restart_vm` | `virsh_cmd('resume', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 378 | `restart_vm` | `virsh_cmd('shutdown', name)` | modify | virsh_needs_sudo() | yes | **user** | default | no read or bookkeeping rule matched |
| 414 | `_start_vm` | `virsh_cmd('start', name)` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/drift.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 209 | `read_actual_vm_hardware` | `cmd` | — | use_sudo and virsh_needs_sudo() | no | **read** **?** | unsure | unchecked call in an inspection helper |

### `aivm/vm/host_access.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 129 | `_submit_qemu_dir_prepare` | `['mkdir', '-p', str(path)]` | modify | True | no | **tool** | reviewed | qemu-access dir under base_dir |
| 137 | `_submit_qemu_dir_prepare` | `['chown', *(['-R'] if recursive else []), f'root:{group}', ...` | modify | True | no | **user** | default | no read or bookkeeping rule matched |
| 145 | `_submit_qemu_dir_prepare` | `['chmod', mode, str(path)]` | modify | True | no | **user** | default | no read or bookkeeping rule matched |
| 191 | `_ensure_qemu_access_unprivileged` | `['mkdir', '-p', str(d)]` | modify | False | yes | **tool** | reviewed | qemu-access dir under base_dir |
| 232 | `_ensure_qemu_access_unprivileged` | `['setfacl', '-m', f'u:{LIBVIRT_QEMU_USER}:x', str(d)]` | modify | False | yes | **user** | default | no read or bookkeeping rule matched |
| 271 | `_ensure_qemu_access` | `['getent', 'group', 'libvirt-qemu']` | — | — | no | **read** **?** | unsure | read-only verb; enclosing function unclear |

### `aivm/vm/images.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 83 | `_resolve_expected_image_sha256` | `['sha256sum', str(file_path)]` | — | — | no | **read** | rule | read-only verb in an inspection helper |
| 141 | `_verify_image_sha256` | `['rm', '-f', str(image_path)]` | modify | path_needs_sudo(image_path) | no | **tool** | reviewed | removes a checksum-failed cached image; refetchable |
| 263 | `fetch_image` | `['mkdir', '-p', str(p['img_dir'])]` | modify | use_sudo | yes | **tool** | reviewed | image cache dir under base_dir |
| 272 | `fetch_image` | `['rm', '-f', str(tmp_img)]` | modify | use_sudo | yes | **tool** | reviewed | removes the download temp file |
| 294 | `fetch_image` | `transfer_cmd` | modify | use_sudo | yes | **tool** **?** | unsure | base-image cache; regenerable by redownload |
| 311 | `fetch_image` | `['mv', '-f', str(tmp_img), str(base_img)]` | modify | use_sudo | yes | **tool** **?** | unsure | base-image cache; regenerable by redownload |
| 348 | `fetch_image` | `['rm', '-f', str(base_img)]` | modify | use_sudo | yes | **tool** | reviewed | removes a stale cached base image; refetchable |

### `aivm/vm/provision.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 85 | `provision` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/share.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 428 | `attach_vm_share` | `attach_cmd` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 526 | `detach_vm_share` | `detach_cmd` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 594 | `ensure_share_mounted` | `cmd` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/update/apply.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 72 | `_apply_vm_update` | `max_cmd` | — | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 73 | `_apply_vm_update` | `cmd` | — | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 92 | `_apply_vm_update` | `max_cmd` | — | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 93 | `_apply_vm_update` | `mem_cmd` | — | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
| 112 | `_apply_vm_update` | `cmd` | — | file_write_needs_sudo(drift.disk_path) | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/update/detect.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 34 | `_resolve_vm_disk_path` | `virsh_cmd('dumpxml', cfg.vm.name)` | — | use_sudo and virsh_needs_sudo() | no | **read** | rule | read-only verb in an inspection helper |
| 57 | `_qemu_img_virtual_size_bytes` | `['qemu-img', 'info', '--output=json', str(path)]` | — | use_sudo and sudo_allowed() | no | **read** | reviewed | qemu-img info inspects only |
| 72 | `_virsh_domblk_capacity_bytes` | `virsh_cmd('domblkinfo', cfg.vm.name, path_or_target)` | — | use_sudo and virsh_needs_sudo() | no | **read** | rule | read-only verb in an inspection helper |

### `aivm/vm/update/fdguard.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 78 | `_fdguard_drift` | `_guest_ssh_cmd( cfg, ip, fdguard_probe_script(), label='vir...` | — | False | no | **user** | default | no read or bookkeeping rule matched |
| 202 | `_apply_fdguard_drift` | `_guest_ssh_cmd( cfg, ip, script, label=( f'virtiofs guard {...` | — | False | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/update/restart.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 68 | `_maybe_restart_vm_after_update` | `cmd` | — | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |

### `aivm/vm/update/virtiofs.py`

| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |
|---|---|---|---|---|---|---|---|---|
| 154 | `_apply_virtiofs_binary_drift` | `virsh_cmd('define', tmp)` | modify | virsh_needs_sudo() | no | **user** | default | no read or bookkeeping rule matched |
