# Deferred: the rootless `qemu:///session` runtime

Status: **implemented, then removed before release.** Blocked on
externally-managed virtiofsd.

| | |
|---|---|
| Added in | `cd3886f` — *"Add the rootless session runtime (qemu:///session) as a first-class mode"* |
| Removed in | `190ed83` — *"Remove the rootless qemu:///session runtime"* |
| Design docs | `dev/design/future/rootless-vms.md`, `dev/design/future/external-virtiofsd.md` |
| Never shipped | Correct. `cd3886f` landed on the unmerged `dev/sudoless` branch. No released version of `aivm` ever exposed it. |

## What it was

A second *runtime* axis, orthogonal to `behavior.privilege_mode`. Where
privilege mode governs **how aivm escalates**, `runtime.mode` governed
**which libvirt daemon a VM lives on**:

- `system` (default): the root system daemon, `qemu:///system`. Managed NAT
  network, storage under `/var/lib/libvirt/aivm`, optional nftables
  firewall, QEMU running as `libvirt-qemu`.
- `session`: the per-user daemon, `qemu:///session`. User-owned storage
  under `~/.local/share/aivm`, user-mode [passt](https://passt.top)
  networking with guest SSH forwarded to a persisted localhost port, no
  managed network, no firewall, QEMU running as the invoking user.

It was reachable through `aivm host rootless check` / `aivm host rootless
setup`, which added the user to the `kvm` group and persisted
`defaults.runtime.mode = "session"`.

## Why we did not move forward

**It cannot share folders.** libvirt owns the `virtiofsd` invocation for
every `<filesystem type='mount'>` device. Under `qemu:///session` there is no
privileged daemon to spawn it, so session VMs supported only `--mode git`
attachments. Since `aivm code .` is the tool's primary command and git-mode
sync is reserved for repositories whose contents must not reach the guest,
a session VM could not do the main job. Worse, the code *silently* fell back
to git mode when no `--mode` was given, so a user got a git clone and no
error.

**It is not the safer option, despite the name.** Under `qemu:///system`,
QEMU runs as the dedicated `libvirt-qemu` user. Under `qemu:///session`,
QEMU runs as **you**. For a tool whose purpose is isolating an AI coding
agent from the host, that inverts the guarantee being sold: a hypervisor
escape from a session VM lands with the invoking user's UID, SSH keys, and
source tree. "Rootless" buys *aivm needs no root* and pays for it in *escape
containment*. The removed `docs/source/runtimes.rst` described it as "the
strongest host-privilege posture," which was misleading.

**Its niche is already covered.** The stated goal in `rootless-vms.md` was
"no host sudo in normal create/start/stop/status/ssh/code paths." The system
runtime plus `libvirt` group membership plus `privilege_mode = "auto"`
already achieves that: `virsh` reaches `qemu:///system` unprivileged via the
polkit rule, a user-owned `base_dir` removes storage escalation, and an
already-established attachment reconciles with zero privileged commands.
Sudo remains only for `nft`, `apt-get`, and establishing a *new*
`mount --bind` — none of which the session runtime could do either.

**It taxed everything else.** 25 `runtime_is_session()` branches across nine
modules, each a fork in reasoning for a feature nobody could use, sitting in
exactly the modules (`status.py`, `host_access.py`, `attachments/resolve.py`)
that ongoing privilege work needs to touch.

## What would unblock it

`dev/design/future/external-virtiofsd.md` (design ready, not started). Run
`virtiofsd` outside libvirt as a per-share user systemd service and connect
it to the guest with libvirt's external-socket form:

```xml
<filesystem type='mount'>
  <driver type='virtiofs' queue='1024'/>
  <source socket='/run/user/1000/aivm/<vm>/<tag>.sock'/>
  <target dir='<tag>'/>
</filesystem>
```

That design lists "rootless `shared` attachments are blocked" as limitation 3
of the 3 it fixes. Note that limitations 1 and 2 — the EMFILE fd-retention
root cause, and the inability to restart a wedged virtiofsd without a VM
restart — apply to the **system** runtime too. So external-virtiofsd is worth
doing on its own merits, and session viability falls out of it downstream.

Even then, the UID/escape-containment trade above does not go away. Session
mode should return as a deliberate per-VM opt-in (`aivm vm create --runtime
session`) for hosts where the `libvirt` group is unobtainable — never as a
global default, and never as the recommended posture.

## Resurrecting it

The code is intact at `cd3886f` and its successors. A `git revert` of the
removal will **not** apply cleanly: the branch has since grown an
application-services layer (`aa0a0d8`), the `PrivilegeMode` StrEnum
(`0b558ac`), and the `_StatusChecklist` refactor (`8dfa44f`), all of which
touch the same lines.

Recover the pieces rather than the commit:

```bash
git show cd3886f -- aivm/vm/ports.py          # passt SSH forward-port allocation
git show cd3886f -- aivm/cli/host_rootless.py # host rootless check/setup CLI
git show cd3886f -- aivm/vm/create.py         # _session_network_arg (passt XML)
git show 190ed83 --stat                       # everything that came back out
```

Files deleted outright: `aivm/cli/host_rootless.py`, `aivm/vm/ports.py`,
`tests/test_session_runtime.py`, `tests/test_e2e_session.py`. Symbols removed:
`RuntimeMode`, `SessionRuntimeError`, `RuntimeConfig`, `runtime_is_session`,
`require_system_runtime`, `activate_runtime`, `current_runtime_mode`,
`normalize_runtime_mode`, `libvirt_uri_for_mode`, `SESSION_LIBVIRT_URI`,
`SESSION_DEFAULT_BASE_DIR`, `apply_session_runtime_defaults`,
`SESSION_ONLY_CMDS`, `_ensure_session_storage`, `ssh_port_for`, and the
`port=` parameter of `ssh_base_args`.

## If you have an existing session VM

Nothing crashes, but aivm no longer sees it. A `[defaults.runtime]` section
left in `~/.config/aivm/config.toml` is ignored on load and dropped on the
next save; aivm now always targets `qemu:///system`. Any VM you created on
the per-user daemon is still there, orphaned:

```bash
virsh -c qemu:///session list --all
virsh -c qemu:///session destroy <name>
virsh -c qemu:///session undefine <name> --remove-all-storage
```
