# Guest OS abstraction: Ubuntu + NixOS

**Status: Brainstorm.** Not designed, not approved, not started. This
document captures a research session and the shape an implementation would
take. It is *not* yet executable by an implementing agent: the open
questions in the last section have to be closed first, and several of the
facts marked `[I]` (inferred) need to be verified against a real NixOS guest
before anyone writes code.

Anchors below were verified against the tree at commit `fdd3585`
(`dev/sudoless`).

---

## 1. Problem

`aivm` supports exactly one guest OS. Ubuntu 24.04 is not a configuration
value; it is spelled out inline across image acquisition, cloud-init
rendering, package provisioning, status probes, and the two guest-side
agents. Adding a second guest OS today means editing all five.

The goal is a seam that lets a second guest OS exist. The goal is *not*
"support many distros" — see non-goals.

## 2. Scope and non-goals

**In scope**
- A guest-OS seam covering install/provisioning and guest-side behavior.
- Exactly two profiles: `ubuntu-24.04` (the incumbent) and `nixos`.
- The migration of two user-facing config landmines (§9).

**Explicit non-goals**
- **No Fedora, no Debian, no third profile — not even "on paper."** A
  profile that is registered but never booted is a silent lie about
  coverage. If it isn't verified end-to-end, it does not go in the
  registry. (An earlier draft of this doc proposed a golden-file-tested
  unbooted Fedora record as an anti-overfit check. That test is
  tautological: it asserts that a dataclass we filled in renders to a
  string we wrote down. It was rejected. §10 gives a real check.)
- **No host-OS abstraction.** `host_is_debian_like()`
  ([`aivm/host.py:70`](../../../aivm/host.py)) and `install_deps_debian()`
  ([`aivm/host.py:115`](../../../aivm/host.py)) stay as they are. That work
  is sequenced strictly after this, and is separately sketched in §11.
- **No image supply chain.** Building and publishing a NixOS qcow2 is real
  work (§8) but is deliberately deferred; the seam can be developed against
  a locally-built image via the `file://` path that
  [`aivm/vm/images.py:33-70`](../../../aivm/vm/images.py) already supports.

## 3. Why NixOS, specifically

NixOS was chosen as the second profile *because* it is maximally hostile,
not despite it. A Debian-family or Fedora second profile would have forced
four string swaps (`sudo`→`wheel`, `ssh`→`sshd`, `apt-get`→`dnf`,
`dpkg-query`→`rpm -q`) and produced a reskin. NixOS forces fields to change
*type*, and forces one genuine mechanism split. It is the difference between
an abstraction and a rename.

## 4. Current state (verified anchors)

The Ubuntu assumption lives in five places.

### 4.1 Image acquisition

- [`aivm/config.py:23-26`](../../../aivm/config.py) — `DEFAULT_UBUNTU_NOBLE_IMG_URL`
  and `SUPPORTED_IMAGE_SHA256`, a flat `url → sha256` dict with one entry.
- [`aivm/config.py:93-99`](../../../aivm/config.py) — `ImageConfig.ubuntu_img_url`,
  `cache_name = 'noble-base.img'`.
- [`aivm/vm/images.py:29-78`](../../../aivm/vm/images.py) —
  `_resolve_expected_image_sha256` hard-rejects any URL absent from the
  registry. `file://` URLs are accepted if their digest matches a
  registered entry.
- [`aivm/vm/create.py:68-69`](../../../aivm/vm/create.py) — `--os-variant ubuntu24.04`.

An existing `TODO(design)` at [`aivm/config.py:19-21`](../../../aivm/config.py)
already asks for "a network asset dataclass/registry that can describe the
primary URL, SHA256, mirrors, torrent magnet, and IPFS CID."

### 4.2 cloud-init

[`aivm/vm/cloudinit.py`](../../../aivm/vm/cloudinit.py) renders one
`#cloud-config` document (`_render_user_data_text`, line 105) and packs it
into a NoCloud seed ISO with `cloud-localds` (line 400), attached as a cdrom
by [`aivm/vm/create.py:73`](../../../aivm/vm/create.py).

The document does nine things. Ubuntu-specific values are marked:

| # | Effect | Ubuntu-specific |
|---|--------|-----------------|
| 1 | create user, match host uid/gid | `groups: [sudo]`, `shell: /bin/bash` |
| 2 | plant SSH authorized key | no |
| 3 | set password (`chpasswd`) | no |
| 4 | set timezone | no |
| 5 | install packages (`packages:`) | apt names |
| 6 | write sshd hardening drop-in | `/etc/ssh/sshd_config.d/` |
| 7 | write two agent binaries | `/usr/local/libexec` |
| 8 | write two systemd units | `/etc/systemd/system` |
| 9 | `systemctl enable` them + `ssh` + `unattended-upgrades` | unit names |

### 4.3 Package provisioning

- [`aivm/vm/provision.py:49-62`](../../../aivm/vm/provision.py) —
  `sudo apt-get update`, `add-apt-repository universe`,
  `sudo DEBIAN_FRONTEND=noninteractive apt-get install -y`.
- [`aivm/config.py`](../../../aivm/config.py) `ProvisionConfig.packages` —
  apt names (`fd-find`, `ripgrep`, …); `install_docker` → `docker.io`,
  `docker-compose-v2`.
- [`aivm/vm/guest_tools.py:137-177`](../../../aivm/vm/guest_tools.py) — VS
  Code CLI from Microsoft's Debian apt repo. (`uv` via astral.sh and `rust`
  via rustup in the same file are already distro-agnostic.)

### 4.4 Status probes

- [`aivm/status.py:496-506`](../../../aivm/status.py) — verifies packages with
  `dpkg-query -W -f='${Status}'`.

### 4.5 Guest-side agents

Two Python programs plus systemd units, rendered on the host and installed
into the guest by two independent paths (cloud-init at first boot, SSH
thereafter).

- **fd guard** — [`aivm/fdguard.py:45-50`](../../../aivm/fdguard.py) pins
  `FDGUARD_BIN = /usr/local/libexec/aivm-virtiofs-guard`,
  `FDGUARD_CONF = /etc/aivm/virtiofs-guard.conf`, and unit paths under
  `/etc/systemd/system/`. `fdguard_install_script`
  ([`:334-363`](../../../aivm/fdguard.py)) does
  `sudo -n mkdir -p /usr/local/libexec /etc/aivm /etc/systemd/system`,
  `... | sudo -n tee <path>`, `sudo -n systemctl daemon-reload`,
  `sudo -n systemctl enable --now`. It also edits `/etc/updatedb.conf`
  `PRUNEFS` ([`:138-174`](../../../aivm/fdguard.py)) so Ubuntu's nightly
  `plocate-updatedb` sweep does not walk every shared virtiofs inode.
- **persistent-attachment replay** —
  [`aivm/persistent_replay.py:16-29`](../../../aivm/persistent_replay.py)
  pins `/usr/local/libexec/aivm-persistent-attachment-replay`,
  `/var/lib/aivm`, `/mnt/aivm-persistent`. Enabled via
  [`aivm/attachments/persistent/replay.py:58-59`](../../../aivm/attachments/persistent/replay.py)
  (`sudo -n systemctl daemon-reload; sudo -n systemctl enable ...`).
  Refreshed over SSH by `_install_guest_text_if_changed`
  ([`aivm/attachments/persistent/transport.py:393`](../../../aivm/attachments/persistent/transport.py)).

### 4.6 The structural defect

[`aivm/vm/cloudinit.py:16-31`](../../../aivm/vm/cloudinit.py) imports
`fdguard_python`, `fdguard_conf_text`, `fdguard_service_unit`,
`fdguard_timer_unit`, `persistent_replay_python`, and
`persistent_replay_service_unit` **by name**, and `_render_user_data_text`
hand-weaves them into `write_files:`/`runcmd:` with
`textwrap.indent(..., ' ' * 14)` to get the YAML nesting right.

The seed-ISO renderer is simultaneously a NoCloud transport *and* the
install script for every guest agent aivm ships. Adding a third agent today
means editing the seed renderer. This coupling — not the distro strings —
is the real architectural problem, and it is what makes the Ubuntu
assumption load-bearing rather than incidental.

## 5. Research findings

### 5.1 cloud-init is the portability layer — but it carries less than it looks

cloud-init is a cross-distro standard, not an Ubuntu technology. Crucially
for this effort, **NixOS supports the NoCloud seed-ISO path**, and nixpkgs'
own CI proves it: [`nixos/tests/cloud-init.nix`](https://github.com/NixOS/nixpkgs/blob/master/nixos/tests/cloud-init.nix)
builds a `cidata`-labeled ISO with `genisoimage`, attaches it as `-cdrom`,
and asserts provisioning — functionally identical to what `cloud-localds`
produces. `services.cloud-init.enable` lives at
[`nixos/modules/services/system/cloud-init.nix`](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/system/cloud-init.nix). `[V]`

So the seed-ISO spine survives the most hostile distro we could pick. That
is strong evidence it is the right transport.

**But**: of the nine effects in §4.2, NixOS kills five (#5–#9). The
cloud-config is not a portable spine with distro-specific values sprinkled
in. It is a transport for a small genuinely-universal *identity* core (#1–#4:
user, uid/gid, keys, password, timezone) plus a pile of Ubuntu-shaped side
effects riding along in the same document.

The refactor that follows is therefore **eviction, not parameterization**:
effects #5–#9 must leave the cloud-config and become capabilities the
profile satisfies however it likes (via `write_files`, via the image, or via
a post-boot SSH step).

### 5.2 NixOS guest facts

Verified against nixpkgs (`release-26.05` / master) unless marked.
`[V]` verified against primary source, `[I]` inferred, `[?]` unverified.

| Question | Answer |
|---|---|
| `services.cloud-init.enable` exists | `[V]` yes |
| NoCloud from cdrom seed ISO | `[V]` yes — nixpkgs CI does exactly this |
| `write_files`, `users-groups`, `runcmd`, `timezone`, `set-passwords` | `[V]` all in NixOS's enabled module lists |
| `packages:` | `[V]` **silently ignored** — `package-update-upgrade-install` is in none of the three module lists |
| `services.cloud-init.network.enable` | `[V]` **defaults to `false`** — our generated `network-config` is ignored unless the image opts in |
| user uid/gid + `sudo:` rules via cloud-init | `[I]` upstream feature, not exercised by the nixpkgs test; NixOS reads `/etc/sudoers.d/` so drop-ins should apply. **Verify before relying on it.** |
| `/bin/bash` | `[V]` **does not exist**. Only `/bin/sh`. `users.defaultUserShell` is the literal string `"/bin/sh"` |
| `/usr/bin/env` | `[V]` exists (`environment.usrbinenv`), the only file in `/usr/bin`. `#!/usr/bin/env python3` shebangs are fine |
| `/usr/local` | `[I]` does not exist, unmanaged. Persists if you `mkdir` it on a persistent root, wiped under impermanence. **Do not rely on it** |
| `/etc/systemd/system/` | `[V]` **read-only store symlink** (`environment.etc."systemd/system".source = generateUnits ...`). Hand-written units do not work; `systemctl enable` (which writes `.wants` symlinks there) fails |
| `/run/systemd/system/` | `[V]` standard runtime unit dir, writable tmpfs, higher precedence than `/etc`. `systemctl start` works; wiped on reboot |
| python3 | `[V]` no FHS path, not present in a minimal image. Via `environment.systemPackages` it lands at `/run/current-system/sw/bin/python3` |
| `/etc/updatedb.conf` | `[V]` written only when `services.locate.enable = true` (**default false**). With locate off there is no updatedb binary, no timer, nothing to prune |
| `/etc/ssh/sshd_config.d/` | `[V]` **not honored**. NixOS writes a complete `/etc/ssh/sshd_config` store symlink with no `Include`. Drop-ins are ignored |
| admin group | `[V]` `wheel`. No `sudo` group. `security.sudo.wheelNeedsPassword` defaults to **true** |
| sshd unit | `[V]` `sshd.service` (not `ssh.service`) |
| virtiofs | `[V]` loadable module in the stock kernel. Post-boot `mount -t virtiofs <tag> /mnt` needs no initrd config. All four attachment modes survive |
| `nix-env -iA nixpkgs.ripgrep` as non-root | `[V]` works out of the box, no sudo, no experimental features. `~/.nix-profile/bin` is on PATH. Needs `<nixpkgs>` in NIX_PATH `[I]` — verify per image |
| `nix profile install` | `[V]` needs `nix-command`/`flakes` experimental features, **not** on by default |
| osinfo-db entry | `[V]` `data/os/nixos.org/` exists; short-ids `nixos-25.05`, `nixos-unstable`, etc. Resolution depends on the *host's* installed osinfo-db version — older hosts need a fallback (`linux2022`, or `detect=on,require=off`) |
| official qcow2 with stable URL | `[V]` **none exists.** nixos.org publishes ISOs + AWS AMIs. nix-community/nixos-images publishes installer/kexec/netboot only. nixpkgs' OpenStack builder makes a qcow2 but uses bespoke `openstack-init`, not cloud-init. Build with `nixos-generators -f qcow` (flag is `qcow`, not `qcow2`) |

A payoff worth naming: on NixOS, `aivm vm provision` needs **no privilege
escalation at all**, where the apt path needs `sudo` for every install. This
is a direct vindication of the CLAUDE.md rule *"whether an operation needs
root is a property of the command being run, not of the feature requesting
it."* Privilege becomes per-profile, which the current code cannot express.

### 5.3 Prior art: build vs borrow

Surveyed for a reusable guest-profile abstraction. **Nothing carries the
composite.** Each candidate has a slice:

| Candidate | Covers | Verdict |
|---|---|---|
| **libosinfo / osinfo-db** ([libosinfo.org](https://libosinfo.org/), [gitlab](https://gitlab.com/libosinfo/osinfo-db)) | `short-id` (the `--os-variant` string), cloud image URLs, `cloud-init="true"` flag, resource minimums. **No package-manager data, no checksums.** | **Borrow the vocabulary, not the dependency.** It gives us one string per profile that we would hardcode anyway; the cost is PyGObject + system libosinfo, or parsing `/usr/share/osinfo` XML. Do document that `os_variant` must be an osinfo short-id and point users at `osinfo-query os`. |
| **mkosi** (systemd) | Python, per-distro classes in `mkosi/distribution/*.py` with `package_manager()`, `install()`, … | Explicitly **"not to be considered a public API."** Reference only. |
| **cloud-init `cloudinit/distros/`** | A real `PackageManager` abstraction; per-distro `default_user` groups/shell; config paths | pip-installable but it is **in-guest runtime code** that selects by detecting the *running* system, not a host-side table for an arbitrary target. Best **reference source** for package-manager verbs (Apache-2.0 — attribute if we copy tables). Not a dependency. |
| **distrobuilder** (Incus) | Declarative per-distro YAML: source, package manager, install sets, files, actions | Closest conceptual cousin. Go CLI. Borrow the **schema design** (`shared/definition.go`), not the code. |
| **python `distro`** | `/etc/os-release` parsing | Host detection only. Irrelevant to the *guest* seam — but see §11. |
| **Ansible** `module_utils/facts/system/pkg_mgr.py` | `PKG_MGRS` detection table | Not usable standalone. |
| **virt-builder** index | Image URL + **checksum** + revision | Prior art for the registry schema (§8). Not a Python dep. |
| **Repology** ([api](https://repology.org/api)) | Cross-distro package *name* mapping (`fd-find` vs `fd`) | The right tool if aivm ever supports many distros. A runtime network dep for two. Skip. |

**Conclusion: roll our own.** Roughly a dozen fields across two profiles of
static data. Both projects that seriously attempted this abstraction
(mkosi, distrobuilder) ended up as build *engines* rather than data tables,
and mkosi marks its version non-public because it does not stabilize.

**Should the seam become its own package?** Not yet, likely never. Its field
list is defined by *aivm's* requirements contract (§6.1). A general package
would have to abstract over that contract, which is where all the difficulty
lives. Revisit if a second consumer appears.

## 6. The trap, and the shape that avoids it

### 6.1 The trap: diff-shaped abstractions silently delete behavior

The obvious design is a data record whose fields are "the things that differ
between Ubuntu and NixOS":

```python
sshd_dropin_dir: str | None    # '/etc/ssh/sshd_config.d' | None
updatedb_conf: str | None      # '/etc/updatedb.conf' | None
login_shell: str | None        # '/bin/bash' | None
```

Every consumer then becomes `if profile.sshd_dropin_dir: emit(...)`.

Trace that. [`aivm/vm/cloudinit.py:241-249`](../../../aivm/vm/cloudinit.py)
writes an sshd hardening drop-in with `PermitRootLogin no`,
`X11Forwarding no`, and `PasswordAuthentication` driven by
`cfg.vm.allow_password_login`. On NixOS the field is `None`, the `if` skips,
and **the guest boots with no aivm ssh hardening at all** — and
`allow_password_login = False` is silently not enforced. A security-relevant
regression, produced *by the abstraction*, invisible in review, and it
type-checks.

`None` there does not mean "this distro has no such path." It means
"hardening must happen somewhere else, and you had better find out where."
The type collapsed two different facts.

This is a **diff-shaped** abstraction: a field for every place two distros
disagree. What is needed is a **concept-shaped** one: a method for every
capability aivm depends on, with **no way to express "silently do nothing."**

It is the CLAUDE.md rule lifted one level: *enforce at the capability, not
the config field.*

### 6.2 Absence is a value you construct on purpose

```python
class Unsupported(Exception):
    """This profile cannot provide this capability. Reconcile must refuse."""

@dataclass(frozen=True)
class NotApplicable:
    """This capability is meaningless here. Recorded, reported, not an error."""
    reason: str
```

- `harden_sshd(policy)` — Ubuntu writes a drop-in. NixOS cannot express this
  through cloud-init (`/etc/ssh/` is read-only), so it must do it via an
  sshd unit override in `/run` (which composes with §7), or raise
  `Unsupported` and have reconcile refuse with guidance.
- `guard_filesystem_indexer()` — Ubuntu prunes virtiofs from
  `/etc/updatedb.conf`. NixOS returns
  `NotApplicable("services.locate is off; no indexer to guard")`. That is a
  **claim someone made**, surfaced in `aivm status` — not a `None` someone
  forgot.

Neither outcome is reachable by omission. That is the whole point.

### 6.3 Proposed shape

A data record for what varies by *value*, plus exactly two strategy points
for what varies by *mechanism*.

```python
@dataclass(frozen=True)
class GuestProfile:
    id: str                 # 'ubuntu-24.04' | 'nixos'
    os_variant: str         # osinfo short-id; fallback if host osinfo-db is old
    admin_group: str        # 'sudo' | 'wheel'
    sshd_unit: str          # 'ssh' | 'sshd'
    login_shell: str | None # None = use the image's default (NixOS)
    state_dir: str          # '/var/lib/aivm'
    libexec_dir: str        # '/usr/local/libexec' | '/var/lib/aivm/bin'
    packages: GuestPackages
    units: GuestUnits
    def harden_sshd(self, policy) -> Steps | Unsupported: ...
    def guard_filesystem_indexer(self) -> Steps | NotApplicable: ...
```

`GuestPackages` — cloud-init package list (Ubuntu: apt names; NixOS: empty,
because `packages:` is a no-op), install command, installed-query command,
and **whether install requires sudo** (Ubuntu: yes; NixOS: no).

`GuestUnits` — deliver a unit, activate a unit. `FhsUnits` writes to
`/etc/systemd/system` and `systemctl enable`s. `NixUnits` writes to
`/run/systemd/system` and `systemctl start`s (§7).

Expect these two to share **zero code**. That is fine, and the doc should
say so rather than treat it as failure. A union of two honest implementations
behind a real interface is a good outcome. The failure mode is not "no shared
code"; it is "shared code that only one implementation means."

### 6.4 Evict guest-agent installation from `cloudinit.py`

Consequence of §4.6 and §5.1. Guest agents declare what they need — *a file
at path P with mode M*, *a unit named U, activated* — the profile decides how
that is satisfied, and `cloudinit.py` imports neither `fdguard` nor
`persistent_replay`. It renders identity (§4.2 #1–#4) plus whatever fragments
the profile hands it.

This also disentangles `refresh_cloud_init_seed_for_next_boot`
([`aivm/vm/cloudinit.py:67-103`](../../../aivm/vm/cloudinit.py)), which today
exists solely to make cloud-init replay `write_files`/`runcmd` so a stopped
VM gets its replay agent before boot-time attachment replay. Once agent
delivery is a capability, that mechanism is Ubuntu's business, not the seed
renderer's.

## 7. NixOS unit delivery: `/run` + a baked re-materializer

`/etc/systemd/system` is a read-only store symlink, so there is **no writable
path to swap in**. This is the one place a data field is genuinely
insufficient, and the reason `GuestUnits` exists.

Two mechanisms were considered:

1. **Bake into the image.** Declare both agents as `systemd.services.*` in
   the image's nix expression. Idiomatic. Cost: the agent version is pinned
   to the image, so `_install_guest_text_if_changed`
   ([`transport.py:393`](../../../aivm/attachments/persistent/transport.py))
   has nothing to write to and `aivm vm update` cannot refresh an agent.
2. **Runtime units in `/run/systemd/system`.** Writable tmpfs, higher
   precedence than `/etc`, so `systemctl start` works and runtime updates
   keep working. `/run` is wiped on reboot, so persistence comes from one
   small unit *baked into the image* that re-materializes aivm's units from
   `/var/lib/aivm/units/` at boot. Note `systemctl enable` still cannot be
   used — it writes `.wants` symlinks into `/etc` — so the boot-time
   re-materializer must also `start` them.

**Decision: (2).** It is more elegant and it preserves the update path; the
re-materializer is a few lines of nix.

### 7.1 The image contract (and the tension with "bring your own image")

Mechanism (2) requires the image to carry the re-materializer. A user who
supplies a **stock** NixOS qcow2 gets agents that work until first reboot and
then vanish — silently. That is the §6.1 bug in a different costume.

Therefore the NixOS profile declares **preconditions on the image**, `aivm
status` probes them, and reconcile refuses with guidance rather than
degrading:

1. `/var/lib/aivm/units/` exists and `aivm-units.service` is present and
   enabled.
2. `services.cloud-init.enable = true`.
3. `services.cloud-init.network.enable = true` — otherwise the generated
   `network-config` ([`cloudinit.py:303-318`](../../../aivm/vm/cloudinit.py))
   is silently ignored and the VM comes up with no IP.
4. `python3` in `environment.systemPackages`.

"Bring your own image" then means "bring an image satisfying this stated
contract" — a thing we can write down and check, not a thing we hope for.

### 7.2 `allow_password_login` on NixOS

`VMConfig.allow_password_login` and `VMConfig.password` are per-VM knobs.
NixOS's sshd config is declarative and read-only, and cloud-init's
`set-passwords`/`ssh` modules would need to edit `/etc/ssh/sshd_config` — a
store symlink. `[I]` **This needs verification.** If confirmed, the per-VM
knob has to be satisfied by an sshd unit override in `/run` (composes with
§7), or declared `Unsupported` on NixOS. It must not silently no-op.

## 8. Image registry and fetching (recorded, deferred)

Not part of this effort. Recorded because the research was done and because
`aivm/config.py:19-21`'s `TODO(design)` describes it.

**Fetching cannot use an off-the-shelf library.** [`aivm/vm/images.py:172-215`](../../../aivm/vm/images.py)
downloads via `curl -L --fail -o` submitted through `mgr.submit(...)` with
`sudo=path_needs_sudo(p['img_dir'])`, wrapped in `mgr.intent`/`mgr.step` with
an `image-fetch:` approval scope and a dry-run branch. The default
`paths.base_dir` is `/var/lib/libvirt/aivm` — **root-owned**. An in-process
`urllib`/`requests` download physically cannot write there, and would bypass
the command manager: no step log, no approval, no dry-run, no sudo gate.

pooch, `hf_hub_download`, and `ubelt.grabdata` (already a runtime dep) are
all disqualified **by layer, not by quality**. `pooch` additionally assigns
exactly one URL per file with no fallback; `grabdata` does in-process urllib
to a name-based cache and its `hash_prefix` is a prefix check, not
full-digest equality.

**The extractable piece is the pure half:**

- **Resolver** (pure, no I/O): asset id → `(expected_sha256, [ordered
  candidate sources])`. Registry entries, mirror ordering, digest-addressed
  cache path. Package-worthy *because* it has no I/O and no domain coupling,
  and because nothing on PyPI does mirror-fallback + digest-addressed cache +
  pluggable sources together.
- **Transport** (stays in aivm): executes candidates via `mgr.submit(['curl',
  ...])`, falls through on failure, verifies the digest, `os.replace`s into
  place.

**IPFS is then free.** Once the resolver emits *candidate URLs*, IPFS is one
more entry in the fallback list:

```
https://cloud-images.ubuntu.com/.../noble-server-cloudimg-amd64.img  # primary
https://mirror.example/noble-base.img                                # mirror
http://127.0.0.1:8080/ipfs/<cid>                                     # local daemon
https://ipfs.io/ipfs/<cid>                                           # public gateway
```

All four are `curl` URLs. **No `ipfsspec`, no daemon requirement, no new
dependency.** If a gateway is down, curl fails and we fall through — "IPFS as
an option, never relied upon" satisfied structurally rather than by a flag.
CID verification is unnecessary for integrity: the entry already carries a
`sha256` that gates every candidate identically. IPFS gives distribution; the
digest gives trust. They are independent.

**Naming.** `fetch` is taken on PyPI (a dead 2011 URL-mirroring utility) and
would be the wrong name anyway — "fetch" describes the transport, which stays
in aivm. The extractable piece is *resolution*. `naar` is available and is a
literal acronym of the phrase the existing `TODO(design)` already uses
("network asset registry"); `fetchreg` and `netasset` are also free.

**Registry policy.** `_resolve_expected_image_sha256` currently *reads* like
a security control. It is not one: `config.toml` is user-owned, and anyone who
can edit it can already make aivm run arbitrary commands. It is a
corrupt-cache/typo guard. It should stay strict-by-default and grow an
explicit escape hatch — a config-pinned `{url, sha256, profile}` triple — so
that using an unlisted image does not require patching the package.

**Consequence for NixOS.** There is no upstream NixOS qcow2 to point at
(§5.2), so a `nix/aivm-guest.nix` built in CI and published to a mirror plus
IPFS is on the critical path *for shipping*, though not for *developing*:
`file://` already works for local iteration.

## 9. Migration landmines

**Config compat.** `image.ubuntu_img_url` is a public TOML field, touched
across ~15 test sites plus [`tests/test_e2e_sudoless.py:104`](../../../tests/test_e2e_sudoless.py)
and [`tests/test_e2e_full.py:127`](../../../tests/test_e2e_full.py). It
becomes `image.url` + `image.id`, with `ubuntu_img_url` kept readable as an
alias for one release behind a `log.warning`. First-class deprecation support
in `kwconf` was discussed and deliberately deferred; hand-roll the alias in
`AgentVMConfig` post-init for now.

**Identity leak.** `_DEFAULT_VM_NAME_PREFIX = 'aivm-2404-'`
([`aivm/config.py:28`](../../../aivm/config.py)) bakes Ubuntu 24.04 into every
default VM name. Derive it from the profile for new distros; leave it literal
for Ubuntu. Existing `aivm-2404-*` VMs must keep resolving.

## 10. Acceptance criteria

Not "does a third distro fit." That question cannot be answered by an
unbooted profile, and a booted third distro is out of scope. The criterion is
about the *call sites*:

> **No distro conditional outside `aivm/guest/profiles/`.** No
> `if profile.id == ...`, no `if profile.is_nix`, and no truthiness test on a
> profile field that guards a behavior.

Grep-able, and it fails loudly the moment someone reaches for
`if profile.updatedb_conf:` in `fdguard.py`. If `provision.py`, `status.py`,
`fdguard.py`, `persistent_replay.py`, and `cloudinit.py` come out of this with
zero branches on distro identity, the seam is load-bearing. If they do not, it
is not, and no number of profiles would have revealed that.

Additionally:

- Every capability returns `Steps`, `Unsupported`, or `NotApplicable`. There
  is no code path where a capability silently does nothing.
- `aivm status` reports each `NotApplicable` with its reason, and each failed
  image precondition (§7.1) by name.
- Both profiles boot end-to-end under `tests/test_e2e_sudoless.py`, which is
  already CI-compatible (no passwordless sudo needed) and is the template.
- Ubuntu behavior is byte-identical before and after the refactor. Golden-file
  the current rendered `user-data` first, then refactor against it.

## 11. Host-side abstraction (sequenced after; sketch only)

Different shape from the guest: on the host you **detect** an OS; on the guest
you **select** one. [`aivm/host.py:70`](../../../aivm/host.py)'s
`host_is_debian_like()` already does the detection half by substring-matching
`/etc/os-release`; the `distro` package (Apache-2.0, maintained) does it
properly via `distro.id()` / `distro.like()`. That is a delete-code-add-dep
trade when the time comes.

A cheap partial win is available *before* any abstraction and does not depend
on this effort: split `install_deps_debian()`
([`aivm/host.py:115`](../../../aivm/host.py), which already carries a `TODO`
saying exactly this) into `check_deps()` — the probe already exists — and
`install_deps()`, and have an unrecognized host emit "aivm needs these
packages: …" guidance rather than erroring. ~30 lines, no new structure.

## 12. Open questions

These must be closed before this doc is executable.

1. **`allow_password_login` on NixOS** (§7.2). Does cloud-init's
   `set-passwords`/`ssh` module fail, no-op, or error when
   `/etc/ssh/sshd_config` is a read-only store symlink? Determines whether the
   knob is satisfiable via a `/run` unit override or must raise `Unsupported`.
2. **cloud-init `users-groups` uid/gid + `sudo:` rules on NixOS** (§5.2,
   `[I]`). The nixpkgs CI test creates a user with an SSH key but does not
   exercise numeric uid/gid or sudoers drop-ins. `aivm`'s
   `match_host_user_ids` depends on this entirely. Verify on a real guest.
3. **`/run/systemd/system` + timers.** `fdguard` installs a `.timer`, not just
   a `.service` ([`fdguard.py:47-50`](../../../aivm/fdguard.py)). Confirm a
   runtime-dir timer started (not enabled) behaves correctly across the
   re-materializer's boot ordering.
4. **`nix-env -iA nixpkgs.X` and `<nixpkgs>` in NIX_PATH** (§5.2, `[I]`). A
   pure-flake image with channels removed may not resolve `<nixpkgs>`. This
   determines whether `aivm vm provision` works on NixOS at all, or whether
   the image must set `nix.nixPath`.
5. **`guest_tools.py`.** `uv` (astral.sh) and `rust` (rustup) are already
   portable. The VS Code CLI comes from Microsoft's Debian apt repo
   ([`:137-177`](../../../aivm/vm/guest_tools.py)). Is `code` `Unsupported` on
   NixOS, or is there a `nixpkgs` equivalent worth wiring up?
6. **Ordering.** Confirmed lean: profile seam first (refactor-only, Ubuntu
   behavior unchanged, developed against the existing single-entry registry),
   then the NixOS profile and image against a `file://` URL, then §8's registry
   widening in order to publish. The seam gets forced through all five call
   sites while only one image has to keep working.

## 13. Sources

- nixpkgs cloud-init module: https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/system/cloud-init.nix
- nixpkgs cloud-init NoCloud CI test: https://github.com/NixOS/nixpkgs/blob/master/nixos/tests/cloud-init.nix
- nixpkgs locate module: `nixos/modules/misc/locate.nix`
- nixpkgs sshd module: `nixos/modules/services/networking/ssh/sshd.nix`
- nixpkgs `/etc` activation: `nixos/modules/system/activation/activation-script.nix`; issue https://github.com/NixOS/nixpkgs/issues/108054
- nixpkgs qemu-guest profile (virtiofs): `nixos/modules/profiles/qemu-guest.nix`
- NixOS virtiofs wiki: https://wiki.nixos.org/wiki/VirtioFS
- nixos-generators: https://github.com/nix-community/nixos-generators
- NixOS downloads (ISO + AMI only): https://nixos.org/download/
- nix-community/nixos-images releases: https://github.com/nix-community/nixos-images/releases
- osinfo-db NixOS entries: https://gitlab.com/libosinfo/osinfo-db/-/tree/main/data/os/nixos.org
- libosinfo: https://libosinfo.org/
- mkosi distribution policy: https://mkosi.systemd.io/distribution-policy.html
- cloud-init distros: https://github.com/canonical/cloud-init/tree/main/cloudinit/distros
- distrobuilder: https://github.com/lxc/distrobuilder
- pooch (one URL per file): https://www.fatiando.org/pooch/latest/multiple-urls.html
- Repology API: https://repology.org/api
- virt-builder index format: https://libguestfs.org/virt-builder.1.html
