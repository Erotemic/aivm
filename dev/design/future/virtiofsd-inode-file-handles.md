# virtiofsd inode-file-handles and host trust boundary

Written: 2026-05-12 America/New_York
Baseline commit: 525a96e8bafbfa539e3db27ed4c9a128a4665ea6
Status: do not implement generated host-side wrappers in normal AIVM flows

## Goal

AIVM needs a safe way to reduce virtiofsd file descriptor pressure for large
virtiofs exports, especially persistent-root style exports that can touch many
host inodes. The virtiofsd option that looks relevant is:

```text
--inode-file-handles=prefer
```

However, AIVM must preserve a host trust boundary: privileged host/libvirt/QEMU
startup paths should use known, distro-provided, administrator-vetted binaries.
AIVM should not silently generate scripts or executables under its state
directory and configure libvirt to execute them during VM startup.

Guest-side generated scripts are different. They execute inside the VM that AIVM
is managing. Host-side generated scripts are part of the trusted host runtime and
must be treated much more conservatively.

## What happened

A previous implementation attempted to pass `--inode-file-handles` by installing
a generated shell script such as:

```text
/var/lib/libvirt/aivm/virtiofsd-wrapper-prefer.sh
```

and rewriting each virtiofs `<filesystem>` device to use:

```xml
<binary path="/var/lib/libvirt/aivm/virtiofsd-wrapper-prefer.sh"/>
```

On the observed host, `aivm vm update` rewrote three virtiofs devices and then a
requested power cycle failed because libvirt reported:

```text
internal error: virtiofsd died unexpectedly
```

The qemu log showed libvirt attempting to launch the generated wrapper for the
three virtiofs devices:

```text
/var/lib/libvirt/aivm/virtiofsd-wrapper-prefer.sh --fd=33 -o source=...
```

and then failing the virtiofsd handshake.

The host did support the option:

```text
sudo /usr/libexec/virtiofsd --help | grep inode-file-handles
  --inode-file-handles=<INODE_FILE_HANDLES>
```

The host file descriptor limits were also already high:

```text
libvirtd LimitNOFILE = 524288
virtqemud LimitNOFILE = 1048576
/proc/sys/fs/nr_open = 1048576
```

So the failure was not simply "host virtiofsd lacks the flag" or "systemd's
NOFILE limit is tiny". The generated host wrapper itself became part of the VM
startup trust and reliability problem.

## Decision

Normal AIVM managed-libvirt mode must not install or use generated host-side
virtiofsd wrappers.

Current behavior should be:

1. New virtiofs attachments emit no AIVM wrapper `<binary>` override.
2. `aivm vm update` treats old AIVM wrapper paths as drift and removes them from
   persistent domain XML.
3. Existing config values such as `virtiofs.inode_file_handles = "prefer"` are
   ignored in managed-libvirt mode until there is a vetted implementation path.
4. The old wrapper recognition helpers may remain only to identify and clean up
   stale paths.

This means a subsequent `aivm vm update` should repair VMs whose XML still points
at `/var/lib/libvirt/aivm/virtiofsd-wrapper-*.sh` by removing those `<binary>`
elements and returning to libvirt's managed virtiofsd invocation.

## Options for a future safe solution

### 1. First-class libvirt XML support

Best long-term answer: libvirt exposes an XML knob for the virtiofsd
`inode-file-handles` behavior. AIVM can then use managed libvirt XML and avoid
external daemons or generated host code.

Before implementing anything else, check whether the target libvirt version has
added support for this option.

### 2. Managed libvirt resource knobs

If available on the host libvirt version, use managed XML such as virtiofsd
`openfiles` limits or other documented `<binary>` children. This stays inside
the libvirt trust model. Do not emit XML that the host libvirt version does not
support.

### 3. Administrator-owned external virtiofsd

Libvirt supports externally launched virtiofsd via a socket. If AIVM needs
arbitrary virtiofsd command-line flags before libvirt exposes them directly, an
administrator-owned systemd unit/socket is a cleaner design than an AIVM-generated
wrapper.

That design should be explicit and reviewable. AIVM may generate documentation or
a proposed unit file, but normal `aivm vm update` should not silently install it
or switch a VM to it.

### 4. Workload fallback

For workloads that are pathological for virtiofs, use a different sharing or sync
mode such as git sync, rsync/scp, a persistent disk image, or an admin-managed
network filesystem.

## Non-goals

Do not reintroduce any of the following as default behavior:

- generated shell wrappers launched by libvirt/QEMU;
- generated compiled shims launched by libvirt/QEMU;
- silently rewriting VM XML to point at AIVM-generated host executables;
- auto-installing privileged host services as a side effect of `aivm vm update`.

Any future host-side helper must be explicit, administrator-reviewed, and clearly
separated from ordinary VM update drift repair.

## Recovery check

To inspect a VM for stale wrapper paths:

```bash
sudo virsh -c qemu:///system dumpxml aivm-2404 | grep -n 'virtiofsd-wrapper'
```

After this decision, `aivm vm update --restart never` should plan a virtiofsd
binary path update from the wrapper path back to `(default)`. A full power cycle
is still needed for libvirt to spawn fresh virtiofsd processes, but the XML
repair itself should not install or execute any generated wrapper.

## 2026-05-12 follow-up: repair detection must not depend on current base_dir

A later local repair attempt reported `VM aivm-2404 is already in sync with
config` while `virsh start` still failed with `virtiofsd died unexpectedly`.
That means the cleanup drift detector failed to recognize the stale generated
wrapper in persistent domain XML. The likely cause is that the detector matched
only exact wrapper paths under the currently loaded `cfg.paths.base_dir`, while
historical wrapper paths used the default `/var/lib/libvirt/aivm` location.

Cleanup must therefore recognize AIVM legacy wrapper basenames such as
`virtiofsd-wrapper-prefer.sh` and `virtiofsd-wrapper-prefer` under AIVM-owned
libvirt paths, even if the current config has a different base directory. This
repair logic is intentionally broader than normal desired-state generation: it
exists only to remove previously generated host-side wrappers from VM XML.
