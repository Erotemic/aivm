#!/usr/bin/env python3
"""
Verify that ``virtiofsd --inode-file-handles=prefer`` can be enabled on this
host with the filesystems currently bound under persistent-root.

Run on the HOST (not inside a VM), with sudo so we can read every
virtiofsd's ``/proc/<pid>/status`` and walk into bind-mounted token
directories.

    sudo python3 dev/devcheck/virtiofsd_filehandles_check.py [VM]

Default VM is ``aivm-2404``; override by passing a name as the first
argument, or by setting ``AIVM_VM``.

Three things must hold for ``--inode-file-handles=prefer`` to do what we
want (cache cached-inode references as file handles instead of long-lived
FDs):

  1. virtiofsd recognizes the flag.
        Detected by parsing ``virtiofsd --help``.

  2. virtiofsd's effective capability set includes CAP_DAC_READ_SEARCH.
        Required by ``open_by_handle_at`` (man 2 open_by_handle_at).
        Detected by parsing ``CapEff`` in ``/proc/<pid>/status`` of each
        running virtiofsd process.

  3. The filesystems exposed under persistent-root each support
     name_to_handle_at / open_by_handle_at.
        Detected by directly calling name_to_handle_at on a sample file
        from each distinct filesystem.

``prefer`` mode falls back to FDs per-filesystem if a given filesystem
returns EOPNOTSUPP, so it is safe to enable even on a mixed host; only
``mandatory`` would refuse to start.

What this script does NOT do
----------------------------
It does not redefine the libvirt domain or restart anything. After this
script reports "all three checks pass" you still need to wire the flag
into virtiofsd's command line (typically via a libvirt ``<binary>``
element or a wrapper script that ``exec``s the real virtiofsd with the
flag appended). The script ends with a suggested wrapper recipe.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import subprocess
import sys
from pathlib import Path

VM = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AIVM_VM", "aivm-2404")
PERSISTENT_ROOT = Path(f"/var/lib/libvirt/aivm/{VM}/persistent-root")

AT_FDCWD = -100
MAX_HANDLE_SZ = 128
CAP_DAC_READ_SEARCH = 2  # bit index, see capabilities(7)

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


class FileHandle(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint32),
        ("handle_type", ctypes.c_int32),
        ("f_handle", ctypes.c_ubyte * MAX_HANDLE_SZ),
    ]


libc.name_to_handle_at.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(FileHandle),
    ctypes.POINTER(ctypes.c_int), ctypes.c_int,
]
libc.name_to_handle_at.restype = ctypes.c_int


def test_name_to_handle_at(path: Path):
    h = FileHandle()
    h.handle_bytes = MAX_HANDLE_SZ
    mnt_id = ctypes.c_int(0)
    rc = libc.name_to_handle_at(
        AT_FDCWD, str(path).encode(), ctypes.byref(h),
        ctypes.byref(mnt_id), 0,
    )
    if rc == 0:
        return True, f"OK (handle_bytes={h.handle_bytes} handle_type={h.handle_type})"
    err = ctypes.get_errno()
    name = {
        95: "EOPNOTSUPP",
        38: "ENOSYS",
        13: "EACCES",
        2: "ENOENT",
    }.get(err, str(err))
    # EOVERFLOW means the fs *does* support handles but our buffer was too small.
    # That counts as "supports" for our purposes; we'd never see this with 128B.
    if err == 75:  # EOVERFLOW
        return True, "OK (EOVERFLOW: supported but handle larger than test buffer)"
    return False, f"FAIL errno={err} ({name}: {os.strerror(err)})"


def find_virtiofsd_pids() -> list[int]:
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            exe = os.readlink(f"/proc/{entry}/exe")
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if os.path.basename(exe) == "virtiofsd":
            pids.append(int(entry))
    return sorted(pids)


def parse_cap_eff(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (FileNotFoundError, PermissionError):
        return None
    return None


def parse_mountinfo() -> dict[tuple[int, int], tuple[str, str, str]]:
    """Return {(major, minor): (fstype, source, mountpoint)}."""
    out: dict[tuple[int, int], tuple[str, str, str]] = {}
    try:
        with open("/proc/self/mountinfo") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        parts = line.split()
        try:
            sep = parts.index("-")
        except ValueError:
            continue
        major_minor = parts[2]
        mountpoint = parts[4]
        fstype = parts[sep + 1]
        source = parts[sep + 2] if len(parts) > sep + 2 else "?"
        try:
            maj, mnr = (int(x) for x in major_minor.split(":"))
        except ValueError:
            continue
        out.setdefault((maj, mnr), (fstype, source, mountpoint))
    return out


def banner(s: str) -> None:
    print()
    print("=" * 60)
    print(s)
    print("=" * 60)


def sub(s: str) -> None:
    print(f"\n--- {s}")


def main() -> int:
    banner(f"--inode-file-handles=prefer feasibility check for VM={VM}")
    print(f"persistent-root: {PERSISTENT_ROOT}")

    pass_1 = pass_2 = pass_3 = True

    # 1. virtiofsd flag support
    sub("1. virtiofsd version + --inode-file-handles flag")
    binary = None
    for cand in ("/usr/libexec/virtiofsd", "/usr/bin/virtiofsd"):
        if os.path.exists(cand):
            binary = cand
            break
    if not binary:
        print("    virtiofsd binary not found on common paths")
        pass_1 = False
    else:
        v = subprocess.run([binary, "--version"], capture_output=True, text=True)
        print(f"    binary:  {binary}")
        print(f"    version: {(v.stdout or v.stderr).strip()}")
        h = subprocess.run([binary, "--help"], capture_output=True, text=True)
        helptext = h.stdout + h.stderr
        if "inode-file-handles" in helptext:
            print("    --inode-file-handles flag: SUPPORTED")
        else:
            print("    --inode-file-handles flag: NOT FOUND in --help")
            pass_1 = False

    # 2. CAP_DAC_READ_SEARCH availability path
    sub("2. CAP_DAC_READ_SEARCH availability for virtiofsd")
    bit = 1 << CAP_DAC_READ_SEARCH

    # 2a. running virtiofsd: shows current state, not inevitable state
    print("    [2a] live virtiofsd effective caps (current state, not the question we care about)")
    pids = find_virtiofsd_pids()
    if not pids:
        print("        (no virtiofsd processes running)")
    else:
        for pid in pids:
            cap_eff = parse_cap_eff(pid)
            if cap_eff is None:
                print(f"        pid={pid}: cannot read /proc/{pid}/status (need sudo)")
                continue
            has = "YES" if cap_eff & bit else "NO "
            print(f"        pid={pid:<7} CapEff={cap_eff:#018x}  dac_read_search={has}")
    print("        (virtiofsd drops this cap when not using file handles; missing")
    print("         here is expected and does NOT prove anything about feasibility.)")

    # 2b. actual parent(s) of virtiofsd: do they hold dac_read_search?
    print()
    print("    [2b] virtiofsd's actual parent process(es): can they pass dac_read_search down?")

    def _read_status_field(pid: int, field: str) -> str | None:
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith(field):
                        return line.split(maxsplit=1)[1].strip()
        except (FileNotFoundError, PermissionError):
            return None
        return None

    def _comm(pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError):
            return "?"

    parent_pids: set[int] = set()
    for vd_pid in pids:
        ppid_str = _read_status_field(vd_pid, "PPid:")
        if ppid_str and ppid_str.isdigit():
            ppid = int(ppid_str)
            if ppid > 0:
                parent_pids.add(ppid)

    parent_has_cap = False
    if not parent_pids:
        print("        (no virtiofsd processes; cannot inspect parent)")
    else:
        for ppid in sorted(parent_pids):
            cap_eff = parse_cap_eff(ppid)
            cap_bnd_s = _read_status_field(ppid, "CapBnd:")
            cap_bnd = int(cap_bnd_s, 16) if cap_bnd_s else None
            eff = "?" if cap_eff is None else ("YES" if cap_eff & bit else "NO ")
            bnd = "?" if cap_bnd is None else ("YES" if cap_bnd & bit else "NO ")
            print(f"        parent pid={ppid} comm={_comm(ppid)}  "
                  f"effective={eff}  bounding={bnd}")
            if (cap_eff and cap_eff & bit) or (cap_bnd and cap_bnd & bit):
                parent_has_cap = True

    # 2c. AppArmor: does the profile allow it?
    print()
    print("    [2c] AppArmor: profile allows capability dac_read_search?")
    aa_enabled = os.path.exists("/sys/kernel/security/apparmor")
    profile_finding = None
    if not aa_enabled:
        print("        AppArmor not enabled on this host; not a blocker.")
        profile_finding = True
    else:
        candidates = [
            "/etc/apparmor.d/usr.libexec.virtiofsd",
            "/etc/apparmor.d/abstractions/libvirt-qemu",
            "/etc/apparmor.d/libvirt/TEMPLATE.qemu",
        ]
        found_any = False
        for p in candidates:
            if not os.path.exists(p):
                continue
            found_any = True
            try:
                with open(p) as f:
                    content = f.read()
            except PermissionError:
                print(f"        {p}: permission denied (try sudo)")
                continue
            allows = "dac_read_search" in content
            denies = "deny capability dac_read_search" in content
            marker = "ALLOWS" if (allows and not denies) else \
                     "DENIES" if denies else \
                     "no explicit rule (may inherit from abstractions)"
            print(f"        {p}: {marker}")
            if profile_finding is None and allows and not denies:
                profile_finding = True
            if denies:
                profile_finding = False
        if not found_any:
            print("        (no virtiofsd/libvirt profiles found in /etc/apparmor.d/)")
            profile_finding = None

    # Combined judgement for check 2
    if parent_has_cap and profile_finding is not False:
        print()
        print("    -> parent has the cap and AppArmor is not a known blocker:")
        print("       virtiofsd should retain dac_read_search when started with")
        print("       --inode-file-handles=prefer or =mandatory.")
        pass_2 = True
    else:
        pass_2 = False
        print()
        print("    -> at least one prerequisite is missing or unclear.")

    # 3. Per-filesystem name_to_handle_at support under persistent-root
    sub("3. name_to_handle_at support per filesystem under persistent-root")
    if not PERSISTENT_ROOT.is_dir():
        print(f"    {PERSISTENT_ROOT} not a directory; skipping")
        pass_3 = False
    else:
        mountinfo = parse_mountinfo()
        seen: dict[int, tuple[str, Path | None]] = {}
        for token_dir in sorted(PERSISTENT_ROOT.iterdir()):
            if not token_dir.is_dir():
                continue
            try:
                st = token_dir.stat()
            except OSError:
                continue
            if st.st_dev in seen:
                continue
            sample: Path | None = None
            for root, _dirs, files in os.walk(token_dir):
                for fname in files:
                    p = Path(root) / fname
                    try:
                        st2 = p.lstat()
                        if (st2.st_mode & 0o170000) == 0o100000 and st2.st_dev == st.st_dev:
                            sample = p
                            break
                    except OSError:
                        continue
                if sample:
                    break
            seen[st.st_dev] = (token_dir.name, sample)

        if not seen:
            print("    (no token directories found)")
            pass_3 = False
        else:
            print(f"    {'token (first hit per fs)':50s}  {'fstype':8s}  result")
            for dev, (token, sample) in seen.items():
                maj, mnr = os.major(dev), os.minor(dev)
                fs_info = mountinfo.get((maj, mnr))
                fstype = fs_info[0] if fs_info else "?"
                if sample is None:
                    print(f"    {token:50s}  {fstype:8s}  (no regular file found to test)")
                    continue
                ok, msg = test_name_to_handle_at(sample)
                if not ok:
                    pass_3 = False
                print(f"    {token:50s}  {fstype:8s}  {msg}")

    # Verdict
    sub("verdict")
    results = [
        ("flag supported by virtiofsd", pass_1),
        ("running virtiofsd has CAP_DAC_READ_SEARCH", pass_2),
        ("filesystems support name_to_handle_at", pass_3),
    ]
    for label, ok in results:
        print(f"    [{'PASS' if ok else 'FAIL'}] {label}")
    overall = all(ok for _, ok in results)
    print()
    if overall:
        print("    All checks passed. --inode-file-handles=prefer should work.")
        print("    With 'prefer', any filesystem that does NOT support handles will")
        print("    silently fall back to per-FD inode caching; only 'mandatory'")
        print("    would refuse to start.")
    else:
        print("    Some checks failed; review above. Note that 'prefer' is still")
        print("    safe to try if (1) passes, since unsupported filesystems just")
        print("    fall back to per-FD caching; the win simply becomes partial.")

    sub("how to apply (suggested)")
    print("""\
    The cleanest non-invasive way is a tiny wrapper script:

        sudo mkdir -p /usr/local/libexec
        sudo tee /usr/local/libexec/aivm-virtiofsd >/dev/null <<'SH'
        #!/bin/bash
        exec /usr/libexec/virtiofsd --inode-file-handles=prefer "$@"
        SH
        sudo chmod +x /usr/local/libexec/aivm-virtiofsd

    Then in the libvirt domain XML for each VM, set the binary path on
    each <filesystem> device:

        <filesystem type='mount' accessmode='passthrough'>
          <driver type='virtiofs'/>
          <binary path='/usr/local/libexec/aivm-virtiofsd'/>
          ...
        </filesystem>

    Apply via `virsh edit <vm>`, then shut down and start the VM (live
    redefine of vhost-user-fs devices is unreliable). After restart, run
    the virtiofsd_emfile_mwe.py guest demo against geowatch again and
    compare host virtiofsd FD count: if file-handles are in use, the FD
    count should NOT scale with the working set the way it did before.""")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
