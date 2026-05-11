#!/usr/bin/env python3
"""
MWE for the virtiofsd-EMFILE hypothesis.

Hypothesis under test
---------------------
A guest process can see ``OSError(EMFILE, "Too many open files")`` from a
single ``open``/``listdir``/``statx`` on a virtiofs path even when:

  * the guest process holds very few file descriptors
  * the guest soft RLIMIT_NOFILE is very high (e.g. 1048576)
  * the guest ``/proc/sys/fs/file-nr`` is low

The hypothesis is that the EMFILE actually comes from ``virtiofsd`` on the
HOST hitting its own RLIMIT_NOFILE. virtiofsd by default holds one host file
descriptor per cached inode; once it reaches its soft limit it cannot accept
any new lookups and FUSE propagates ``EMFILE`` back to the guest VFS, which
surfaces it on whichever syscall happened to trigger the next inode lookup.

What this MWE measures, and where the numbers come from
-------------------------------------------------------
There are two distinct sides. Every line of output is tagged ``[HOST]`` or
``[GUEST]`` so it is unambiguous which kernel produced the number.

  [HOST]  inputs:
    /proc/<virtiofsd_pid>/limits      -> virtiofsd RLIMIT_NOFILE soft/hard
    /proc/<virtiofsd_pid>/fd          -> host FDs currently held by virtiofsd
    /proc/<virtiofsd_pid>/cmdline     -> source=..., --inode-file-handles=...
    systemctl show libvirtd virtqemud -> inherited LimitNOFILE

  [GUEST] inputs:
    resource.getrlimit(RLIMIT_NOFILE) -> guest process FD limit
    /proc/sys/fs/file-nr, file-max    -> guest kernel file-table state
    /proc/self/fd                     -> FDs held by this guest process
    open()/listdir() return codes     -> the actual symptom

How to run end-to-end
---------------------
The MWE is one file. Copy it to both sides if needed.

  1. On the HOST (the machine running libvirt + virtiofsd), one-shot:

         sudo python3 virtiofsd_emfile_mwe.py host probe

     Note the ``NOFILE soft`` value for each virtiofsd serving your VM.

  2. On the HOST, in a separate terminal, run the watcher during the test:

         sudo python3 virtiofsd_emfile_mwe.py host watch \\
             --interval 0.5 --duration 300 | tee host-watch.log

  3. On the GUEST (inside the VM), one-shot:

         python3 virtiofsd_emfile_mwe.py guest probe

  4. On the GUEST, run the demonstration against a virtiofs path:

         python3 virtiofsd_emfile_mwe.py guest demo \\
             /mnt/aivm-persistent/hostcode-geowatch-5f1a05ef \\
             --hold 5000

     This opens files one at a time inside the virtiofs subtree and holds
     each FD open. Every guest-side open() forces virtiofsd on the host to
     hold a matching inode FD.

  5. Look at host-watch.log around the moment the guest reported its first
     EMFILE. If virtiofsd's open-FD count is near ``NOFILE soft`` at that
     instant, while the guest process still has plenty of FDs, the
     hypothesis is supported.

How to read the result
----------------------
Confirms hypothesis:
    [GUEST] EMFILE happens
    [GUEST] self_fd_count is small (e.g. < 100k) and well under guest RLIMIT
    [HOST]  virtiofsd open_fds  ~  virtiofsd NOFILE soft

Refutes hypothesis:
    [GUEST] EMFILE happens *and* self_fd_count is near guest RLIMIT
        -> the guest process itself ran out of FDs, not virtiofsd.
    [GUEST] EMFILE happens *and* /proc/sys/fs/file-nr is near file-max
        -> guest kernel file table is exhausted, not virtiofsd.
    [HOST]  virtiofsd open_fds stays far below NOFILE soft during repro
        -> EMFILE is coming from somewhere else (virtio-fs kernel bug,
           per-mount limit, etc.).

Mitigation experiments (run separately, not part of this MWE)
-------------------------------------------------------------
  * Raise virtiofsd NOFILE via systemd drop-in for virtqemud/libvirtd:
        [Service]
        LimitNOFILE=1048576
  * Pass ``--inode-file-handles=prefer`` (or ``mandatory``) to virtiofsd
    so it uses ``name_to_handle_at`` + ``open_by_handle_at`` instead of
    keeping a long-lived FD per cached inode.
After either change, redefine the domain so virtiofsd respawns, and rerun
this MWE. If the hypothesis is correct, the EMFILE should no longer trigger
at the same opening count.
"""

from __future__ import annotations

import argparse
import errno
import os
import resource
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path


def _read_proc_limits(pid):
    """Return parsed /proc/<pid>/limits or None."""
    try:
        with open(f"/proc/{pid}/limits") as f:
            text = f.read()
    except FileNotFoundError:
        return None
    except PermissionError:
        return {"_error": f"PermissionError reading /proc/{pid}/limits (try sudo)"}
    out = {}
    for line in text.splitlines():
        if line.startswith("Limit") or not line.strip():
            continue
        name = line[:26].strip()
        rest = line[26:].split()
        if not rest:
            continue
        out[name] = {
            "soft": rest[0],
            "hard": rest[1] if len(rest) > 1 else "",
            "unit": rest[2] if len(rest) > 2 else "",
        }
    return out


def _count_fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except FileNotFoundError:
        return -1
    except PermissionError:
        return -2


def _get_argv(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError):
        return []
    return [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]


def _find_virtiofsd_pids():
    """Find real virtiofsd processes by exe basename.

    Avoids matching unrelated processes that just happen to mention
    "virtiofsd" in their cmdline (e.g. this MWE itself).
    """
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid_path = f"/proc/{entry}"
        try:
            exe = os.readlink(f"{pid_path}/exe")
        except (FileNotFoundError, PermissionError, OSError):
            exe = ""
        if os.path.basename(exe) == "virtiofsd":
            pids.append(int(entry))
            continue
        try:
            with open(f"{pid_path}/comm") as f:
                comm = f.read().strip()
        except (FileNotFoundError, PermissionError):
            continue
        if comm == "virtiofsd":
            pids.append(int(entry))
    return sorted(pids)


def _virtiofsd_summary(pid):
    argv = _get_argv(pid)
    source = next(
        (a.split("source=", 1)[1] for a in argv if "source=" in a),
        "<unknown>",
    )
    ifh = "<unset: default per-fd inode caching>"
    for a in argv:
        if a.startswith("--inode-file-handles="):
            ifh = a.split("=", 1)[1]
    limits = _read_proc_limits(pid) or {}
    nofile = limits.get("Max open files", {})
    return {
        "pid": pid,
        "source": source,
        "inode_file_handles": ifh,
        "nofile_soft": nofile.get("soft", "?"),
        "nofile_hard": nofile.get("hard", "?"),
        "fds": _count_fds(pid),
        "argv": argv,
    }


def host_probe(_args):
    print("[HOST] one-shot snapshot of virtiofsd processes")
    print("[HOST] (run on the libvirt/KVM host, not inside a VM)")
    print()
    pids = _find_virtiofsd_pids()
    if not pids:
        print("[HOST] no virtiofsd processes found. Is libvirt running? VM up?")
        return 2
    for pid in pids:
        s = _virtiofsd_summary(pid)
        print(f"[HOST] --- virtiofsd pid={s['pid']}")
        print(f"[HOST]     source                = {s['source']}")
        print(f"[HOST]     --inode-file-handles  = {s['inode_file_handles']}")
        print(f"[HOST]     RLIMIT_NOFILE (soft)  = {s['nofile_soft']}")
        print(f"[HOST]     RLIMIT_NOFILE (hard)  = {s['nofile_hard']}")
        print(f"[HOST]     open FDs now          = {s['fds']}")
        print(f"[HOST]     cmdline               = "
              f"{' '.join(shlex.quote(a) for a in s['argv'])}")
        print()

    print("[HOST] inherited systemd NOFILE for libvirt daemons:")
    systemctl = shutil.which("systemctl")
    for unit in ("libvirtd", "virtqemud"):
        if not systemctl:
            break
        r = subprocess.run(
            [systemctl, "show", unit, "-p", "LimitNOFILE", "-p", "LimitNOFILESoft"],
            capture_output=True, text=True, check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.strip().splitlines():
                print(f"[HOST]     {unit}: {line}")

    print()
    print("[HOST] interpretation hints:")
    print("[HOST]   - If NOFILE soft <= 8192 for any virtiofsd that serves a")
    print("[HOST]     directory the guest actively traverses, EMFILE is very")
    print("[HOST]     plausible. Production-grade values are >= 1048576.")
    print("[HOST]   - If --inode-file-handles is unset, virtiofsd holds one")
    print("[HOST]     host FD per cached inode; that is the worst case for")
    print("[HOST]     this failure mode.")
    return 0


def host_watch(args):
    print("[HOST] watcher: polling virtiofsd open-FD count")
    print(f"[HOST] interval={args.interval}s duration={args.duration}s")
    print("[HOST] columns: ts pid src_basename open_fds nofile_soft")
    deadline = time.time() + args.duration
    while time.time() < deadline:
        ts = time.strftime("%H:%M:%S")
        for pid in _find_virtiofsd_pids():
            s = _virtiofsd_summary(pid)
            print(
                f"[HOST] {ts} pid={pid} src={Path(s['source']).name} "
                f"fds={s['fds']} nofile_soft={s['nofile_soft']}",
                flush=True,
            )
        time.sleep(args.interval)
    return 0


def guest_probe(_args):
    print("[GUEST] one-shot snapshot")
    print("[GUEST] (run inside the VM)")
    print()
    try:
        with open("/sys/class/dmi/id/sys_vendor") as f:
            print(f"[GUEST] sys_vendor       = {f.read().strip()}")
    except FileNotFoundError:
        pass

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"[GUEST] RLIMIT_NOFILE    = soft={soft} hard={hard}")

    for path, label in (
        ("/proc/sys/fs/file-nr", "file-nr (alloc free max)"),
        ("/proc/sys/fs/file-max", "file-max"),
        ("/proc/sys/fs/nr_open", "nr_open"),
    ):
        try:
            with open(path) as f:
                print(f"[GUEST] {label:24s} = {f.read().strip()}")
        except FileNotFoundError:
            pass

    print(f"[GUEST] self open FDs    = {_count_fds('self')}")

    print()
    print("[GUEST] virtiofs mounts visible inside guest:")
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                if "virtiofs" in line:
                    print("[GUEST]     " + line.rstrip())
    except FileNotFoundError:
        pass
    return 0


def guest_demo(args):
    """Open files inside `path` and hold them, reporting the first error.

    Every guest-side ``open()`` of a regular file forces virtiofsd on the
    host to hold (or look up) a matching inode reference. With the default
    ``--inode-file-handles`` setting that means one host FD per opened file.
    """
    target = Path(args.path)
    if not target.exists():
        print(f"[GUEST] error: target does not exist: {target}")
        return 2

    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"[GUEST] demo target      = {target}")
    print(f"[GUEST] guest soft RLIMIT_NOFILE = {soft}")
    print(f"[GUEST] self open FDs at start   = {_count_fds('self')}")
    print(f"[GUEST] will hold up to {args.hold} files open")
    print()

    held = []
    files_iter = _iter_regular_files(target, args.max_walk)

    try:
        for i, fpath in enumerate(files_iter):
            if i >= args.hold:
                break
            try:
                fd = os.open(fpath, os.O_RDONLY)
                held.append(fd)
            except OSError as ex:
                self_fd = _count_fds("self")
                print(f"[GUEST] !! os.open failed at i={i}: {ex!r}")
                print(f"[GUEST]    path:           {fpath}")
                print(f"[GUEST]    errno:          {errno.errorcode.get(ex.errno, ex.errno)}")
                print(f"[GUEST]    self_fd_count:  {self_fd}")
                _guest_post_failure_probes(target)
                return _classify(ex, self_fd, soft)

            if (i + 1) % args.progress == 0:
                self_fd = _count_fds("self")
                print(f"[GUEST]    progress i={i + 1} self_fd_count={self_fd}", flush=True)

        print(f"[GUEST] held {len(held)} files open without error.")
        print(f"[GUEST] self_fd_count={_count_fds('self')}")
        print("[GUEST] running post-hold listdir/statx probes...")
        _guest_post_failure_probes(target)
        return 0
    finally:
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                pass


def _iter_regular_files(root: Path, max_walk: int):
    """Yield regular file paths under `root` (no follow_symlinks)."""
    count = 0
    for cur, dirs, files in os.walk(root, followlinks=False):
        for name in files:
            p = os.path.join(cur, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if (st.st_mode & 0o170000) != 0o100000:
                continue
            yield p
            count += 1
            if max_walk and count >= max_walk:
                return


def _guest_post_failure_probes(target: Path):
    """Run the same syscalls the original report saw failing: listdir, statx."""
    print("[GUEST]    listdir probe:")
    try:
        n = len(os.listdir(target))
        print(f"[GUEST]      listdir({target}) -> {n} entries (OK)")
    except OSError as ex:
        print(f"[GUEST]      listdir({target}) -> {ex!r}")

    print("[GUEST]    statx probe (os.stat on a few entries):")
    try:
        for name in list(os.listdir(target))[:3]:
            p = os.path.join(str(target), name)
            try:
                os.stat(p, follow_symlinks=False)
                print(f"[GUEST]      stat({p}) -> OK")
            except OSError as ex:
                print(f"[GUEST]      stat({p}) -> {ex!r}")
    except OSError as ex:
        print(f"[GUEST]      listdir for statx probe failed: {ex!r}")


def _classify(ex: OSError, self_fd: int, guest_soft_rlimit: int) -> int:
    """Print a short verdict and return an exit code."""
    print()
    print("[GUEST] ---- verdict ----")
    if ex.errno == errno.EMFILE:
        if self_fd < guest_soft_rlimit // 2:
            print("[GUEST] EMFILE while self_fd_count is far below guest "
                  "RLIMIT_NOFILE.")
            print("[GUEST] This is the signature predicted by the "
                  "virtiofsd-RLIMIT hypothesis.")
            print("[GUEST] Check the [HOST] watch log: virtiofsd open_fds "
                  "should be near its NOFILE soft.")
            return 0
        print("[GUEST] EMFILE but self_fd_count is also near guest RLIMIT; "
              "the guest process itself is the bottleneck.")
        return 0
    if ex.errno == errno.ENFILE:
        print("[GUEST] ENFILE = guest kernel file table exhausted. Check "
              "/proc/sys/fs/file-nr vs file-max.")
        return 0
    print(f"[GUEST] unexpected errno {errno.errorcode.get(ex.errno, ex.errno)}; "
          "not the predicted failure mode.")
    return 3


def main():
    p = argparse.ArgumentParser(
        description=(
            "MWE to test the hypothesis that guest-side EMFILE on virtiofs "
            "paths is caused by host-side virtiofsd hitting RLIMIT_NOFILE."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for the full host/guest workflow.",
    )
    sub = p.add_subparsers(dest="side", required=True)

    h = sub.add_parser("host", help="commands to run on the libvirt host")
    hsub = h.add_subparsers(dest="cmd", required=True)
    hsub.add_parser("probe", help="one-shot snapshot of virtiofsd state")
    w = hsub.add_parser("watch", help="continuously sample virtiofsd FD count")
    w.add_argument("--interval", type=float, default=0.5)
    w.add_argument("--duration", type=float, default=300.0)

    g = sub.add_parser("guest", help="commands to run inside the VM")
    gsub = g.add_subparsers(dest="cmd", required=True)
    gsub.add_parser("probe", help="one-shot snapshot of guest FD-related state")
    d = gsub.add_parser(
        "demo",
        help="open files inside a virtiofs path until something fails",
    )
    d.add_argument("path", help="virtiofs path (e.g. /mnt/aivm-persistent/<token>)")
    d.add_argument("--hold", type=int, default=5000,
                   help="how many files to open + hold")
    d.add_argument("--max-walk", type=int, default=0,
                   help="cap on files visited during the walk (0 = no cap)")
    d.add_argument("--progress", type=int, default=500,
                   help="print a progress line every N opens")

    args = p.parse_args()

    if args.side == "host" and args.cmd == "probe":
        return host_probe(args)
    if args.side == "host" and args.cmd == "watch":
        return host_watch(args)
    if args.side == "guest" and args.cmd == "probe":
        return guest_probe(args)
    if args.side == "guest" and args.cmd == "demo":
        return guest_demo(args)
    p.error("unhandled subcommand")
    return 1


if __name__ == "__main__":
    sys.exit(main())
