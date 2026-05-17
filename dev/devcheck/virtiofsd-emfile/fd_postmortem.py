#!/usr/bin/env python3
"""
Post-mortem helpers for a saturated virtiofsd FD table.

This tool is intentionally read-only except for the ``guest-drop-caches``
subcommand, which must be run explicitly and only writes to the guest kernel's
``/proc/sys/vm/drop_caches`` knob.  The host-side subcommands inspect procfs and
write evidence files under an output directory.

These helpers are for incident analysis.  They are not a cold-start
reproduction by themselves: ``collect``, ``watch``, and ``token-count`` are most
useful when run against an already-saturated or suspicious live virtiofsd
process.  For a reproducible growth demonstration from a clean VM, use
``../virtiofsd_emfile_mwe.py``.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as _datetime
import errno
import os
import re
import sys
import time
from pathlib import Path
from typing import Iterable


CAP_NAMES = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
]


@dataclasses.dataclass(frozen=True)
class VirtiofsdProc:
    pid: int
    ppid: int | None
    fds: int | None
    nofile_soft: str | None
    nofile_hard: str | None
    cap_eff_hex: str | None
    cap_bnd_hex: str | None
    state: str | None
    cmdline: str
    source: str | None


def now_stamp() -> str:
    return _datetime.datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def read_cmdline(pid: int) -> str:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return raw.replace(b"\0", b" ").decode(errors="replace").strip()


def read_status_fields(pid: int) -> dict[str, str]:
    text = read_text(Path(f"/proc/{pid}/status")) or ""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k] = v.strip()
    return out


def read_nofile_limits(pid: int) -> tuple[str | None, str | None]:
    text = read_text(Path(f"/proc/{pid}/limits")) or ""
    for line in text.splitlines():
        if line.startswith("Max open files"):
            parts = line.split()
            # Max open files <soft> <hard> files
            if len(parts) >= 6:
                return parts[3], parts[4]
    return None, None


def count_fds(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except PermissionError:
        return None
    except FileNotFoundError:
        return None


def extract_source(cmdline: str) -> str | None:
    # Handles both "-o source=/path" and raw "source=/path" spellings.
    match = re.search(r"(?:^|\s)source=([^\s,]+)", cmdline)
    if match:
        return match.group(1)
    return None


def iter_virtiofsd_procs() -> list[VirtiofsdProc]:
    procs: list[VirtiofsdProc] = []
    for item in sorted(Path("/proc").iterdir(), key=lambda p: p.name):
        if not item.name.isdigit():
            continue
        pid = int(item.name)
        comm = read_text(item / "comm")
        cmdline = ""
        if comm and comm.strip() == "virtiofsd":
            try:
                cmdline = read_cmdline(pid)
            except (PermissionError, FileNotFoundError, OSError):
                cmdline = ""
        else:
            try:
                cmdline = read_cmdline(pid)
            except (PermissionError, FileNotFoundError, OSError):
                continue
            if "virtiofsd" not in cmdline:
                continue
        status = read_status_fields(pid)
        soft, hard = read_nofile_limits(pid)
        try:
            ppid = int(status.get("PPid", ""))
        except ValueError:
            ppid = None
        procs.append(VirtiofsdProc(
            pid=pid,
            ppid=ppid,
            fds=count_fds(pid),
            nofile_soft=soft,
            nofile_hard=hard,
            cap_eff_hex=status.get("CapEff"),
            cap_bnd_hex=status.get("CapBnd"),
            state=status.get("State"),
            cmdline=cmdline,
            source=extract_source(cmdline),
        ))
    return procs


def select_hot_pid(procs: list[VirtiofsdProc], vm: str | None, pid: int | None) -> int:
    if pid is not None:
        return pid
    candidates = procs
    if vm:
        needle = f"/var/lib/libvirt/aivm/{vm}/persistent-root"
        candidates = [p for p in procs if p.source and needle in p.source]
    if not candidates:
        candidates = [p for p in procs if p.source and "persistent-root" in p.source]
    if not candidates:
        candidates = procs
    if not candidates:
        raise SystemExit("No virtiofsd processes found")
    # Permission-denied FD counts sort as -1 so visible counts win.
    best = max(candidates, key=lambda p: p.fds if p.fds is not None else -1)
    return best.pid


def decode_caps(hex_value: str | None) -> list[str]:
    if not hex_value:
        return []
    try:
        caps = int(hex_value, 16)
    except ValueError:
        return []
    out = []
    for idx, name in enumerate(CAP_NAMES):
        if caps & (1 << idx):
            out.append(name)
    return out


def iter_fd_targets(pid: int) -> Iterable[tuple[str, str]]:
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        names = sorted(fd_dir.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else -1)
    except PermissionError as ex:
        raise SystemExit(
            f"Permission denied reading {fd_dir}. Re-run with sudo for FD target audits."
        ) from ex
    except FileNotFoundError as ex:
        raise SystemExit(f"Process {pid} no longer exists") from ex
    for entry in names:
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        except PermissionError:
            target = "<permission-denied>"
        except OSError as ex:
            target = f"<readlink-error errno={ex.errno}>"
        yield entry.name, target


def normalize_target(target: str) -> str:
    if target.endswith(" (deleted)"):
        return target[:-10]
    return target


def suffix_key(target: str) -> str:
    target = normalize_target(target)
    base = target.rsplit("/", 1)[-1]
    if base in {"0", "1", "2"}:
        return "stdio"
    for ext in [
        ".tar.gz",
        ".jsonl",
        ".dist-info",
        ".timestamp",
        ".history",
        ".latest",
        ".typed",
        ".rlib",
        ".rmeta",
        ".pyc",
        ".pyi",
        ".py",
        ".json",
        ".txt",
        ".csv",
        ".html",
        ".bin",
        ".lock",
        ".so",
        ".o",
        ".png",
        ".jpg",
        ".jpeg",
        ".h",
        ".hpp",
        ".sh",
        ".md",
        ".rst",
        ".yaml",
        ".yml",
    ]:
        if base.endswith(ext):
            return ext
    match = re.search(r"(\.[A-Za-z0-9_+-]{1,16})$", base)
    return match.group(1) if match else "<no-ext>"


def aggregate_targets(targets: Iterable[str]) -> dict[str, collections.Counter[str]]:
    counters = {
        "by_hostcode_token": collections.Counter(),
        "by_token_topdir": collections.Counter(),
        "by_token_topdir_seconddir": collections.Counter(),
        "by_suffix": collections.Counter(),
        "other_special_kinds": collections.Counter(),
    }
    for target in targets:
        target = normalize_target(target)
        if target.startswith("/hostcode-"):
            parts = target.split("/")
            token = parts[1] if len(parts) > 1 else ""
            counters["by_hostcode_token"][token] += 1
            if len(parts) >= 3:
                counters["by_token_topdir"]["/" + "/".join(parts[1:3])] += 1
            else:
                counters["by_token_topdir"]["/" + token] += 1
            if len(parts) >= 4:
                counters["by_token_topdir_seconddir"]["/" + "/".join(parts[1:4])] += 1
            else:
                counters["by_token_topdir_seconddir"]["/" + token] += 1
        elif target.startswith("/"):
            root = target.split("/", 2)[1]
            counters["other_special_kinds"]["absolute-non-hostcode:" + root] += 1
        else:
            root = target.split(":", 1)[0]
            counters["other_special_kinds"]["non-path-or-special:" + root] += 1
        counters["by_suffix"][suffix_key(target)] += 1
    return counters


def write_counter(path: Path, counter: collections.Counter[str], limit: int = 80) -> None:
    total = sum(counter.values())
    shown = 0
    with path.open("w") as f:
        f.write(f"TOTAL\t{total}\n")
        f.write("count\tpercent\tkey\n")
        for key, value in counter.most_common(limit):
            shown += value
            pct = (100.0 * value / total) if total else 0.0
            f.write(f"{value}\t{pct:.4f}\t{key}\n")
        pct = (100.0 * shown / total) if total else 0.0
        f.write(f"SHOWN\t{pct:.4f}\t{shown}\n")


def human_section_name(name: str) -> str:
    return name.replace("_", " ")


def render_counter_section(
    name: str,
    counter: collections.Counter[str],
    limit: int = 40,
) -> str:
    total = sum(counter.values())
    shown = 0
    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append(human_section_name(name))
    lines.append("=" * 80)
    if not total:
        lines.append("         0    0.00%  <empty>")
        return "\n".join(lines)
    for key, value in counter.most_common(limit):
        shown += value
        lines.append(f"{value:10d}  {100.0 * value / total:6.2f}%  {key}")
    lines.append(f"{'SHOWN':>10s}  {100.0 * shown / total:6.2f}%")
    lines.append(f"{'TOTAL':>10s}  {100.0:6.2f}%  {total}")
    return "\n".join(lines)


def render_aggregate_report(
    counters: dict[str, collections.Counter[str]],
    *,
    title: str = "virtiofsd FD target aggregate",
    source: str | None = None,
    pid: int | None = None,
    report_limit: int = 40,
) -> str:
    lines = []
    lines.append(title)
    lines.append("=" * len(title))
    lines.append("")
    lines.append(f"date: {_datetime.datetime.now().astimezone().isoformat()}")
    if source:
        lines.append(f"source: {source}")
    if pid is not None:
        lines.append(f"pid: {pid}")
    total = max((sum(c.values()) for c in counters.values()), default=0)
    lines.append(f"targets: {total}")
    lines.append("")
    lines.append(
        "This is a shareable text summary.  The TSV files beside it contain "
        "the same aggregate counters in machine-readable form."
    )
    for name in [
        "by_hostcode_token",
        "by_token_topdir",
        "by_token_topdir_seconddir",
        "by_suffix",
        "other_special_kinds",
    ]:
        if name in counters:
            lines.append(render_counter_section(name, counters[name], limit=report_limit))
    lines.append("")
    return "\n".join(lines)


def write_aggregate_bundle(
    out: Path,
    counters: dict[str, collections.Counter[str]],
    *,
    source: str | None = None,
    pid: int | None = None,
    aggregate_limit: int = 80,
    report_limit: int = 40,
) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    for name, counter in counters.items():
        write_counter(out / f"aggregate-{name}.tsv", counter, limit=aggregate_limit)
    report = render_aggregate_report(
        counters,
        source=source,
        pid=pid,
        report_limit=report_limit,
    )
    report_path = out / "aggregate-report.txt"
    report_path.write_text(report)
    return report_path


def default_aggregate_outdir(fd_targets: Path) -> Path:
    # Avoid writing multiple files into the caller's current working directory by
    # default.  Keep derived aggregate artifacts next to the evidence input, in
    # their own timestamped subfolder.
    parent = fd_targets.resolve().parent
    stem = fd_targets.stem or "fd-targets"
    return parent / f"{stem}-aggregate-{now_stamp()}"


def render_inventory(procs: list[VirtiofsdProc]) -> str:
    lines = []
    lines.append("PID\tPPID\tFDS\tNOFILE_SOFT\tNOFILE_HARD\tCAP_EFF\tCAP_BND\tSOURCE\tCMDLINE")
    for p in procs:
        lines.append("\t".join([
            str(p.pid),
            "" if p.ppid is None else str(p.ppid),
            "permission-denied" if p.fds is None else str(p.fds),
            p.nofile_soft or "",
            p.nofile_hard or "",
            p.cap_eff_hex or "",
            p.cap_bnd_hex or "",
            p.source or "",
            p.cmdline,
        ]))
    return "\n".join(lines) + "\n"


def command_collect(args: argparse.Namespace) -> int:
    procs = iter_virtiofsd_procs()
    pid = select_hot_pid(procs, args.vm, args.pid)
    out = Path(args.out or f"virtiofsd-incident-{now_stamp()}")
    out.mkdir(parents=True, exist_ok=True)

    proc_by_pid = {p.pid: p for p in procs}
    hot = proc_by_pid.get(pid)
    if hot is None:
        # The user may have supplied a PID that disappeared between scan and selection.
        hot = VirtiofsdProc(
            pid=pid,
            ppid=None,
            fds=count_fds(pid),
            nofile_soft=None,
            nofile_hard=None,
            cap_eff_hex=None,
            cap_bnd_hex=None,
            state=None,
            cmdline="",
            source=None,
        )

    (out / "virtiofsd-inventory.tsv").write_text(render_inventory(procs))

    summary_lines = []
    summary_lines.append(f"date: {_datetime.datetime.now().astimezone().isoformat()}")
    summary_lines.append(f"hostname: {os.uname().nodename}")
    summary_lines.append(f"vm: {args.vm or ''}")
    summary_lines.append(f"hot_pid: {pid}")
    summary_lines.append(f"hot_source: {hot.source or ''}")
    summary_lines.append(f"hot_cmdline: {hot.cmdline}")
    summary_lines.append(f"hot_fds: {hot.fds}")
    summary_lines.append(f"hot_nofile: {hot.nofile_soft}/{hot.nofile_hard}")
    summary_lines.append(f"hot_state: {hot.state or ''}")
    summary_lines.append(f"hot_ppid: {hot.ppid or ''}")
    summary_lines.append(f"hot_cap_eff: {hot.cap_eff_hex or ''}")
    summary_lines.append(f"hot_cap_bnd: {hot.cap_bnd_hex or ''}")
    cap_names = decode_caps(hot.cap_eff_hex)
    summary_lines.append("hot_cap_eff_decoded: " + ", ".join(cap_names))
    summary_lines.append(
        "hot_has_CAP_DAC_READ_SEARCH: "
        + str("CAP_DAC_READ_SEARCH" in cap_names)
    )
    (out / "summary.txt").write_text("\n".join(summary_lines) + "\n")

    fd_target_path = out / "fd-targets.tsv"
    targets: list[str] = []
    with fd_target_path.open("w") as f:
        f.write("fd\ttarget\n")
        for fd, target in iter_fd_targets(pid):
            f.write(f"{fd}\t{target}\n")
            targets.append(target)
            if args.sample_limit and len(targets) >= args.sample_limit:
                break

    counters = aggregate_targets(targets)
    report_path = write_aggregate_bundle(
        out / "aggregate",
        counters,
        source=str(fd_target_path),
        pid=pid,
        aggregate_limit=args.aggregate_limit,
        report_limit=args.report_limit,
    )

    readme = out / "README.txt"
    readme.write_text(
        "This directory was produced by fd_postmortem.py collect.\n"
        "The evidence is a post-mortem snapshot of a live virtiofsd process, not\n"
        "a cold-start reproducer.  Use ../virtiofsd_emfile_mwe.py for controlled\n"
        "reproduction experiments from a clean VM.\n"
        "\n"
        "The aggregate/ subdirectory contains aggregate-report.txt, which is the\n"
        "compact shareable report to paste into an issue or chat, plus TSV counter\n"
        "files for machine-readable follow-up.\n"
    )
    print(f"wrote {out}")
    print(f"hot_pid={pid} hot_fds={hot.fds} hot_source={hot.source}")
    print(f"aggregate_report={report_path}")
    if args.print_report:
        print()
        print(report_path.read_text())
    return 0


def read_targets_file(path: Path) -> list[str]:
    targets: list[str] = []
    for idx, line in enumerate(path.read_text(errors="replace").splitlines()):
        line = line.rstrip("\n")
        if idx == 0 and line.startswith("fd\t"):
            continue
        if "\t" in line:
            left, target = line.split("\t", 1)
            if left == "fd" or left.strip().isdigit():
                targets.append(target)
            continue
        if " -> " in line:
            left, target = line.split(" -> ", 1)
            left = left.strip()
            # Accept normal `find /proc/$pid/fd -printf '%p -> %l'` output,
            # but ignore shell commands pasted in front of that output.
            if re.search(r"/proc/[0-9]+/fd/[0-9]+$", left) or left.isdigit():
                targets.append(target)
    return targets


def command_aggregate(args: argparse.Namespace) -> int:
    fd_targets = Path(args.fd_targets)
    targets = read_targets_file(fd_targets)
    out = Path(args.out) if args.out else default_aggregate_outdir(fd_targets)
    counters = aggregate_targets(targets)
    report_path = write_aggregate_bundle(
        out,
        counters,
        source=str(fd_targets),
        aggregate_limit=args.aggregate_limit,
        report_limit=args.report_limit,
    )
    print(f"aggregated {len(targets)} targets into {out}")
    print(f"aggregate_report={report_path}")
    if args.print_report:
        print()
        print(report_path.read_text())
    return 0


def command_watch(args: argparse.Namespace) -> int:
    procs = iter_virtiofsd_procs()
    pid = select_hot_pid(procs, args.vm, args.pid)
    stop_time = None if args.duration is None else (time.time() + args.duration)
    print("timestamp\tpid\tfds\tnofile_soft\tnofile_hard")
    while True:
        soft, hard = read_nofile_limits(pid)
        fds = count_fds(pid)
        print(f"{_datetime.datetime.now().astimezone().isoformat()}\t{pid}\t{fds}\t{soft}\t{hard}", flush=True)
        if stop_time is not None and time.time() >= stop_time:
            break
        time.sleep(args.interval)
    return 0


def command_token_count(args: argparse.Namespace) -> int:
    procs = iter_virtiofsd_procs()
    pid = select_hot_pid(procs, args.vm, args.pid)
    token = args.token
    prefix = "/" + token.strip("/") + "/"

    def one_count() -> tuple[int, int]:
        total = 0
        token_total = 0
        for _, target in iter_fd_targets(pid):
            total += 1
            if normalize_target(target).startswith(prefix):
                token_total += 1
        return token_total, total

    if args.watch:
        print("timestamp\tpid\ttoken\ttoken_fds\ttotal_fds")
        stop_time = None if args.duration is None else (time.time() + args.duration)
        while True:
            token_total, total = one_count()
            print(
                f"{_datetime.datetime.now().astimezone().isoformat()}\t{pid}\t{token}\t{token_total}\t{total}",
                flush=True,
            )
            if stop_time is not None and time.time() >= stop_time:
                break
            time.sleep(args.interval)
    else:
        token_total, total = one_count()
        print(f"pid={pid}")
        print(f"token={token}")
        print(f"token_fds={token_total}")
        print(f"total_fds={total}")
    return 0


def command_decode_caps(args: argparse.Namespace) -> int:
    status = read_status_fields(args.pid)
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        value = status.get(key)
        if value:
            names = decode_caps(value)
            print(f"{key}: {value}")
            print("  " + ", ".join(names))
            if key == "CapEff":
                print(f"  has CAP_DAC_READ_SEARCH: {'CAP_DAC_READ_SEARCH' in names}")
    return 0


def command_guest_drop_caches(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise SystemExit("guest-drop-caches must run as root inside the guest, e.g. sudo python3 ...")
    print("sync()")
    os.sync()
    for value in args.values:
        if value not in {1, 2, 3}:
            raise SystemExit("drop_caches values must be 1, 2, or 3")
        print(f"writing {value} to /proc/sys/vm/drop_caches")
        try:
            Path("/proc/sys/vm/drop_caches").write_text(str(value) + "\n")
        except OSError as ex:
            if ex.errno == errno.EROFS:
                raise SystemExit("/proc/sys/vm/drop_caches is read-only in this environment") from ex
            raise
        if args.sleep:
            time.sleep(args.sleep)
    print("done")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Post-mortem helpers for analyzing saturated virtiofsd FD tables.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("collect", help="Collect a host-side incident evidence bundle")
    p.add_argument("--vm", default=os.environ.get("AIVM_VM", "aivm-2404"))
    p.add_argument("--pid", type=int, default=None, help="virtiofsd PID; default is busiest persistent-root worker")
    p.add_argument("--out", default=None, help="output directory")
    p.add_argument("--sample-limit", type=int, default=0, help="limit FD target audit for quick samples; 0 means all")
    p.add_argument("--aggregate-limit", type=int, default=80, help="rows to write in each aggregate TSV")
    p.add_argument("--report-limit", type=int, default=40, help="rows to show in the shareable text report")
    p.add_argument("--no-print-report", dest="print_report", action="store_false", help="do not print the shareable aggregate report to stdout")
    p.set_defaults(func=command_collect, print_report=True)

    p = sub.add_parser("aggregate", help="Aggregate an existing fd-targets.tsv or 'fd -> target' file")
    p.add_argument("fd_targets")
    p.add_argument("--out", default=None, help="output directory; default is a timestamped subfolder next to fd_targets")
    p.add_argument("--aggregate-limit", type=int, default=80, help="rows to write in each aggregate TSV")
    p.add_argument("--report-limit", type=int, default=40, help="rows to show in the shareable text report")
    p.add_argument("--no-print-report", dest="print_report", action="store_false", help="write report files but do not print the report to stdout")
    p.set_defaults(func=command_aggregate, print_report=True)

    p = sub.add_parser("watch", help="Watch FD count for a virtiofsd process")
    p.add_argument("--vm", default=os.environ.get("AIVM_VM", "aivm-2404"))
    p.add_argument("--pid", type=int, default=None)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--duration", type=float, default=None)
    p.set_defaults(func=command_watch)

    p = sub.add_parser("token-count", help="Count FD targets under one /hostcode-* token")
    p.add_argument("token", help="token name, e.g. hostcode-crfm-helm-audit-st-8bd60e77")
    p.add_argument("--vm", default=os.environ.get("AIVM_VM", "aivm-2404"))
    p.add_argument("--pid", type=int, default=None)
    p.add_argument("--watch", action="store_true")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--duration", type=float, default=None)
    p.set_defaults(func=command_token_count)

    p = sub.add_parser("decode-caps", help="Decode Linux capability hex fields for a process")
    p.add_argument("pid", type=int)
    p.set_defaults(func=command_decode_caps)

    p = sub.add_parser("guest-drop-caches", help="Guest-side incident experiment: sync and drop caches")
    p.add_argument("--values", type=int, nargs="+", default=[2, 3], help="drop_caches values to write")
    p.add_argument("--sleep", type=float, default=30.0, help="seconds between writes")
    p.set_defaults(func=command_guest_drop_caches)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
