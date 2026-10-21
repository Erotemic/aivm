#!/usr/bin/env python3
"""Replay the guest-local attachment manifest, or verify one foreground path.

Verified bindings get a private reference under /run/aivm-persistent-mounts.
That reference pins the original directory object even when virtiofs recreates
its source automount. Only that proof (or explicit kernel token provenance)
permits an idle foreground rebind; busy and unidentified mounts are preserved.
References are boot-local, root-controlled, and pruned during lifecycle replay.
"""

import argparse
import fcntl
import hashlib
import json
import os
import posixpath
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

Record = dict[str, Any]
AcceptedRecord = tuple[str, bool, Record]
MountInfo = dict[str, str]

PERSISTENT_ROOT_TAG = "aivm-persistent-root"
PERSISTENT_ROOT_MOUNT = "/mnt/aivm-persistent"
# Guest replay is intentionally fed only from the VM-local manifest
# that the host syncs in. The helper must never read host desired state
# back through virtiofs.
STATE_DIR = "/var/lib/aivm"
STATE_PATH = "/var/lib/aivm/attachments.json"
DEGRADED_EXIT = 3
REPAIR_EXIT = 10
PROVENANCE_ROOT = "/run/aivm-persistent-mounts"


def provenance_directory(*, create: bool = True) -> Path:
    """Only root may create or replace the kernel references used as proof."""
    path = Path(PROVENANCE_ROOT)
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError(f"unsafe persistent mount provenance directory: {path}")
    return path


class ReplayLock:
    """Serialize boot replay, foreground recovery, and provenance updates."""

    def __enter__(self):
        path = provenance_directory() / "lock"
        self.fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            os.close(self.fd)
            raise RuntimeError(f"unsafe persistent mount replay lock: {path}")
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        os.close(self.fd)


def provenance_path(record: Record) -> str:
    key = normalize_guest_dst(record.get("guest_dst")) + "\0" + str(record["shared_root_token"])
    return str(Path(PROVENANCE_ROOT) / hashlib.sha256(key.encode()).hexdigest())


def has_pinned_provenance(record: Record) -> bool:
    path = provenance_path(record)
    # Never infer identity across virtiofs superblocks. A private bind keeps
    # the original object alive, preventing inode/device reuse from forging it.
    try:
        provenance_directory(create=False)
    except FileNotFoundError:
        return False
    return is_mountpoint(path) and same_directory_object(path, str(record["guest_dst"]))


def remember_provenance(record: Record) -> None:
    source, target = mount_source_for(record), str(record["guest_dst"])
    if not same_directory_object(source, target):
        return
    provenance_directory()
    path = provenance_path(record)
    if is_mountpoint(path):
        if same_directory_object(path, target):
            return
        unmount_guest_dst(path)
    # The protected parent, not the mounted directory's ownership, is the
    # authority boundary. Mounted source directories may belong to the user.
    Path(path).mkdir(mode=0o700, exist_ok=True)
    if Path(path).is_symlink():
        raise RuntimeError(f"symlink in persistent mount provenance: {path}")
    run(["mount", "--bind", target, path])
    run(["mount", "--make-private", path])
    if not same_directory_object(path, target):
        raise RuntimeError(f"could not pin persistent mount provenance: {path}")


def prune_provenance(records: Sequence[AcceptedRecord]) -> None:
    desired = {provenance_path(record) for _, enabled, record in records if enabled}
    for path in provenance_directory().iterdir():
        if path.name == "lock" or str(path) in desired:
            continue
        if len(path.name) != 64 or any(c not in "0123456789abcdef" for c in path.name):
            raise RuntimeError(f"unexpected persistent mount provenance entry: {path}")
        unmount_guest_dst(str(path))
        path.rmdir()

class SourceUnavailableError(RuntimeError):
    pass

class LiveMountConflictError(RuntimeError):
    pass

def run(
    cmd: Sequence[str], *, check: bool = True, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )

def mount_persistent_root() -> None:
    os.makedirs(PERSISTENT_ROOT_MOUNT, exist_ok=True)
    probe = subprocess.run(["mountpoint", "-q", PERSISTENT_ROOT_MOUNT])
    if probe.returncode == 0:
        return
    run(["mount", "-t", "virtiofs", PERSISTENT_ROOT_TAG, PERSISTENT_ROOT_MOUNT])

def load_json(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"persistent attachment manifest missing from guest state dir: {path}"
        )

def normalize_guest_dst(raw: object) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    text = posixpath.normpath(text)
    if not text.startswith("/"):
        return ""
    return text

def desired_option(record: Record) -> str:
    return "ro" if str(record.get("access") or "").strip() == "ro" else "rw"

def mount_source_for(record: Record) -> str:
    token = str(record.get("shared_root_token") or "").strip()
    if not token:
        return ""
    return str(PurePosixPath(PERSISTENT_ROOT_MOUNT) / token)

def parse_findmnt_pairs(stdout: str) -> dict[str, str]:
    values = {}
    for token in (stdout or "").split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        values[key.strip().upper()] = value.strip().strip('"')
    return values

def is_mountpoint(target: str) -> bool:
    probe = subprocess.run(["mountpoint", "-q", target])
    return probe.returncode == 0

def same_directory_object(left: str, right: str) -> bool:
    try:
        left_info = os.stat(left)
        right_info = os.stat(right)
    except OSError:
        return False
    return (left_info.st_dev, left_info.st_ino) == (
        right_info.st_dev,
        right_info.st_ino,
    )

def current_mount_info(target: str) -> MountInfo | None:
    if not is_mountpoint(target):
        return None
    result = subprocess.run(
        [
            "findmnt",
            "-P",
            "-n",
            "-o",
            "TARGET,SOURCE,FSROOT,OPTIONS",
            "--mountpoint",
            target,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return None
    info = parse_findmnt_pairs(result.stdout)
    if not info:
        return None
    normalized_target = normalize_guest_dst(info.get("TARGET"))
    if normalized_target != target:
        return None
    return {
        "target": normalized_target,
        "source": info.get("SOURCE", ""),
        "fsroot": info.get("FSROOT", ""),
        "options": info.get("OPTIONS", ""),
    }

def mount_is_same_persistent_token(current: MountInfo, record: Record) -> bool:
    """Return whether mount provenance names this exact AIVM token.

    A bind made from a subdirectory of the persistent-root virtiofs mount can
    outlive replacement of that subdirectory on the host.  In that reboot
    race, object identity differs even though mountinfo still proves the live
    bind came from this attachment's exact persistent-root token.  SOURCE and
    FSROOT are kernel mount provenance; unlike a lexical path comparison they
    remain meaningful for the stale bind.
    """
    token = str(record.get("shared_root_token") or "").strip()
    if not token or "/" in token or token in {".", ".."}:
        return False
    source = str(current.get("source") or "").strip()
    fsroot = str(current.get("fsroot") or "").strip()
    expected_root = "/" + token

    if fsroot != expected_root:
        return False
    if source == PERSISTENT_ROOT_TAG:
        return True
    prefix = PERSISTENT_ROOT_TAG + "["
    if source.startswith(prefix) and source.endswith("]"):
        return source[len(prefix) : -1] == expected_root
    return False

def unmount_guest_dst(guest_dst: str, *, ignore_busy: bool = False) -> bool:
    probe = subprocess.run(["mountpoint", "-q", guest_dst])
    if probe.returncode != 0:
        return True
    result = subprocess.run(
        ["umount", guest_dst],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        return True
    message = ((result.stderr or "") + "\n" + (result.stdout or "")).lower()
    if "not mounted" in message:
        return True
    if ignore_busy and "busy" in message:
        print(
            f"WARNING: skipping busy stale persistent attachment mount {guest_dst}: {(result.stderr or result.stdout).strip()}",
            file=sys.stderr,
        )
        return False
    raise RuntimeError(
        f"could not unmount {guest_dst}: {(result.stderr or result.stdout).strip()}"
    )

def is_descendant(child: str, parent: str) -> bool:
    child_path = PurePosixPath(child)
    parent_path = PurePosixPath(parent)
    return child_path != parent_path and child_path.is_relative_to(parent_path)

def validate_records(records: Sequence[object]) -> list[AcceptedRecord]:
    # Normalize the desired record set before replay.
    #
    # Enabled parents are the only entries that may suppress nested
    # enabled children. Disabled entries are still tracked so we can
    # unmount them explicitly, but they never act as blockers for
    # descendant mounts.
    normalized = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            print(
                f"WARNING: skipping malformed persistent attachment record at index {index}",
                file=sys.stderr,
            )
            continue
        guest_dst = normalize_guest_dst(record.get("guest_dst"))
        if not guest_dst:
            print(
                f"WARNING: skipping persistent attachment record with missing guest_dst at index {index}",
                file=sys.stderr,
            )
            continue
        token = str(record.get("shared_root_token") or "").strip()
        if not token:
            print(
                f"WARNING: skipping persistent attachment record with missing shared_root_token at index {index}",
                file=sys.stderr,
            )
            continue
        enabled = bool(record.get("enabled", True))
        access = str(record.get("access") or "").strip() or "rw"
        normalized.append((guest_dst, index, enabled, access, record))

    normalized.sort(
        key=lambda item: (
            len(PurePosixPath(item[0]).parts),
            item[0],
            item[1],
        )
    )
    accepted = []
    blockers = []
    seen_targets = {}
    for guest_dst, index, enabled, access, record in normalized:
        if guest_dst in seen_targets:
            first_index = seen_targets[guest_dst]
            print(
                f"ERROR: duplicate persistent attachment guest_dst {guest_dst} at index {index} duplicates index {first_index}; skipping",
                file=sys.stderr,
            )
            continue
        seen_targets[guest_dst] = index
        if enabled:
            parent_hit = None
            for accepted_guest_dst, accepted_access in blockers:
                if is_descendant(guest_dst, accepted_guest_dst):
                    parent_hit = (accepted_guest_dst, accepted_access)
            if parent_hit is not None:
                parent_guest_dst, parent_access = parent_hit
                if access != parent_access:
                    print(
                        f"ERROR: ignoring nested persistent attachment child {guest_dst} under {parent_guest_dst} because access differs (child={access} parent={parent_access})",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"WARNING: ignoring nested persistent attachment child {guest_dst} under {parent_guest_dst}",
                        file=sys.stderr,
                    )
                continue
            blockers.append((guest_dst, access))
        accepted.append((guest_dst, enabled, record))
    return accepted

def prune_stale_mounts(desired_targets: set[str]) -> None:
    result = subprocess.run(
        ["findmnt", "-P", "-n", "-o", "TARGET,SOURCE"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return
    root_prefix = PERSISTENT_ROOT_MOUNT.rstrip("/") + "/"
    for line in (result.stdout or "").splitlines():
        info = parse_findmnt_pairs(line)
        target = normalize_guest_dst(info.get("TARGET"))
        source = str(info.get("SOURCE") or "").strip()
        if not target or target == PERSISTENT_ROOT_MOUNT:
            continue
        if not source:
            continue
        if not (source == PERSISTENT_ROOT_MOUNT or source.startswith(root_prefix)):
            continue
        if target in desired_targets:
            continue
        unmount_guest_dst(target, ignore_busy=True)

def ensure_record(
    record: Record, *, preserve_live_mounts: bool = False
) -> None:
    guest_dst = normalize_guest_dst(record.get("guest_dst"))
    if not guest_dst:
        raise RuntimeError("persistent attachment record missing guest_dst")
    source = mount_source_for(record)
    if not source:
        raise RuntimeError(
            f"persistent attachment record missing shared_root_token for guest_dst {guest_dst}"
        )
    current = current_mount_info(guest_dst)
    if not os.path.isdir(source):
        if current is not None and not preserve_live_mounts:
            # Full lifecycle replay converges desired state strictly.
            # Foreground session preparation instead leaves a live
            # workspace alone and reports the source problem.
            unmount_guest_dst(guest_dst, ignore_busy=False)
        suffix = (
            "; existing live mount left untouched"
            if current is not None and preserve_live_mounts
            else ""
        )
        raise SourceUnavailableError(
            f"persistent attachment source is unavailable in shared root: {source}{suffix}"
        )
    desired = desired_option(record)
    if current is not None:
        current_source = str(current.get("source") or "").strip()
        current_options = str(current.get("options") or "").strip()
        if preserve_live_mounts and desired not in current_options.split(","):
            raise LiveMountConflictError(
                f"live persistent attachment access differs for {guest_dst} "
                f"(current={current_options} desired={desired}); "
                "foreground session preparation leaves live mounts untouched"
            )
        # findmnt's SOURCE is presentation-oriented and a bind mount
        # may be rendered as a filesystem plus FSROOT instead of the
        # lexical source path. Object identity is authoritative.
        same_source = (
            current_source == source
            or same_directory_object(source, guest_dst)
        )
        if same_source:
            if desired in current_options.split(","):
                remember_provenance(record)
                return
        else:
            stale_same_token = preserve_live_mounts and (
                mount_is_same_persistent_token(current, record) or has_pinned_provenance(record)
            )
            if preserve_live_mounts and not stale_same_token:
                raise LiveMountConflictError(
                    f"cannot verify that live persistent attachment at {guest_dst} belongs to the requested token "
                    f"(findmnt source={current_source or '<unknown>'} desired={source}); "
                    "foreground session preparation leaves live mounts untouched"
                )
            if preserve_live_mounts:
                # This is AIVM's own bind for the exact requested token, but it
                # points at the pre-replay directory object. A plain umount is
                # safe to attempt; a busy mount is preserved rather than forced.
                unmounted = unmount_guest_dst(guest_dst, ignore_busy=True)
                if not unmounted:
                    raise LiveMountConflictError(
                        f"stale AIVM persistent attachment at {guest_dst} belongs "
                        "to the requested token but is busy; foreground session "
                        "preparation leaves the live mount untouched"
                    )
            else:
                unmount_guest_dst(guest_dst, ignore_busy=False)
            current = current_mount_info(guest_dst)
            if current is not None:
                current_source = str(current.get("source") or "").strip()
                if current_source and current_source != source:
                    raise RuntimeError(
                        f"persistent attachment replacement did not unmount for {guest_dst} "
                        f"(current={current_source} desired={source})"
                    )
                current_options = str(current.get("options") or "").strip()
                if desired in current_options.split(","):
                    return
    created_mount = current is None
    if current is None:
        os.makedirs(guest_dst, exist_ok=True)
        if subprocess.run(["mountpoint", "-q", guest_dst]).returncode != 0:
            run(["mount", "--bind", source, guest_dst])
        current = current_mount_info(guest_dst)
    if current is None:
        raise RuntimeError(f"could not verify persistent attachment mount {guest_dst}")
    current_options = str(current.get("options") or "").strip()
    if desired not in current_options.split(","):
        if preserve_live_mounts and not created_mount:
            raise LiveMountConflictError(
                f"live persistent attachment access differs for {guest_dst} "
                f"(current={current_options} desired={desired}); "
                "foreground session preparation leaves live mounts untouched"
            )
        run(["mount", "-o", f"remount,bind,{desired}", guest_dst])
    remember_provenance(record)

def select_record(
    records: Sequence[object], only_guest_dst: str
) -> list[AcceptedRecord]:
    target = normalize_guest_dst(only_guest_dst)
    if not target:
        raise RuntimeError(
            f"invalid scoped persistent attachment guest destination: {only_guest_dst!r}"
        )
    matches = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        guest_dst = normalize_guest_dst(record.get("guest_dst"))
        if guest_dst != target:
            continue
        token = str(record.get("shared_root_token") or "").strip()
        if not token:
            raise RuntimeError(
                f"persistent attachment record for {target} is missing shared_root_token"
            )
        matches.append((guest_dst, bool(record.get("enabled", True)), record))
    if not matches:
        raise RuntimeError(
            f"persistent attachment record not found for scoped guest destination {target}"
        )
    if len(matches) != 1:
        raise RuntimeError(
            f"multiple persistent attachment records target scoped guest destination {target}"
        )
    return matches


def inspect_record(record: Record) -> tuple[int, str]:
    """Read live state without creating directories, locks, pins, or mounts.

    A repair result authorizes only asking the operator. The modifying helper
    always rechecks everything under its lock before any mutation.
    """
    target = normalize_guest_dst(record.get("guest_dst"))
    current = current_mount_info(target)
    if not bool(record.get("enabled", True)):
        if current is not None:
            return DEGRADED_EXIT, f"persistent attachment {target} is disabled but still mounted; existing live mount left untouched"
        return 0, ""
    if not is_mountpoint(PERSISTENT_ROOT_MOUNT):
        return REPAIR_EXIT, "persistent root needs mounting"
    source = mount_source_for(record)
    if not os.path.isdir(source):
        return DEGRADED_EXIT, f"persistent attachment source is unavailable in shared root: {source}; existing live mount left untouched"
    if current is None:
        return REPAIR_EXIT, f"persistent attachment needs mounting at {target}"
    desired = desired_option(record)
    if desired not in current.get("options", "").split(","):
        return DEGRADED_EXIT, f"live persistent attachment access differs for {target}; existing live mount left untouched"
    if same_directory_object(source, target):
        if has_pinned_provenance(record):
            return 0, ""
        return REPAIR_EXIT, f"verified attachment needs a private provenance reference at {target}"
    if mount_is_same_persistent_token(current, record) or has_pinned_provenance(record):
        return REPAIR_EXIT, f"stale persistent attachment at {target} belongs to the requested token; normal recovery can be attempted"
    return DEGRADED_EXIT, f"cannot verify that live persistent attachment at {target} belongs to the requested token; existing live mount left untouched"

def sync_state(
    *, only_guest_dst: str = "", preserve_live_mounts: bool = False
) -> list[str]:
    desired = load_json(STATE_PATH)
    raw_records = desired.get("records", [])
    if only_guest_dst:
        # Foreground operations are attachment-local. Session entry
        # additionally requests preserve_live_mounts so it can verify
        # or add the requested path without replacing live work.
        records = select_record(raw_records, only_guest_dst)
    else:
        records = validate_records(raw_records)
        desired_targets = {
            guest_dst for guest_dst, _enabled, _record in records
        }
        prune_stale_mounts(desired_targets)
        prune_provenance(records)
    failures = []
    for guest_dst, enabled, record in records:
        if not enabled:
            if preserve_live_mounts and is_mountpoint(guest_dst):
                failures.append(
                    f"persistent attachment {guest_dst} is disabled but still mounted; "
                    "foreground session preparation leaves live mounts untouched"
                )
            else:
                unmount_guest_dst(guest_dst, ignore_busy=False)
                path = provenance_path(record)
                if is_mountpoint(path):
                    unmount_guest_dst(path)
                    Path(path).rmdir()
            continue
        try:
            ensure_record(
                record, preserve_live_mounts=preserve_live_mounts
            )
        except (SourceUnavailableError, LiveMountConflictError) as ex:
            # Foreground session preparation is explicitly
            # non-destructive. A live mismatch is useful diagnostic
            # information, but it must not prevent SSH/VS Code from
            # entering an already-running VM whose workspace we just
            # promised to leave untouched. Return degraded state so
            # the host can warn and continue. Strict lifecycle replay
            # never sets preserve_live_mounts and remains convergent.
            failures.append(str(ex))
    return failures

def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only-guest-dst", default="")
    parser.add_argument("--preserve-live-mounts", action="store_true")
    parser.add_argument("--check", action="store_true", help="Inspect one foreground attachment without changing guest state")
    # Keep programmatic calls isolated from the parent process argv.
    # The executable wrapper below explicitly forwards its own CLI args.
    args = parser.parse_args(list(argv))
    if args.preserve_live_mounts and not args.only_guest_dst:
        parser.error("--preserve-live-mounts requires --only-guest-dst")
    if args.check:
        if not args.only_guest_dst:
            parser.error("--check requires --only-guest-dst")
        records = select_record(load_json(STATE_PATH).get("records", []), args.only_guest_dst)
        code, message = inspect_record(records[0][2])
        if message:
            print(message, file=sys.stderr)
        return code
    try:
        with ReplayLock():
            mount_persistent_root()
            failures = sync_state(
                only_guest_dst=args.only_guest_dst,
                preserve_live_mounts=args.preserve_live_mounts,
            )
    except FileNotFoundError as ex:
        print(str(ex), file=sys.stderr)
        raise SystemExit(1)
    if failures:
        for item in failures:
            print(
                f"WARNING: persistent attachment replay skipped one record: {item}",
                file=sys.stderr,
            )
        return DEGRADED_EXIT
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
