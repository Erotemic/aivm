#!/usr/bin/env python3
import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

Record = dict[str, Any]

TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
DEGRADED_EXIT = 3
DIRECTORY_FLAGS = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

class SourceUnavailableError(RuntimeError):
    pass

class LiveBindConflictError(RuntimeError):
    pass

def run(
    cmd: Sequence[str],
    *,
    check: bool = True,
    capture: bool = False,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        pass_fds=tuple(pass_fds),
    )

def fd_path(fd: int) -> str:
    return f"/proc/self/fd/{fd}"

def open_validated_manifest(path: str | Path) -> int:
    manifest = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(manifest, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"host replay manifest is not a regular file: {manifest}")
        if st.st_uid != 0:
            raise RuntimeError(f"host replay manifest is not root-owned: {manifest}")
        if st.st_mode & 0o022:
            raise RuntimeError(f"host replay manifest is group/other writable: {manifest}")
        return fd
    except BaseException:
        os.close(fd)
        raise

def validate_token(raw: object) -> str:
    token = str(raw or "").strip()
    if not TOKEN_RE.fullmatch(token) or token in {".", ".."}:
        raise RuntimeError(f"invalid persistent host bind token: {token!r}")
    return token

def path_parts(raw: object, *, label: str) -> tuple[Path, list[str]]:
    path = Path(str(raw or "").strip())
    if not path.is_absolute():
        raise RuntimeError(f"{label} must be absolute: {path}")
    parts = [part for part in path.parts if part not in {"", "/"}]
    if any(part in {".", ".."} for part in parts):
        raise RuntimeError(f"{label} contains unsafe components: {path}")
    return path, parts

def open_absolute_directory(
    raw: object, *, label: str, create: bool = False, mode: int = 0o755
) -> int:
    path, parts = path_parts(raw, label=label)
    current_fd = os.open("/", DIRECTORY_FLAGS)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=mode, dir_fd=current_fd)
                except FileExistsError:
                    pass
            next_fd = os.open(part, DIRECTORY_FLAGS, dir_fd=current_fd)
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode):
                os.close(next_fd)
                raise RuntimeError(f"{label} component is not a directory: {path}")
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise

def open_child_directory(
    parent_fd: int, name: object, *, create: bool = False, mode: int = 0o755
) -> int:
    token = validate_token(name)
    if create:
        try:
            os.mkdir(token, mode=mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
    fd = os.open(token, DIRECTORY_FLAGS, dir_fd=parent_fd)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise RuntimeError(f"persistent bind target is not a directory: {token}")
    return fd

def open_approved_source(record: Record) -> int:
    token = validate_token(record.get("shared_root_token"))
    source_path, _parts = path_parts(
        record.get("source_dir"), label=f"source_dir for {token}"
    )
    try:
        source_fd = open_absolute_directory(
            source_path, label=f"source_dir for {token}"
        )
    except (OSError, RuntimeError) as ex:
        raise SourceUnavailableError(
            f"persistent source unavailable for {token}: {source_path}: {ex}"
        ) from ex
    info = os.fstat(source_fd)
    expected_dev = int(record.get("source_dev", -1))
    expected_ino = int(record.get("source_ino", -1))
    if expected_dev < 0 or expected_ino <= 0:
        os.close(source_fd)
        raise RuntimeError(f"manifest lacks approved source identity for {token}")
    if (int(info.st_dev), int(info.st_ino)) != (expected_dev, expected_ino):
        os.close(source_fd)
        raise SourceUnavailableError(
            f"approved persistent source changed for {token}: "
            f"expected dev={expected_dev} ino={expected_ino}, "
            f"found dev={info.st_dev} ino={info.st_ino}"
        )
    return source_fd

def is_mountpoint_fd(fd: int) -> bool:
    return run(
        ["mountpoint", "-q", fd_path(fd)],
        check=False,
        pass_fds=(fd,),
    ).returncode == 0

def same_tree_fds(left_fd: int, right_fd: int) -> bool:
    left = os.fstat(left_fd)
    right = os.fstat(right_fd)
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino

def child_fd_path(parent_fd: int, name: object) -> str:
    token = validate_token(name)
    return f"{fd_path(parent_fd)}/{token}"

def is_mountpoint_child(parent_fd: int, name: object) -> bool:
    return run(
        ["mountpoint", "-q", child_fd_path(parent_fd, name)],
        check=False,
        pass_fds=(parent_fd,),
    ).returncode == 0

def unmount_child(parent_fd: int, name: object) -> None:
    # Holding an O_PATH descriptor for the mountpoint itself can make
    # a normal umount report EBUSY. Resolve the child through the held,
    # trusted parent descriptor instead. The export root and its token
    # directories are root-owned, so an unprivileged user cannot swap
    # the child during this short close/unmount/reopen sequence.
    target = child_fd_path(parent_fd, name)
    result = run(
        ["umount", target],
        check=False,
        capture=True,
        pass_fds=(parent_fd,),
    )
    if result.returncode == 0 or not is_mountpoint_child(parent_fd, name):
        return
    detail = (result.stderr or result.stdout or "").strip()
    if "busy" in detail.lower():
        lazy = run(
            ["umount", "--lazy", target],
            check=False,
            capture=True,
            pass_fds=(parent_fd,),
        )
        if lazy.returncode == 0 or not is_mountpoint_child(parent_fd, name):
            return
        lazy_detail = (lazy.stderr or lazy.stdout or "").strip()
        if lazy_detail:
            detail = f"{detail}; lazy detach also failed: {lazy_detail}"
    raise RuntimeError(f"could not unmount persistent host bind: {detail}")

def access_matches_fd(target_fd: int, raw_access: object) -> bool:
    desired = "ro" if str(raw_access or "").strip() == "ro" else "rw"
    result = run(
        ["findmnt", "-n", "-o", "OPTIONS", "--mountpoint", fd_path(target_fd)],
        check=False,
        capture=True,
        pass_fds=(target_fd,),
    )
    options = {item.strip() for item in (result.stdout or "").split(",")}
    return desired in options

def enforce_access_fd(target_fd: int, raw_access: object) -> None:
    desired = "ro" if str(raw_access or "").strip() == "ro" else "rw"
    if access_matches_fd(target_fd, raw_access):
        return
    run(
        ["mount", "-o", f"remount,bind,{desired}", fd_path(target_fd)],
        pass_fds=(target_fd,),
    )

def ensure_record(
    export_root_fd: int, record: Record, *, preserve_live_binds: bool = False
) -> None:
    if not bool(record.get("enabled", True)):
        return
    token = validate_token(record.get("shared_root_token"))
    source_fd = open_approved_source(record)
    target_fd = open_child_directory(export_root_fd, token, create=True)
    try:
        if is_mountpoint_fd(target_fd) and same_tree_fds(source_fd, target_fd):
            if preserve_live_binds and not access_matches_fd(
                target_fd, record.get("access")
            ):
                raise LiveBindConflictError(
                    f"live persistent host bind for {{token}} has different access; "
                    "foreground session preparation leaves live binds untouched"
                )
            enforce_access_fd(target_fd, record.get("access"))
            return
        if is_mountpoint_fd(target_fd):
            if preserve_live_binds:
                raise LiveBindConflictError(
                    f"live persistent host bind for {{token}} points at a different directory; "
                    "foreground session preparation leaves live binds untouched"
                )
            os.close(target_fd)
            target_fd = -1
            unmount_child(export_root_fd, token)
            target_fd = open_child_directory(export_root_fd, token)
        run(
            ["mount", "--bind", fd_path(source_fd), fd_path(target_fd)],
            pass_fds=(source_fd, target_fd),
        )
        os.close(target_fd)
        target_fd = open_child_directory(export_root_fd, token)
        if not is_mountpoint_fd(target_fd) or not same_tree_fds(source_fd, target_fd):
            raise RuntimeError(f"could not verify persistent host bind for {token}")
        enforce_access_fd(target_fd, record.get("access"))
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        os.close(source_fd)

def prune_stale_mounts(export_root_fd: int, desired_tokens: set[str]) -> None:
    # O_PATH descriptors pin the approved directory but cannot be
    # enumerated directly. Re-open that exact object through procfs
    # rather than falling back to its mutable pathname.
    for child in os.listdir(fd_path(export_root_fd)):
        if child in desired_tokens or not TOKEN_RE.fullmatch(child):
            continue
        try:
            child_fd = open_child_directory(export_root_fd, child)
        except OSError:
            continue
        try:
            if is_mountpoint_fd(child_fd):
                os.close(child_fd)
                child_fd = -1
                unmount_child(export_root_fd, child)
        finally:
            if child_fd >= 0:
                os.close(child_fd)

def quarantine_unavailable_token(export_root_fd: int, token: object) -> None:
    # A rejected token must not survive as an empty directory that the
    # guest could mistake for a successfully exported source.
    token = validate_token(token)
    try:
        child_fd = open_child_directory(export_root_fd, token)
    except FileNotFoundError:
        return
    try:
        if is_mountpoint_fd(child_fd):
            os.close(child_fd)
            child_fd = -1
            unmount_child(export_root_fd, token)
    finally:
        if child_fd >= 0:
            os.close(child_fd)
    try:
        os.rmdir(token, dir_fd=export_root_fd)
    except FileNotFoundError:
        return
    except OSError as ex:
        raise RuntimeError(
            f"could not quarantine unavailable persistent host bind {token}: {ex}"
        ) from ex

def probe_source_identity(raw: object) -> int:
    source_fd = open_absolute_directory(raw, label="probe source")
    try:
        info = os.fstat(source_fd)
        print(
            json.dumps(
                {"dev": int(info.st_dev), "ino": int(info.st_ino)},
                sort_keys=True,
            )
        )
    finally:
        os.close(source_fd)
    return 0

def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest")
    parser.add_argument("--export-root")
    parser.add_argument("--vm-name")
    parser.add_argument("--prune-stale", action="store_true")
    parser.add_argument("--only-guest-dst", default="")
    parser.add_argument("--preserve-live-binds", action="store_true")
    parser.add_argument("--probe-source")
    # Keep programmatic calls isolated from the parent process argv.
    # The executable wrapper below explicitly forwards its own CLI args.
    args = parser.parse_args(list(argv))

    if args.probe_source:
        if (
            args.manifest
            or args.export_root
            or args.vm_name
            or args.prune_stale
            or args.only_guest_dst
            or args.preserve_live_binds
        ):
            parser.error("--probe-source cannot be combined with replay arguments")
        return probe_source_identity(args.probe_source)
    if not args.manifest or not args.export_root or not args.vm_name:
        parser.error("--manifest, --export-root, and --vm-name are required for replay")
    if args.only_guest_dst and args.prune_stale:
        parser.error("--only-guest-dst cannot be combined with --prune-stale")
    if args.preserve_live_binds and not args.only_guest_dst:
        parser.error("--preserve-live-binds requires --only-guest-dst")

    manifest_fd = open_validated_manifest(args.manifest)
    with os.fdopen(manifest_fd, "r", encoding="utf-8") as file:
        payload = json.load(file)
    if payload.get("vm_name") != args.vm_name:
        raise RuntimeError(
            f"host replay manifest VM mismatch: expected {args.vm_name!r}, "
            f"found {payload.get('vm_name')!r}"
        )
    records = payload.get("records", [])
    if not isinstance(records, list):
        raise RuntimeError("host replay manifest records must be a list")

    export_root_fd = open_absolute_directory(
        args.export_root, label="export root", create=True
    )
    try:
        desired_tokens = set()
        unavailable = []
        scoped_matches = 0
        for record in records:
            if not isinstance(record, dict):
                raise RuntimeError("host replay manifest contains a non-object record")
            token = validate_token(record.get("shared_root_token"))
            if args.only_guest_dst:
                guest_dst = str(record.get("guest_dst") or "").strip()
                if guest_dst != args.only_guest_dst:
                    continue
                scoped_matches += 1
                if scoped_matches > 1:
                    raise RuntimeError(
                        f"multiple persistent attachment records target scoped guest destination {{args.only_guest_dst}}"
                    )
            if not bool(record.get("enabled", True)):
                if args.only_guest_dst and not args.preserve_live_binds:
                    quarantine_unavailable_token(export_root_fd, token)
                continue
            try:
                ensure_record(
                    export_root_fd,
                    record,
                    preserve_live_binds=args.preserve_live_binds,
                )
            except (SourceUnavailableError, LiveBindConflictError) as ex:
                if (
                    isinstance(ex, SourceUnavailableError)
                    and not args.preserve_live_binds
                ):
                    quarantine_unavailable_token(export_root_fd, token)
                unavailable.append(
                    (
                        token,
                        str(record.get("source_dir") or ""),
                        str(ex),
                    )
                )
                print(
                    f"WARNING: skipping persistent host attachment {token}: {ex}",
                    file=sys.stderr,
                )
                continue
            desired_tokens.add(token)
        if args.only_guest_dst and scoped_matches == 0:
            raise RuntimeError(
                f"persistent attachment record not found for scoped guest destination {{args.only_guest_dst}}"
            )
        if args.prune_stale:
            prune_stale_mounts(export_root_fd, desired_tokens)
    finally:
        os.close(export_root_fd)
    if unavailable:
        for token, source_dir, detail in unavailable:
            print(
                "AIVM_PERSISTENT_SOURCE_UNAVAILABLE "
                + json.dumps(
                    {
                        "token": token,
                        "source_dir": source_dir,
                        "detail": detail,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
        return DEGRADED_EXIT
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
