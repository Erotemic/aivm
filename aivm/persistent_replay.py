"""Shared persistent-attachment replay constants and templates.

This module is intentionally dependency-light so VM bootstrap code can import
it without pulling in the higher-level attachments package.
"""

from __future__ import annotations

import textwrap

PERSISTENT_ATTACHMENT_HOST_MANIFEST_NAME = 'persistent-attachments.json'
PERSISTENT_ATTACHMENT_HOST_APPROVED_STATE_DIR = '/var/lib/aivm/persistent-host'
PERSISTENT_ATTACHMENT_GUEST_STATE_DIR = '/var/lib/aivm'
PERSISTENT_ATTACHMENT_GUEST_STATE_PATH = (
    f'{PERSISTENT_ATTACHMENT_GUEST_STATE_DIR}/attachments.json'
)
PERSISTENT_ATTACHMENT_REPLAY_BIN = (
    '/usr/local/libexec/aivm-persistent-attachment-replay'
)
PERSISTENT_ATTACHMENT_REPLAY_SERVICE = (
    'aivm-persistent-attachment-replay.service'
)
PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN = (
    '/usr/local/libexec/aivm-persistent-host-bind-replay'
)
PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX = (
    'aivm-persistent-host-bind-replay'
)
PERSISTENT_ROOT_VIRTIOFS_TAG = 'aivm-persistent-root'
PERSISTENT_ROOT_GUEST_MOUNT_ROOT = '/mnt/aivm-persistent'

# Replay helpers use this distinct exit status when they safely isolate one or
# more unavailable/untrusted source records while still converging every other
# record. Callers may continue the broader VM/session operation, but should
# surface the diagnostics and offer the explicit trust/re-pin recovery action.
PERSISTENT_REPLAY_DEGRADED_EXIT = 3

#: Export-root child names the privileged host replay helper will act on.
#: The helper embeds this same pattern (it is a standalone script, so it
#: cannot import it); ``test_persistent_templates`` holds the two together.
PERSISTENT_BIND_TOKEN_PATTERN = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'


def persistent_replay_python() -> str:
    source = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import argparse
        import json
        import os
        import posixpath
        import subprocess
        import sys
        from pathlib import PurePosixPath

        PERSISTENT_ROOT_TAG = "{PERSISTENT_ROOT_VIRTIOFS_TAG}"
        PERSISTENT_ROOT_MOUNT = "{PERSISTENT_ROOT_GUEST_MOUNT_ROOT}"
        # Guest replay is intentionally fed only from the VM-local manifest
        # that the host syncs in. The helper must never read host desired state
        # back through virtiofs.
        STATE_DIR = "{PERSISTENT_ATTACHMENT_GUEST_STATE_DIR}"
        STATE_PATH = "{PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}"
        DEGRADED_EXIT = __AIVM_DEGRADED_EXIT__

        class SourceUnavailableError(RuntimeError):
            pass

        class LiveMountConflictError(RuntimeError):
            pass

        def run(cmd, check=True, capture=False):
            return subprocess.run(
                cmd,
                check=check,
                text=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
            )

        def mount_persistent_root():
            os.makedirs(PERSISTENT_ROOT_MOUNT, exist_ok=True)
            probe = subprocess.run(["mountpoint", "-q", PERSISTENT_ROOT_MOUNT])
            if probe.returncode == 0:
                return
            run(["mount", "-t", "virtiofs", PERSISTENT_ROOT_TAG, PERSISTENT_ROOT_MOUNT])

        def load_json(path):
            try:
                with open(path, "r", encoding="utf-8") as file:
                    return json.load(file)
            except FileNotFoundError:
                raise FileNotFoundError(
                    f"persistent attachment manifest missing from guest state dir: {{path}}"
                )

        def normalize_guest_dst(raw):
            text = str(raw or "").strip()
            if not text:
                return ""
            text = posixpath.normpath(text)
            if not text.startswith("/"):
                return ""
            return text

        def desired_option(record):
            return "ro" if str(record.get("access") or "").strip() == "ro" else "rw"

        def mount_source_for(record):
            token = str(record.get("shared_root_token") or "").strip()
            if not token:
                return ""
            return str(PurePosixPath(PERSISTENT_ROOT_MOUNT) / token)

        def parse_findmnt_pairs(stdout):
            values = {{}}
            for token in (stdout or "").split():
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                values[key.strip().upper()] = value.strip().strip('"')
            return values

        def is_mountpoint(target):
            probe = subprocess.run(["mountpoint", "-q", target])
            return probe.returncode == 0

        def same_directory_object(left, right):
            try:
                left_info = os.stat(left)
                right_info = os.stat(right)
            except OSError:
                return False
            return (left_info.st_dev, left_info.st_ino) == (
                right_info.st_dev,
                right_info.st_ino,
            )

        def current_mount_info(target):
            if not is_mountpoint(target):
                return None
            result = subprocess.run(
                [
                    "findmnt",
                    "-P",
                    "-n",
                    "-o",
                    "TARGET,SOURCE,OPTIONS",
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
            return {{
                "target": normalized_target,
                "source": info.get("SOURCE", ""),
                "options": info.get("OPTIONS", ""),
            }}

        def unmount_guest_dst(guest_dst, *, ignore_busy=False):
            probe = subprocess.run(["mountpoint", "-q", guest_dst])
            if probe.returncode != 0:
                return
            result = subprocess.run(
                ["umount", guest_dst],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                return
            message = ((result.stderr or "") + "\\n" + (result.stdout or "")).lower()
            if "not mounted" in message:
                return
            if ignore_busy and "busy" in message:
                print(
                    f"WARNING: skipping busy stale persistent attachment mount {{guest_dst}}: {{(result.stderr or result.stdout).strip()}}",
                    file=sys.stderr,
                )
                return
            raise RuntimeError(
                f"could not unmount {{guest_dst}}: {{(result.stderr or result.stdout).strip()}}"
            )

        def is_descendant(child, parent):
            child_path = PurePosixPath(child)
            parent_path = PurePosixPath(parent)
            return child_path != parent_path and child_path.is_relative_to(parent_path)

        def validate_records(records):
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
                        f"WARNING: skipping malformed persistent attachment record at index {{index}}",
                        file=sys.stderr,
                    )
                    continue
                guest_dst = normalize_guest_dst(record.get("guest_dst"))
                if not guest_dst:
                    print(
                        f"WARNING: skipping persistent attachment record with missing guest_dst at index {{index}}",
                        file=sys.stderr,
                    )
                    continue
                token = str(record.get("shared_root_token") or "").strip()
                if not token:
                    print(
                        f"WARNING: skipping persistent attachment record with missing shared_root_token at index {{index}}",
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
            seen_targets = {{}}
            for guest_dst, index, enabled, access, record in normalized:
                if guest_dst in seen_targets:
                    first_index = seen_targets[guest_dst]
                    print(
                        f"ERROR: duplicate persistent attachment guest_dst {{guest_dst}} at index {{index}} duplicates index {{first_index}}; skipping",
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
                                f"ERROR: ignoring nested persistent attachment child {{guest_dst}} under {{parent_guest_dst}} because access differs (child={{access}} parent={{parent_access}})",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                f"WARNING: ignoring nested persistent attachment child {{guest_dst}} under {{parent_guest_dst}}",
                                file=sys.stderr,
                            )
                        continue
                    blockers.append((guest_dst, access))
                accepted.append((guest_dst, enabled, record))
            return accepted

        def prune_stale_mounts(desired_targets):
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

        def ensure_record(record, *, preserve_live_mounts=False):
            guest_dst = normalize_guest_dst(record.get("guest_dst"))
            if not guest_dst:
                raise RuntimeError("persistent attachment record missing guest_dst")
            source = mount_source_for(record)
            if not source:
                raise RuntimeError(
                    f"persistent attachment record missing shared_root_token for guest_dst {{guest_dst}}"
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
                    f"persistent attachment source is unavailable in shared root: {{source}}{{suffix}}"
                )
            desired = desired_option(record)
            if current is not None:
                current_source = str(current.get("source") or "").strip()
                current_options = str(current.get("options") or "").strip()
                # findmnt's SOURCE is presentation-oriented and a bind mount
                # may be rendered as a filesystem plus FSROOT instead of the
                # lexical source path. Object identity is authoritative.
                same_source = (
                    current_source == source
                    or same_directory_object(source, guest_dst)
                )
                if same_source:
                    if desired in current_options.split(","):
                        return
                    if preserve_live_mounts:
                        raise LiveMountConflictError(
                            f"live persistent attachment access differs for {{guest_dst}} "
                            f"(current={{current_options}} desired={{desired}}); "
                            "foreground session preparation leaves live mounts untouched"
                        )
                else:
                    if preserve_live_mounts:
                        raise LiveMountConflictError(
                            f"live persistent attachment at {{guest_dst}} is a different directory "
                            f"(findmnt source={{current_source or '<unknown>'}} desired={{source}}); "
                            "foreground session preparation leaves live mounts untouched"
                        )
                    unmount_guest_dst(guest_dst, ignore_busy=False)
                    current = current_mount_info(guest_dst)
                    if current is not None:
                        current_source = str(current.get("source") or "").strip()
                        if current_source and current_source != source:
                            raise RuntimeError(
                                f"persistent attachment replacement did not unmount for {{guest_dst}} "
                                f"(current={{current_source}} desired={{source}})"
                            )
                        current_options = str(current.get("options") or "").strip()
                        if desired in current_options.split(","):
                            return
            if current is None:
                os.makedirs(guest_dst, exist_ok=True)
                if subprocess.run(["mountpoint", "-q", guest_dst]).returncode != 0:
                    run(["mount", "--bind", source, guest_dst])
                current = current_mount_info(guest_dst)
            if current is None:
                raise RuntimeError(f"could not verify persistent attachment mount {{guest_dst}}")
            current_options = str(current.get("options") or "").strip()
            if desired not in current_options.split(","):
                if preserve_live_mounts:
                    raise LiveMountConflictError(
                        f"live persistent attachment access differs for {{guest_dst}} "
                        f"(current={{current_options}} desired={{desired}}); "
                        "foreground session preparation leaves live mounts untouched"
                    )
                run(["mount", "-o", f"remount,bind,{{desired}}", guest_dst])

        def select_record(records, only_guest_dst):
            target = normalize_guest_dst(only_guest_dst)
            if not target:
                raise RuntimeError(
                    f"invalid scoped persistent attachment guest destination: {{only_guest_dst!r}}"
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
                        f"persistent attachment record for {{target}} is missing shared_root_token"
                    )
                matches.append((guest_dst, bool(record.get("enabled", True)), record))
            if not matches:
                raise RuntimeError(
                    f"persistent attachment record not found for scoped guest destination {{target}}"
                )
            if len(matches) != 1:
                raise RuntimeError(
                    f"multiple persistent attachment records target scoped guest destination {{target}}"
                )
            return matches

        def sync_state(*, only_guest_dst="", preserve_live_mounts=False):
            desired = load_json(STATE_PATH)
            raw_records = desired.get("records", [])
            if only_guest_dst:
                # Foreground operations are attachment-local. Session entry
                # additionally requests preserve_live_mounts so it can verify
                # or add the requested path without replacing live work.
                records = select_record(raw_records, only_guest_dst)
            else:
                records = validate_records(raw_records)
                desired_targets = {{
                    guest_dst for guest_dst, _enabled, _record in records
                }}
                prune_stale_mounts(desired_targets)
            failures = []
            for guest_dst, enabled, record in records:
                if not enabled:
                    if preserve_live_mounts and is_mountpoint(guest_dst):
                        failures.append(
                            f"persistent attachment {{guest_dst}} is disabled but still mounted; "
                            "foreground session preparation leaves live mounts untouched"
                        )
                    else:
                        unmount_guest_dst(guest_dst, ignore_busy=False)
                    continue
                try:
                    ensure_record(
                        record, preserve_live_mounts=preserve_live_mounts
                    )
                except SourceUnavailableError as ex:
                    failures.append(str(ex))
            return failures

        def main(argv=()):
            parser = argparse.ArgumentParser()
            parser.add_argument("--only-guest-dst", default="")
            parser.add_argument("--preserve-live-mounts", action="store_true")
            # Keep programmatic calls isolated from the parent process argv.
            # The executable wrapper below explicitly forwards its own CLI args.
            args = parser.parse_args(list(argv))
            if args.preserve_live_mounts and not args.only_guest_dst:
                parser.error("--preserve-live-mounts requires --only-guest-dst")
            mount_persistent_root()
            try:
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
                        f"WARNING: persistent attachment replay skipped one record: {{item}}",
                        file=sys.stderr,
                    )
                return DEGRADED_EXIT
            return 0

        if __name__ == "__main__":
            raise SystemExit(main(sys.argv[1:]))
        """
    )
    return source.replace(
        '__AIVM_DEGRADED_EXIT__', str(PERSISTENT_REPLAY_DEGRADED_EXIT)
    )


def persistent_replay_service_unit() -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description=aivm persistent attachment replay
        After=local-fs.target
        ConditionPathExists={PERSISTENT_ATTACHMENT_GUEST_STATE_PATH}

        [Service]
        Type=oneshot
        ExecStart={PERSISTENT_ATTACHMENT_REPLAY_BIN}

        [Install]
        WantedBy=multi-user.target
        """
    )


def persistent_host_replay_python() -> str:
    source = textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import argparse
        import json
        import os
        import re
        import stat
        import subprocess
        import sys
        from pathlib import Path

        TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
        DEGRADED_EXIT = __AIVM_DEGRADED_EXIT__
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

        def run(cmd, *, check=True, capture=False, pass_fds=()):
            return subprocess.run(
                cmd,
                check=check,
                text=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                pass_fds=tuple(pass_fds),
            )

        def fd_path(fd):
            return f"/proc/self/fd/{fd}"

        def open_validated_manifest(path):
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

        def validate_token(raw):
            token = str(raw or "").strip()
            if not TOKEN_RE.fullmatch(token) or token in {".", ".."}:
                raise RuntimeError(f"invalid persistent host bind token: {token!r}")
            return token

        def path_parts(raw, *, label):
            path = Path(str(raw or "").strip())
            if not path.is_absolute():
                raise RuntimeError(f"{label} must be absolute: {path}")
            parts = [part for part in path.parts if part not in {"", "/"}]
            if any(part in {".", ".."} for part in parts):
                raise RuntimeError(f"{label} contains unsafe components: {path}")
            return path, parts

        def open_absolute_directory(raw, *, label, create=False, mode=0o755):
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

        def open_child_directory(parent_fd, name, *, create=False, mode=0o755):
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

        def open_approved_source(record):
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

        def is_mountpoint_fd(fd):
            return run(
                ["mountpoint", "-q", fd_path(fd)],
                check=False,
                pass_fds=(fd,),
            ).returncode == 0

        def same_tree_fds(left_fd, right_fd):
            left = os.fstat(left_fd)
            right = os.fstat(right_fd)
            return left.st_dev == right.st_dev and left.st_ino == right.st_ino

        def child_fd_path(parent_fd, name):
            token = validate_token(name)
            return f"{fd_path(parent_fd)}/{token}"

        def is_mountpoint_child(parent_fd, name):
            return run(
                ["mountpoint", "-q", child_fd_path(parent_fd, name)],
                check=False,
                pass_fds=(parent_fd,),
            ).returncode == 0

        def unmount_child(parent_fd, name):
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

        def access_matches_fd(target_fd, raw_access):
            desired = "ro" if str(raw_access or "").strip() == "ro" else "rw"
            result = run(
                ["findmnt", "-n", "-o", "OPTIONS", "--mountpoint", fd_path(target_fd)],
                check=False,
                capture=True,
                pass_fds=(target_fd,),
            )
            options = {item.strip() for item in (result.stdout or "").split(",")}
            return desired in options

        def enforce_access_fd(target_fd, raw_access):
            desired = "ro" if str(raw_access or "").strip() == "ro" else "rw"
            if access_matches_fd(target_fd, raw_access):
                return
            run(
                ["mount", "-o", f"remount,bind,{desired}", fd_path(target_fd)],
                pass_fds=(target_fd,),
            )

        def ensure_record(export_root_fd, record, *, preserve_live_binds=False):
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

        def prune_stale_mounts(export_root_fd, desired_tokens):
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

        def quarantine_unavailable_token(export_root_fd, token):
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

        def probe_source_identity(raw):
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

        def main(argv=()):
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
                    except SourceUnavailableError as ex:
                        if not args.preserve_live_binds:
                            quarantine_unavailable_token(export_root_fd, token)
                        unavailable.append((token, str(record.get("source_dir") or ""), str(ex)))
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
        """
    )
    return source.replace(
        '__AIVM_DEGRADED_EXIT__', str(PERSISTENT_REPLAY_DEGRADED_EXIT)
    )


def _systemd_exec_arg(value: str) -> str:
    if '\n' in value or '\r' in value:
        raise ValueError('systemd arguments must not contain newlines')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def persistent_host_replay_service_unit(
    *,
    vm_name: str,
    manifest_path: str,
    export_root: str,
) -> str:
    service_name = (
        f'{PERSISTENT_ATTACHMENT_HOST_REPLAY_SERVICE_PREFIX}-{vm_name}'
    )
    manifest_q = _systemd_exec_arg(manifest_path)
    export_q = _systemd_exec_arg(export_root)
    vm_q = _systemd_exec_arg(vm_name)
    return textwrap.dedent(
        f"""        [Unit]
        Description={service_name}
        After=local-fs.target
        ConditionPathExists={manifest_path}

        [Service]
        Type=oneshot
        User=root
        Group=root
        UMask=0022
        NoNewPrivileges=yes
        PrivateTmp=yes
        ExecStart={PERSISTENT_ATTACHMENT_HOST_REPLAY_BIN} --manifest {manifest_q} --export-root {export_q} --vm-name {vm_q} --prune-stale

        [Install]
        WantedBy=multi-user.target
        """
    )
