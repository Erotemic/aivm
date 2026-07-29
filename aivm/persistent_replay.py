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


def persistent_replay_python() -> str:
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
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

        def ensure_record(record):
            guest_dst = normalize_guest_dst(record.get("guest_dst"))
            if not guest_dst:
                raise RuntimeError("persistent attachment record missing guest_dst")
            source = mount_source_for(record)
            if not source:
                print(
                    f"WARNING: skipping persistent attachment record with missing shared_root_token for guest_dst {{guest_dst}}",
                    file=sys.stderr,
                )
                return
            if not os.path.isdir(source):
                print(
                    f"WARNING: skipping persistent attachment record with missing source in shared root: {{source}}",
                    file=sys.stderr,
                )
                return
            current = current_mount_info(guest_dst)
            desired = desired_option(record)
            if current is not None:
                current_source = str(current.get("source") or "").strip()
                current_options = str(current.get("options") or "").strip()
                if current_source and current_source != source:
                    unmount_guest_dst(guest_dst, ignore_busy=True)
                    current = current_mount_info(guest_dst)
                    if current is not None:
                        current_source = str(current.get("source") or "").strip()
                        if current_source and current_source != source:
                            print(
                                f"WARNING: skipping persistent attachment replacement for busy mount {{guest_dst}} (current={{current_source}} desired={{source}})",
                                file=sys.stderr,
                            )
                            return
                        current_options = str(current.get("options") or "").strip()
                        if desired in current_options.split(","):
                            return
                elif desired in current_options.split(","):
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
                run(["mount", "-o", f"remount,bind,{{desired}}", guest_dst])

        def sync_state():
            desired = load_json(STATE_PATH)
            records = validate_records(desired.get("records", []))
            desired_targets = {{
                guest_dst for guest_dst, _enabled, _record in records
            }}
            prune_stale_mounts(desired_targets)
            failures = []
            for guest_dst, enabled, record in records:
                if not enabled:
                    try:
                        unmount_guest_dst(guest_dst, ignore_busy=True)
                    except Exception as ex:  # pragma: no cover - guest runtime path
                        failures.append(str(ex))
                    continue
                try:
                    ensure_record(record)
                except Exception as ex:  # pragma: no cover - guest runtime path
                    failures.append(str(ex))
            return failures

        def main():
            mount_persistent_root()
            try:
                failures = sync_state()
            except FileNotFoundError as ex:
                print(str(ex), file=sys.stderr)
                raise SystemExit(1)
            if failures:
                for item in failures:
                    print(item, file=sys.stderr)
                raise SystemExit(1)

        if __name__ == "__main__":
            main()
        """
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
    return textwrap.dedent(
        """\
        #!/usr/bin/env python3
        import argparse
        import json
        import os
        import re
        import stat
        import subprocess
        from pathlib import Path

        TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
        DIRECTORY_FLAGS = (
            getattr(os, "O_PATH", os.O_RDONLY)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )

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
            source_fd = open_absolute_directory(
                record.get("source_dir"), label=f"source_dir for {token}"
            )
            info = os.fstat(source_fd)
            expected_dev = int(record.get("source_dev", -1))
            expected_ino = int(record.get("source_ino", -1))
            if expected_dev < 0 or expected_ino <= 0:
                os.close(source_fd)
                raise RuntimeError(f"manifest lacks approved source identity for {token}")
            if (int(info.st_dev), int(info.st_ino)) != (expected_dev, expected_ino):
                os.close(source_fd)
                raise RuntimeError(
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

        def enforce_access_fd(target_fd, raw_access):
            desired = "ro" if str(raw_access or "").strip() == "ro" else "rw"
            result = run(
                ["findmnt", "-n", "-o", "OPTIONS", "--mountpoint", fd_path(target_fd)],
                check=False,
                capture=True,
                pass_fds=(target_fd,),
            )
            options = {item.strip() for item in (result.stdout or "").split(",")}
            if desired in options:
                return
            run(
                ["mount", "-o", f"remount,bind,{desired}", fd_path(target_fd)],
                pass_fds=(target_fd,),
            )

        def ensure_record(export_root_fd, record):
            if not bool(record.get("enabled", True)):
                return
            token = validate_token(record.get("shared_root_token"))
            source_fd = open_approved_source(record)
            target_fd = open_child_directory(export_root_fd, token, create=True)
            try:
                if is_mountpoint_fd(target_fd) and same_tree_fds(source_fd, target_fd):
                    enforce_access_fd(target_fd, record.get("access"))
                    return
                if is_mountpoint_fd(target_fd):
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

        def main(argv=None):
            parser = argparse.ArgumentParser()
            parser.add_argument("--manifest", required=True)
            parser.add_argument("--export-root", required=True)
            parser.add_argument("--vm-name", required=True)
            parser.add_argument("--prune-stale", action="store_true")
            args = parser.parse_args(argv)

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
                for record in records:
                    if not isinstance(record, dict):
                        raise RuntimeError("host replay manifest contains a non-object record")
                    if bool(record.get("enabled", True)):
                        desired_tokens.add(validate_token(record.get("shared_root_token")))
                    ensure_record(export_root_fd, record)
                if args.prune_stale:
                    prune_stale_mounts(export_root_fd, desired_tokens)
            finally:
                os.close(export_root_fd)

        if __name__ == "__main__":
            main()
        """
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
