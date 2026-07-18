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
        import sys
        from pathlib import Path

        TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")

        def run(cmd, check=True, capture=False):
            return subprocess.run(
                cmd,
                check=check,
                text=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
            )

        def validate_manifest_file(path):
            manifest = Path(path)
            st = os.stat(manifest, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(f"host replay manifest is not a regular file: {manifest}")
            if st.st_uid != 0:
                raise RuntimeError(f"host replay manifest is not root-owned: {manifest}")
            if st.st_mode & 0o022:
                raise RuntimeError(f"host replay manifest is group/other writable: {manifest}")
            return manifest

        def validate_token(raw):
            token = str(raw or "").strip()
            if not TOKEN_RE.fullmatch(token) or token in {".", ".."}:
                raise RuntimeError(f"invalid persistent host bind token: {token!r}")
            return token

        def canonical_directory(raw, *, label):
            path = Path(str(raw or "").strip())
            if not path.is_absolute():
                raise RuntimeError(f"{label} must be absolute: {path}")
            try:
                resolved = path.resolve(strict=True)
            except OSError as ex:
                raise RuntimeError(f"{label} does not exist: {path}") from ex
            if not resolved.is_dir():
                raise RuntimeError(f"{label} is not a directory: {resolved}")
            return resolved

        def canonical_export_root(raw):
            path = Path(str(raw or "").strip())
            if not path.is_absolute():
                raise RuntimeError(f"export root must be absolute: {path}")
            if path.is_symlink():
                raise RuntimeError(f"export root must not be a symlink: {path}")
            path.mkdir(mode=0o755, parents=True, exist_ok=True)
            resolved = path.resolve(strict=True)
            if not resolved.is_dir():
                raise RuntimeError(f"export root is not a directory: {resolved}")
            return resolved

        def target_for(export_root, token):
            root = canonical_export_root(export_root)
            target = root / validate_token(token)
            if target.parent != root:
                raise RuntimeError(f"persistent bind target escapes export root: {target}")
            if target.is_symlink():
                raise RuntimeError(f"persistent bind target must not be a symlink: {target}")
            target.mkdir(mode=0o755, exist_ok=True)
            resolved = target.resolve(strict=True)
            if resolved.parent != root or resolved == root:
                raise RuntimeError(f"persistent bind target escapes export root: {resolved}")
            return root, resolved

        def is_mountpoint(target):
            return subprocess.run(["mountpoint", "-q", str(target)]).returncode == 0

        def same_tree(source, target):
            try:
                src_stat = os.stat(source)
                dst_stat = os.stat(target)
            except OSError:
                return False
            return (
                src_stat.st_dev == dst_stat.st_dev
                and src_stat.st_ino == dst_stat.st_ino
            )

        def enforce_access(target, raw_access):
            desired = "ro" if str(raw_access or "").strip() == "ro" else "rw"
            result = run(
                ["findmnt", "-n", "-o", "OPTIONS", "--mountpoint", str(target)],
                check=False,
                capture=True,
            )
            options = {item.strip() for item in (result.stdout or "").split(",")}
            if desired in options:
                return
            run(["mount", "-o", f"remount,bind,{desired}", str(target)])

        def ensure_record(export_root, record):
            enabled = bool(record.get("enabled", True))
            if not enabled:
                return
            token = validate_token(record.get("shared_root_token"))
            source = canonical_directory(record.get("source_dir"), label=f"source_dir for {token}")
            _, target = target_for(export_root, token)
            if is_mountpoint(target) and same_tree(source, target):
                enforce_access(target, record.get("access"))
                return
            if is_mountpoint(target):
                run(["umount", str(target)])
                if is_mountpoint(target):
                    raise RuntimeError(f"could not replace existing persistent host bind {target}")
            run(["mount", "--bind", str(source), str(target)])
            if not (is_mountpoint(target) and same_tree(source, target)):
                raise RuntimeError(f"could not verify persistent host bind {target} -> {source}")
            enforce_access(target, record.get("access"))

        def prune_stale_mounts(export_root, desired_tokens):
            root = canonical_export_root(export_root)
            for child in root.iterdir():
                if child.name in desired_tokens:
                    continue
                if child.is_symlink() or child.parent != root:
                    continue
                if is_mountpoint(child):
                    run(["umount", str(child)])

        def main(argv=None):
            parser = argparse.ArgumentParser()
            parser.add_argument("--manifest", required=True)
            parser.add_argument("--export-root", required=True)
            parser.add_argument("--vm-name", required=True)
            parser.add_argument("--prune-stale", action="store_true")
            args = parser.parse_args(argv)

            manifest = validate_manifest_file(args.manifest)
            with manifest.open("r", encoding="utf-8") as file:
                payload = json.load(file)
            if payload.get("vm_name") != args.vm_name:
                raise RuntimeError(
                    f"host replay manifest VM mismatch: expected {args.vm_name!r}, "
                    f"found {payload.get('vm_name')!r}"
                )

            desired_tokens = set()
            records = payload.get("records", [])
            if not isinstance(records, list):
                raise RuntimeError("host replay manifest records must be a list")
            for record in records:
                if not isinstance(record, dict):
                    raise RuntimeError("host replay manifest contains a non-object record")
                if bool(record.get("enabled", True)):
                    desired_tokens.add(validate_token(record.get("shared_root_token")))
                ensure_record(args.export_root, record)

            if args.prune_stale:
                prune_stale_mounts(args.export_root, desired_tokens)

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
