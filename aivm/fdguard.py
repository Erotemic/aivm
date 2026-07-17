"""Guest-side virtiofs fd guard: templates and install scripts.

Why this exists
---------------

Host-side ``virtiofsd`` represents every inode the *guest* keeps cached with
one open ``O_PATH`` file descriptor on the host (it lacks
``CAP_DAC_READ_SEARCH``, so it cannot use file handles instead). The guest
kernel only releases those inodes (FUSE ``FORGET``) under memory pressure or
an explicit ``drop_caches`` write, so on large-RAM guests the daemon's fd
count grows monotonically toward ``min(RLIMIT_NOFILE, fs.nr_open)`` --
typically about one million -- after which every lookup/open on the share
fails and the guest sees ``EMFILE`` (``[Errno 24] Too many open files``).

Two guest-side facts make this both deterministic and fixable from inside
the VM:

1. Ubuntu's stock ``/etc/updatedb.conf`` ``PRUNEFS`` does **not** include
   ``virtiofs``, and the cloud image ships ``plocate`` with a daily
   ``plocate-updatedb.timer``. Every attached share therefore gets fully
   re-walked nightly, touching every inode -- one sweep over a multi-million
   inode share saturates virtiofsd on its own.
2. The guest-visible ``fuse_inode`` slab count tracks the host daemon's
   path-backed fd count almost 1:1 for the observed topology, so the guest
   can observe the pressure it is creating and shed reclaimable dentries and
   inodes before the host ceiling is reached. Measured on 2026-05-17: a
   guest cache drop took the hot daemon from 999,778 fds to 45 within about
   30 seconds.

The guard installed here is a small root-owned script run from a systemd
timer inside the guest. Each tick it (a) idempotently ensures updatedb
prunes virtiofs, (b) observes guest-global FUSE inode pressure, and (c) uses
soft and emergency watermarks to decide when to shed metadata caches. See
``docs/source/virtiofs.rst`` for the full analysis and tradeoffs.

This module is intentionally dependency-light so VM bootstrap code can
import it without pulling in the higher-level attachments package.
"""

from __future__ import annotations

import base64
import hashlib
import textwrap

FDGUARD_BIN = '/usr/local/libexec/aivm-virtiofs-guard'
FDGUARD_CONF = '/etc/aivm/virtiofs-guard.conf'
FDGUARD_SERVICE = 'aivm-virtiofs-guard.service'
FDGUARD_TIMER = 'aivm-virtiofs-guard.timer'
FDGUARD_SERVICE_PATH = f'/etc/systemd/system/{FDGUARD_SERVICE}'
FDGUARD_TIMER_PATH = f'/etc/systemd/system/{FDGUARD_TIMER}'
FDGUARD_STATE = '/run/aivm-virtiofs-guard.json'

DEFAULT_FDGUARD_THRESHOLD = 500_000
DEFAULT_FDGUARD_EMERGENCY_THRESHOLD = 750_000
DEFAULT_FDGUARD_INTERVAL_SEC = 600


def fdguard_python() -> str:
    """Render the guest-side guard script.

    Paths are overridable via ``AIVM_VIRTIOFS_GUARD_*`` environment
    variables so the script's behavior is directly testable outside a
    guest; production systemd invocation uses the defaults.
    """
    header = textwrap.dedent(
        f'''\
        #!/usr/bin/python3
        """aivm virtiofs guard: control guest-created virtiofs fd pressure.

        Host virtiofsd normally holds one O_PATH fd per inode this guest keeps
        cached. Those fds are released when the guest evicts the inode and
        sends a FUSE FORGET. This script runs from {FDGUARD_TIMER} and:

        1. ensures /etc/updatedb.conf prunes virtiofs so the nightly
           plocate-updatedb sweep does not walk every shared inode;
        2. observes the guest-global fuse_inode slab count; and
        3. sheds reclaimable dentry/inode caches at a soft watermark, while
           an emergency watermark bypasses cooldown after sustained pressure.

        It writes 2 to /proc/sys/vm/drop_caches, which evicts reclaimable
        dentries and inodes but leaves page cache and dirty data intact. A
        first pass avoids global sync; sync plus a second pass is used only
        when the immediate reclaim does not get below the soft watermark.

        Managed by aivm (aivm/fdguard.py); local edits may be overwritten.
        """
        import json
        import os
        import re
        import sys
        import time

        CONF_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_CONF", "{FDGUARD_CONF}")
        SLABINFO_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_SLABINFO", "/proc/slabinfo")
        DROP_CACHES_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_DROP_CACHES", "/proc/sys/vm/drop_caches")
        UPDATEDB_CONF = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_UPDATEDB_CONF", "/etc/updatedb.conf")
        MOUNTINFO_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_MOUNTINFO", "/proc/self/mountinfo")
        STATE_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_STATE", "{FDGUARD_STATE}")
        ACTION_LOG_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_ACTION_LOG", "")
        SETTLE_SEC = float(os.environ.get(
            "AIVM_VIRTIOFS_GUARD_SETTLE_SEC", "5"))

        DEFAULT_THRESHOLD = {DEFAULT_FDGUARD_THRESHOLD}
        DEFAULT_EMERGENCY_THRESHOLD = {DEFAULT_FDGUARD_EMERGENCY_THRESHOLD}
        '''
    )
    body = textwrap.dedent(
        '''\
        # If normal-pressure reclaim is ineffective because inodes are pinned
        # by open files, process CWDs, or inotify watches, do not discard warm
        # metadata every tick. The emergency watermark always bypasses this.
        COOLDOWN_SEC = 900

        def read_watermarks():
            soft = DEFAULT_THRESHOLD
            emergency = DEFAULT_EMERGENCY_THRESHOLD
            try:
                with open(CONF_PATH, "r", encoding="utf-8") as file:
                    text = file.read()
            except OSError:
                return soft, emergency
            values = {}
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
            try:
                parsed = int(values.get("THRESHOLD", soft))
                if parsed > 0:
                    soft = parsed
            except ValueError:
                pass
            try:
                parsed = int(values.get("EMERGENCY_THRESHOLD", emergency))
                if parsed > soft:
                    emergency = parsed
            except ValueError:
                pass
            if emergency <= soft:
                emergency = max(DEFAULT_EMERGENCY_THRESHOLD, soft + 1)
            return soft, emergency

        def fuse_inode_active():
            """Return the guest-global count of active fuse_inode objects."""
            try:
                with open(SLABINFO_PATH, "r", encoding="utf-8") as file:
                    for line in file:
                        parts = line.split()
                        if parts and parts[0] == "fuse_inode":
                            return int(parts[1])
            except OSError:
                return None
            return 0

        def virtiofs_mounted():
            """Return True/False for a live virtiofs mount, or None on error."""
            try:
                with open(MOUNTINFO_PATH, "r", encoding="utf-8") as file:
                    for line in file:
                        if " - " not in line:
                            continue
                        tail = line.split(" - ", 1)[1].split()
                        if tail and tail[0].lower() in {
                            "virtiofs", "fuse.virtiofs"
                        }:
                            return True
            except OSError:
                return None
            return False

        def ensure_updatedb_prunes_virtiofs():
            """Return (status, message), where status may be degraded."""
            try:
                with open(UPDATEDB_CONF, "r", encoding="utf-8") as file:
                    text = file.read()
            except FileNotFoundError:
                return "not-applicable", None
            except OSError as ex:
                return "degraded", f"cannot read {UPDATEDB_CONF}: {ex}"
            match = re.search(r'^(PRUNEFS\\s*=\\s*")([^"]*)(")', text, flags=re.M)
            if match is None:
                return (
                    "degraded",
                    f"{UPDATEDB_CONF} has no PRUNEFS line; leaving unmodified",
                )
            tokens = match.group(2).split()
            lowered = {token.lower() for token in tokens}
            missing = [
                token
                for token in ("virtiofs", "fuse.virtiofs")
                if token.lower() not in lowered
            ]
            if not missing:
                return "ok", None
            new_value = " ".join(missing + tokens)
            new_text = text[: match.start(2)] + new_value + text[match.end(2):]
            tmp_path = UPDATEDB_CONF + ".aivm-tmp"
            try:
                stat = os.stat(UPDATEDB_CONF)
                with open(tmp_path, "w", encoding="utf-8") as file:
                    file.write(new_text)
                    file.flush()
                    os.fsync(file.fileno())
                if os.geteuid() == 0:
                    os.chown(tmp_path, stat.st_uid, stat.st_gid)
                os.chmod(tmp_path, stat.st_mode & 0o7777)
                os.replace(tmp_path, UPDATEDB_CONF)
            except OSError as ex:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                return "degraded", f"cannot update {UPDATEDB_CONF}: {ex}"
            return (
                "updated",
                f"added {' '.join(missing)} to PRUNEFS in {UPDATEDB_CONF}",
            )

        def read_state():
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as file:
                    data = json.load(file)
            except (OSError, ValueError):
                return {}
            if not isinstance(data, dict):
                return {}
            return data

        def write_state(data):
            payload = dict(data)
            payload["version"] = 2
            tmp_path = STATE_PATH + ".tmp"
            try:
                with open(tmp_path, "w", encoding="utf-8") as file:
                    json.dump(payload, file, sort_keys=True)
                    file.write("\\n")
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(tmp_path, STATE_PATH)
            except OSError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        def record_action(action):
            if not ACTION_LOG_PATH:
                return
            try:
                with open(ACTION_LOG_PATH, "a", encoding="utf-8") as file:
                    file.write(action + "\\n")
            except OSError:
                pass

        def drop_inode_caches(*, sync_first):
            if sync_first and DROP_CACHES_PATH == "/proc/sys/vm/drop_caches":
                record_action("sync")
                os.sync()
            record_action("drop_caches")
            with open(DROP_CACHES_PATH, "w", encoding="utf-8") as file:
                file.write("2\\n")

        def settle_and_count():
            if SETTLE_SEC > 0:
                time.sleep(SETTLE_SEC)
            return fuse_inode_active()

        def updatedb_status():
            try:
                with open(UPDATEDB_CONF, "r", encoding="utf-8") as file:
                    text = file.read()
                match = re.search(
                    r'^PRUNEFS\\s*=\\s*"([^"]*)"', text, flags=re.M
                )
                if match is None:
                    return "no PRUNEFS line"
                tokens = {token.lower() for token in match.group(1).split()}
                wanted = {"virtiofs", "fuse.virtiofs"}
                return "yes" if wanted <= tokens else "NO"
            except FileNotFoundError:
                return "n/a (no updatedb.conf)"
            except OSError:
                return "unknown"

        def age_text(timestamp):
            try:
                age = max(0, int(time.time() - float(timestamp)))
            except (TypeError, ValueError):
                return "unknown"
            return f"{age}s ago"

        def print_status():
            soft, emergency = read_watermarks()
            count = fuse_inode_active()
            mounted = virtiofs_mounted()
            shown = "unavailable (need root)" if count is None else str(count)
            mounted_shown = (
                "unknown" if mounted is None else ("yes" if mounted else "no")
            )
            print(f"fuse_inode active (all FUSE mounts): {shown}")
            print(f"virtiofs mounted: {mounted_shown}")
            print(f"soft threshold: {soft}")
            print(f"emergency threshold: {emergency}")
            if count is None:
                pressure = "unknown"
            elif count >= emergency:
                pressure = "EMERGENCY"
            elif count >= soft:
                pressure = "soft watermark exceeded"
            else:
                pressure = "normal"
            print(f"current pressure: {pressure}")
            print(f"updatedb prunes virtiofs: {updatedb_status()}")
            state = read_state()
            if not state:
                print("last check: never (since boot)")
                print("last flush: never (since boot)")
                print("health: unknown")
                return
            action = state.get("last_action", "unknown")
            print(
                f"last check: {age_text(state.get('last_check_ts'))} "
                f"(action: {action})"
            )
            if state.get("last_flush_ts"):
                print(
                    f"last flush: {age_text(state.get('last_flush_ts'))} "
                    f"({state.get('pre_flush')} -> {state.get('post_flush')}; "
                    f"stages: {state.get('flush_stages', 'unknown')})"
                )
            else:
                print("last flush: never (since boot)")
            degraded = state.get("degraded_reason")
            print(f"health: {'DEGRADED: ' + degraded if degraded else 'ok'}")

        def main(argv):
            if "--status" in argv:
                print_status()
                return 0

            now = time.time()
            previous = read_state()
            soft, emergency = read_watermarks()
            prune_status, prune_message = ensure_updatedb_prunes_virtiofs()
            if prune_message:
                print(f"aivm-virtiofs-guard: {prune_message}")

            count = fuse_inode_active()
            mounted = virtiofs_mounted()
            state = dict(previous)
            state.update(
                {
                    "last_check_ts": now,
                    "soft_threshold": soft,
                    "emergency_threshold": emergency,
                    "fuse_inode_count": count,
                    "virtiofs_mounted": mounted,
                    "updatedb_status": prune_status,
                }
            )
            degraded_reasons = []
            if prune_status == "degraded":
                degraded_reasons.append(prune_message or "updatedb pruning failed")
            if count is None:
                message = (
                    "cannot read fuse_inode slab "
                    f"from {SLABINFO_PATH} (need root)"
                )
                degraded_reasons.append(message)
                state["last_action"] = "probe-failed"
                state["degraded_reason"] = "; ".join(degraded_reasons)
                write_state(state)
                print(f"aivm-virtiofs-guard: {message}", file=sys.stderr)
                return 1

            if mounted is None:
                degraded_reasons.append(
                    f"cannot read mount information from {MOUNTINFO_PATH}"
                )
                state["last_action"] = "mount-probe-failed"
                state["pressure_degraded_reason"] = ""
                state["degraded_reason"] = "; ".join(degraded_reasons)
                write_state(state)
                return 1
            if mounted is False:
                state["last_action"] = "no-virtiofs-mount"
                state["pressure_degraded_reason"] = ""
                state["degraded_reason"] = "; ".join(degraded_reasons)
                write_state(state)
                return 1 if degraded_reasons else 0

            if count < soft:
                state["last_action"] = "below-soft-watermark"
                state["pressure_degraded_reason"] = ""
                state["degraded_reason"] = "; ".join(degraded_reasons)
                write_state(state)
                return 1 if degraded_reasons else 0

            emergency_mode = count >= emergency
            try:
                since_flush = now - float(previous.get("last_flush_ts", 0))
            except (TypeError, ValueError):
                since_flush = COOLDOWN_SEC + 1
            if not emergency_mode and since_flush < COOLDOWN_SEC:
                state["last_action"] = "soft-watermark-cooldown"
                pressure_reason = str(
                    previous.get("pressure_degraded_reason", "")
                ).strip()
                if pressure_reason:
                    degraded_reasons.append(pressure_reason)
                state["pressure_degraded_reason"] = pressure_reason
                state["degraded_reason"] = "; ".join(
                    dict.fromkeys(reason for reason in degraded_reasons if reason)
                )
                write_state(state)
                return 1 if degraded_reasons else 0

            pre = count
            mode = "emergency" if emergency_mode else "soft"
            stages = ["drop_caches"]
            try:
                drop_inode_caches(sync_first=False)
            except OSError as ex:
                message = f"cannot drop guest dentry/inode caches: {ex}"
                degraded_reasons.append(message)
                state.update(
                    {
                        "last_action": f"{mode}-watermark-flush-failed",
                        "last_flush_attempt_ts": now,
                        "pre_flush": pre,
                        "post_flush": pre,
                        "flush_stages": "drop_caches(error)",
                        "pressure_degraded_reason": message,
                        "degraded_reason": "; ".join(degraded_reasons),
                    }
                )
                write_state(state)
                print(f"aivm-virtiofs-guard: {message}", file=sys.stderr)
                return 1
            post = settle_and_count()

            # A second, more expensive pass is reserved for ineffective
            # immediate reclaim. sync makes dirty metadata eligible, but is
            # deliberately avoided on the normal fast path.
            if post is None or post >= soft:
                stages.append("sync+drop_caches")
                try:
                    drop_inode_caches(sync_first=True)
                except OSError as ex:
                    degraded_reasons.append(
                        f"cannot complete sync+drop_caches fallback: {ex}"
                    )
                else:
                    second = settle_and_count()
                    if second is not None:
                        post = second

            post_shown = "?" if post is None else post
            print(
                "aivm-virtiofs-guard: flushed guest dentry/inode caches "
                f"at {mode} watermark: fuse inodes {pre} -> {post_shown} "
                f"(soft {soft}, emergency {emergency}; "
                f"stages {','.join(stages)})"
            )

            pressure_reason = ""
            if post is None:
                pressure_reason = "cannot read fuse_inode count after flush"
            elif post >= emergency:
                pressure_reason = (
                    "fuse inode count remains above the emergency watermark; "
                    "inodes are likely pinned by open files, process working "
                    "directories, or inotify watchers"
                )
            elif post >= soft:
                pressure_reason = (
                    "fuse inode count remains above the soft watermark; "
                    "reclaimable metadata was not sufficient"
                )
            if pressure_reason:
                degraded_reasons.append(pressure_reason)

            state.update(
                {
                    "last_action": f"{mode}-watermark-flush",
                    "last_flush_attempt_ts": now,
                    "last_flush_ts": now,
                    "pre_flush": pre,
                    "post_flush": post,
                    "flush_stages": ",".join(stages),
                    "pressure_degraded_reason": pressure_reason,
                    "degraded_reason": "; ".join(degraded_reasons),
                }
            )
            write_state(state)
            if degraded_reasons:
                print(
                    "aivm-virtiofs-guard: WARNING: "
                    + "; ".join(degraded_reasons),
                    file=sys.stderr,
                )
                return 1
            return 0

        if __name__ == "__main__":
            raise SystemExit(main(sys.argv[1:]))
        '''
    )
    return header + body


def fdguard_conf_text(
    threshold: int = DEFAULT_FDGUARD_THRESHOLD,
    emergency_threshold: int = DEFAULT_FDGUARD_EMERGENCY_THRESHOLD,
) -> str:
    threshold = int(threshold)
    emergency_threshold = int(emergency_threshold)
    if threshold <= 0:
        raise ValueError('fd guard threshold must be a positive integer')
    if emergency_threshold <= threshold:
        raise ValueError(
            'fd guard emergency threshold must be greater than the soft threshold'
        )
    return textwrap.dedent(
        f"""\
        # aivm virtiofs guard configuration (KEY=VALUE).
        # THRESHOLD is the soft watermark. Crossing it permits a metadata-cache
        # flush unless a recent ineffective flush is still in cooldown.
        THRESHOLD={threshold}
        # EMERGENCY_THRESHOLD bypasses cooldown. Keep it comfortably below the
        # host virtiofsd fd ceiling, min(RLIMIT_NOFILE, fs.nr_open), which is
        # commonly about one million but must be checked when host limits differ.
        EMERGENCY_THRESHOLD={emergency_threshold}
        """
    )


def fdguard_service_unit() -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description=aivm virtiofs guard (fd watermarks + updatedb prune)

        [Service]
        Type=oneshot
        ExecStart={FDGUARD_BIN}
        TimeoutStartSec=600
        """
    )


def fdguard_timer_unit(
    interval_sec: int = DEFAULT_FDGUARD_INTERVAL_SEC,
) -> str:
    if int(interval_sec) <= 0:
        raise ValueError('fd guard interval must be a positive integer')
    return textwrap.dedent(
        f"""\
        [Unit]
        Description=Run the aivm virtiofs guard periodically

        [Timer]
        OnBootSec=90
        OnUnitActiveSec={int(interval_sec)}s
        AccuracySec=60s

        [Install]
        WantedBy=timers.target
        """
    )


def _b64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def fdguard_install_script(
    *,
    threshold: int = DEFAULT_FDGUARD_THRESHOLD,
    emergency_threshold: int = DEFAULT_FDGUARD_EMERGENCY_THRESHOLD,
    interval_sec: int = DEFAULT_FDGUARD_INTERVAL_SEC,
) -> str:
    """Guest shell script that atomically installs the guard over SSH.

    File payloads travel base64-encoded so no quoting rules apply to the
    embedded Python/unit content. Each payload is written to a sibling
    temporary path and renamed into place, so readers never observe a
    partially written managed file.
    """
    payloads = [
        (FDGUARD_BIN, '0755', fdguard_python()),
        (
            FDGUARD_CONF,
            '0644',
            fdguard_conf_text(threshold, emergency_threshold),
        ),
        (
            f'/etc/systemd/system/{FDGUARD_SERVICE}',
            '0644',
            fdguard_service_unit(),
        ),
        (
            f'/etc/systemd/system/{FDGUARD_TIMER}',
            '0644',
            fdguard_timer_unit(interval_sec),
        ),
    ]
    temp_paths = ' '.join(f'{path}.aivm-new.$$' for path, _, _ in payloads)
    lines = [
        'set -eu',
        'sudo -n mkdir -p /usr/local/libexec /etc/aivm /etc/systemd/system',
        f"trap 'sudo -n rm -f {temp_paths} 2>/dev/null || true' EXIT HUP INT TERM",
    ]
    for path, mode, content in payloads:
        encoded = _b64(content)
        tmp_path = f'{path}.aivm-new.$$'
        lines.append(
            f"printf '%s' {encoded} | base64 -d | "
            f'sudo -n tee {tmp_path} >/dev/null'
        )
        lines.append(f'sudo -n chmod {mode} {tmp_path}')
        lines.append(f'sudo -n chown root:root {tmp_path}')
        lines.append(f'sudo -n mv -f {tmp_path} {path}')
    lines += [
        'trap - EXIT HUP INT TERM',
        'sudo -n systemctl daemon-reload',
        f'sudo -n systemctl enable --now {FDGUARD_TIMER}',
        f'sudo -n systemctl start {FDGUARD_SERVICE}',
        f'sudo -n {FDGUARD_BIN} --status',
        'echo "aivm: virtiofs guard installed"',
    ]
    return '\n'.join(lines)


def _guard_payload_files(
    *,
    threshold: int,
    emergency_threshold: int,
    interval_sec: int,
) -> dict[str, str]:
    """Map probe hash keys to the file contents the guard should have."""
    return {
        'sha_bin': fdguard_python(),
        'sha_conf': fdguard_conf_text(threshold, emergency_threshold),
        'sha_service': fdguard_service_unit(),
        'sha_timer': fdguard_timer_unit(interval_sec),
    }


def fdguard_expected_hashes(
    *,
    threshold: int = DEFAULT_FDGUARD_THRESHOLD,
    emergency_threshold: int = DEFAULT_FDGUARD_EMERGENCY_THRESHOLD,
    interval_sec: int = DEFAULT_FDGUARD_INTERVAL_SEC,
) -> dict[str, str]:
    """sha256 of each guard file as the current config would render it."""
    return {
        key: hashlib.sha256(content.encode('utf-8')).hexdigest()
        for key, content in _guard_payload_files(
            threshold=threshold,
            emergency_threshold=emergency_threshold,
            interval_sec=interval_sec,
        ).items()
    }


def fdguard_probe_script() -> str:
    """Read-only guest script reporting install and timer health.

    Emits ``installed``, timer enable/active state, the latest oneshot
    service result, and a ``sha_*`` line per managed file so drift detection
    can compare against :func:`fdguard_expected_hashes` without sudo.
    """
    hash_targets = {
        'sha_bin': FDGUARD_BIN,
        'sha_conf': FDGUARD_CONF,
        'sha_service': FDGUARD_SERVICE_PATH,
        'sha_timer': FDGUARD_TIMER_PATH,
    }
    lines = [
        'set -eu',
        f'if [ -x {FDGUARD_BIN} ]; then echo "installed=yes"; '
        'else echo "installed=no"; fi',
        f'echo "timer_enabled=$(systemctl is-enabled {FDGUARD_TIMER} '
        '2>/dev/null || echo not-found)"',
        f'echo "timer_active=$(systemctl is-active {FDGUARD_TIMER} '
        '2>/dev/null || echo inactive)"',
        f'echo "service_result=$(systemctl show {FDGUARD_SERVICE} '
        '--property=Result --value 2>/dev/null || echo unknown)"',
    ]
    for key, path in hash_targets.items():
        lines.append(
            f"printf '{key}=%s\\n' "
            f'"$(sha256sum {path} 2>/dev/null | cut -d\' \' -f1)"'
        )
    return '\n'.join(lines)


def parse_fdguard_probe(text: str) -> dict[str, str]:
    """Parse :func:`fdguard_probe_script` output into a dict."""
    state: dict[str, str] = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        if key:
            state[key] = value.strip()
    return state


def fdguard_status_script() -> str:
    return '\n'.join(
        [
            'set -eu',
            f'echo "== {FDGUARD_TIMER} =="',
            f'systemctl is-enabled {FDGUARD_TIMER} 2>&1 || true',
            f'systemctl is-active {FDGUARD_TIMER} 2>&1 || true',
            f'systemctl show {FDGUARD_SERVICE} --property=Result '
            '--property=ExecMainStatus 2>&1 || true',
            'echo "== recent guard runs =="',
            f'sudo -n journalctl -u {FDGUARD_SERVICE} -n 15 --no-pager '
            '--output cat 2>&1 || true',
            'echo "== guard status =="',
            f'if [ -x {FDGUARD_BIN} ]; then sudo -n {FDGUARD_BIN} --status; '
            f'else echo "guard not installed ({FDGUARD_BIN} missing)"; fi',
        ]
    )


def fdguard_uninstall_script() -> str:
    return '\n'.join(
        [
            'set -eu',
            f'sudo -n systemctl disable --now {FDGUARD_TIMER} '
            '2>/dev/null || true',
            f'sudo -n rm -f /etc/systemd/system/{FDGUARD_TIMER} '
            f'/etc/systemd/system/{FDGUARD_SERVICE} {FDGUARD_BIN} '
            f'{FDGUARD_CONF}',
            'sudo -n systemctl daemon-reload',
            'echo "aivm: virtiofs guard uninstalled; the safe updatedb '
            'PRUNEFS entries are intentionally retained"',
        ]
    )
