"""Guest-side virtiofs fd guard: templates and install scripts.

Why this exists
---------------

Host-side ``virtiofsd`` represents every inode the *guest* keeps cached with
one open ``O_PATH`` file descriptor on the host (it lacks
``CAP_DAC_READ_SEARCH``, so it cannot use file handles instead). The guest
kernel only releases those inodes (FUSE ``FORGET``) under memory pressure or
an explicit ``drop_caches`` write, so on large-RAM guests the daemon's fd
count grows monotonically toward ``min(RLIMIT_NOFILE, fs.nr_open)`` --
typically 1,048,576 -- after which every lookup/open on the share fails and
the guest sees ``EMFILE`` (``[Errno 24] Too many open files``).

Two guest-side facts make this both deterministic and fixable from inside
the VM:

1. Ubuntu's stock ``/etc/updatedb.conf`` ``PRUNEFS`` does **not** include
   ``virtiofs``, and the cloud image ships ``plocate`` with a daily
   ``plocate-updatedb.timer``. Every attached share therefore gets fully
   re-walked nightly, touching every inode -- one sweep over a multi-million
   inode share saturates virtiofsd on its own.
2. The guest-visible ``fuse_inode`` slab count tracks the host daemon's
   path-backed fd count almost 1:1, so the guest can observe the pressure it
   is creating and shed it (``drop_caches=2``) before the host ceiling is
   reached. Measured on 2026-05-17: a guest cache drop took the hot daemon
   from 999,778 fds to 45 within ~30 seconds.

The guard installed here is a small root-owned script run from a systemd
timer inside the guest. Each tick it (a) idempotently ensures updatedb
prunes virtiofs and (b) flushes guest dentry/inode caches when the fuse
inode count crosses a watermark. See ``docs/source/virtiofs.rst`` for the
full analysis.

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
DEFAULT_FDGUARD_INTERVAL_SEC = 60


def fdguard_python() -> str:
    """Render the guest-side guard script.

    Paths are overridable via ``AIVM_VIRTIOFS_GUARD_*`` environment
    variables so the script's behavior is directly testable outside a
    guest; production systemd invocation uses the defaults.
    """
    header = textwrap.dedent(
        f'''\
        #!/usr/bin/env python3
        """aivm virtiofs guard: keep guest fuse inode cache below the host fd budget.

        Host virtiofsd holds one O_PATH fd per inode this guest keeps cached;
        those fds are only released when the guest evicts the inode (FUSE
        FORGET). This script runs from {FDGUARD_TIMER} and:

        1. ensures /etc/updatedb.conf prunes virtiofs so the nightly
           plocate-updatedb sweep does not walk every shared inode; and
        2. writes 2 to /proc/sys/vm/drop_caches (dentries+inodes only) when
           the fuse_inode slab count exceeds THRESHOLD from {FDGUARD_CONF}.

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
        STATE_PATH = os.environ.get(
            "AIVM_VIRTIOFS_GUARD_STATE", "{FDGUARD_STATE}")

        DEFAULT_THRESHOLD = {DEFAULT_FDGUARD_THRESHOLD}
        '''
    )
    body = textwrap.dedent(
        '''\
        # After a flush that fails to reclaim (inodes pinned by open files or
        # inotify watchers), do not re-flush every tick: wait for the cooldown
        # or for meaningful regrowth over the post-flush floor.
        COOLDOWN_SEC = 900
        REGROW_FACTOR = 1.10

        def read_threshold():
            try:
                with open(CONF_PATH, "r", encoding="utf-8") as file:
                    text = file.read()
            except OSError:
                return DEFAULT_THRESHOLD
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("THRESHOLD="):
                    value = line.split("=", 1)[1].strip()
                    try:
                        parsed = int(value)
                    except ValueError:
                        return DEFAULT_THRESHOLD
                    if parsed > 0:
                        return parsed
            return DEFAULT_THRESHOLD

        def fuse_inode_active():
            """Count of allocated fuse_inode slab objects (needs root)."""
            try:
                with open(SLABINFO_PATH, "r", encoding="utf-8") as file:
                    for line in file:
                        parts = line.split()
                        if parts and parts[0] == "fuse_inode":
                            return int(parts[1])
            except OSError:
                return None
            return 0

        def ensure_updatedb_prunes_virtiofs():
            """Idempotently add virtiofs to PRUNEFS. Returns a message or None."""
            try:
                with open(UPDATEDB_CONF, "r", encoding="utf-8") as file:
                    text = file.read()
            except FileNotFoundError:
                return None
            except OSError as ex:
                return f"cannot read {UPDATEDB_CONF}: {ex}"
            match = re.search(r'^(PRUNEFS\\s*=\\s*")([^"]*)(")', text, flags=re.M)
            if match is None:
                return f"{UPDATEDB_CONF} has no PRUNEFS line; leaving unmodified"
            tokens = match.group(2).split()
            lowered = {token.lower() for token in tokens}
            missing = [
                token
                for token in ("virtiofs", "fuse.virtiofs")
                if token.lower() not in lowered
            ]
            if not missing:
                return None
            new_value = " ".join(missing + tokens)
            new_text = text[: match.start(2)] + new_value + text[match.end(2):]
            tmp_path = UPDATEDB_CONF + ".aivm-tmp"
            try:
                mode = os.stat(UPDATEDB_CONF).st_mode & 0o7777
                with open(tmp_path, "w", encoding="utf-8") as file:
                    file.write(new_text)
                os.chmod(tmp_path, mode)
                os.replace(tmp_path, UPDATEDB_CONF)
            except OSError as ex:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                return f"cannot update {UPDATEDB_CONF}: {ex}"
            return f"added {' '.join(missing)} to PRUNEFS in {UPDATEDB_CONF}"

        def read_state():
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as file:
                    data = json.load(file)
            except (OSError, ValueError):
                return None
            if not isinstance(data, dict):
                return None
            return data

        def write_state(post_count):
            data = {"ts": time.time(), "post": int(post_count)}
            try:
                with open(STATE_PATH, "w", encoding="utf-8") as file:
                    json.dump(data, file)
            except OSError:
                pass

        def flush_caches():
            if DROP_CACHES_PATH == "/proc/sys/vm/drop_caches":
                # Flush dirty pages first so dirty inodes are also evictable.
                # Skipped under test-path overrides to keep tests hermetic.
                os.sync()
            with open(DROP_CACHES_PATH, "w") as file:
                file.write("2\\n")

        def print_status():
            threshold = read_threshold()
            count = fuse_inode_active()
            shown = "unavailable (need root)" if count is None else str(count)
            print(f"fuse_inode active: {shown}")
            print(f"threshold: {threshold}")
            pruned = "unknown"
            try:
                with open(UPDATEDB_CONF, "r", encoding="utf-8") as file:
                    text = file.read()
                match = re.search(r'^PRUNEFS\\s*=\\s*"([^"]*)"', text, flags=re.M)
                if match is None:
                    pruned = "no PRUNEFS line"
                else:
                    tokens = {token.lower() for token in match.group(1).split()}
                    pruned = "yes" if "virtiofs" in tokens else "NO"
            except FileNotFoundError:
                pruned = "n/a (no updatedb.conf)"
            except OSError:
                pass
            print(f"updatedb prunes virtiofs: {pruned}")
            state = read_state()
            if state:
                age = int(time.time() - float(state.get("ts", 0)))
                print(f"last flush: {age}s ago (post-flush fuse inodes: {state.get('post')})")
            else:
                print("last flush: never (since boot)")

        def main(argv):
            if "--status" in argv:
                print_status()
                return 0
            message = ensure_updatedb_prunes_virtiofs()
            if message:
                print(f"aivm-virtiofs-guard: {message}")
            count = fuse_inode_active()
            if count is None:
                print(
                    "aivm-virtiofs-guard: cannot read fuse_inode slab "
                    f"from {SLABINFO_PATH} (need root)",
                    file=sys.stderr,
                )
                return 1
            threshold = read_threshold()
            if count < threshold:
                return 0
            state = read_state()
            if state is not None:
                age = time.time() - float(state.get("ts", 0))
                floor = int(state.get("post", 0))
                if age < COOLDOWN_SEC and count < floor * REGROW_FACTOR:
                    return 0
            flush_caches()
            post = fuse_inode_active()
            post_shown = "?" if post is None else post
            print(
                "aivm-virtiofs-guard: flushed guest dentry/inode caches: "
                f"fuse inodes {count} -> {post_shown} (threshold {threshold})"
            )
            if post is not None and post >= threshold * 0.9:
                print(
                    "aivm-virtiofs-guard: WARNING: fuse inode count stayed "
                    f"near the threshold after a flush ({post}); inodes are "
                    "likely pinned by open files or inotify watchers "
                    "(editors, file watchers). virtiofsd fd pressure cannot "
                    "be shed for those until they are closed."
                )
            write_state(post if post is not None else count)
            return 0

        if __name__ == "__main__":
            raise SystemExit(main(sys.argv[1:]))
        '''
    )
    return header + body


def fdguard_conf_text(
    threshold: int = DEFAULT_FDGUARD_THRESHOLD,
) -> str:
    if int(threshold) <= 0:
        raise ValueError('fd guard threshold must be a positive integer')
    return textwrap.dedent(
        f'''\
        # aivm virtiofs guard configuration (KEY=VALUE).
        # THRESHOLD: flush guest dentry/inode caches when the fuse_inode slab
        # count exceeds this value. Keep it well below the host virtiofsd fd
        # ceiling, min(RLIMIT_NOFILE, fs.nr_open) -- typically 1,048,576.
        THRESHOLD={int(threshold)}
        '''
    )


def fdguard_service_unit() -> str:
    return textwrap.dedent(
        f'''\
        [Unit]
        Description=aivm virtiofs guard (fd watermark flush + updatedb prune)

        [Service]
        Type=oneshot
        ExecStart={FDGUARD_BIN}
        TimeoutStartSec=600
        '''
    )


def fdguard_timer_unit(
    interval_sec: int = DEFAULT_FDGUARD_INTERVAL_SEC,
) -> str:
    if int(interval_sec) <= 0:
        raise ValueError('fd guard interval must be a positive integer')
    return textwrap.dedent(
        f'''\
        [Unit]
        Description=Run the aivm virtiofs guard periodically

        [Timer]
        OnBootSec=90
        OnUnitActiveSec={int(interval_sec)}s
        AccuracySec=30s

        [Install]
        WantedBy=timers.target
        '''
    )


def _b64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def fdguard_install_script(
    *,
    threshold: int = DEFAULT_FDGUARD_THRESHOLD,
    interval_sec: int = DEFAULT_FDGUARD_INTERVAL_SEC,
) -> str:
    """Guest shell script that installs/updates the guard over SSH.

    File payloads travel base64-encoded so no quoting rules apply to the
    embedded Python/unit content.
    """
    payloads = [
        (FDGUARD_BIN, '0755', fdguard_python()),
        (FDGUARD_CONF, '0644', fdguard_conf_text(threshold)),
        (f'/etc/systemd/system/{FDGUARD_SERVICE}', '0644', fdguard_service_unit()),
        (f'/etc/systemd/system/{FDGUARD_TIMER}', '0644', fdguard_timer_unit(interval_sec)),
    ]
    lines = [
        'set -eu',
        'sudo -n mkdir -p /usr/local/libexec /etc/aivm /etc/systemd/system',
    ]
    for path, mode, content in payloads:
        encoded = _b64(content)
        lines.append(
            f"printf '%s' {encoded} | base64 -d | sudo -n tee {path} >/dev/null"
        )
        lines.append(f'sudo -n chmod {mode} {path}')
    lines += [
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
    interval_sec: int,
) -> dict[str, str]:
    """Map probe hash keys to the file contents the guard should have."""
    return {
        'sha_bin': fdguard_python(),
        'sha_conf': fdguard_conf_text(threshold),
        'sha_service': fdguard_service_unit(),
        'sha_timer': fdguard_timer_unit(interval_sec),
    }


def fdguard_expected_hashes(
    *,
    threshold: int = DEFAULT_FDGUARD_THRESHOLD,
    interval_sec: int = DEFAULT_FDGUARD_INTERVAL_SEC,
) -> dict[str, str]:
    """sha256 of each guard file as the current config would render it."""
    return {
        key: hashlib.sha256(content.encode('utf-8')).hexdigest()
        for key, content in _guard_payload_files(
            threshold=threshold, interval_sec=interval_sec
        ).items()
    }


def fdguard_probe_script() -> str:
    """Read-only guest script reporting guard install state as KEY=VALUE.

    Emits ``installed``, ``timer_enabled``, and a ``sha_*`` line per managed
    file (empty value when the file is absent) so drift detection can compare
    against :func:`fdguard_expected_hashes` without sudo.
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
    ]
    for key, path in hash_targets.items():
        lines.append(
            f'printf \'{key}=%s\\n\' '
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
            'echo "== recent guard runs =="',
            f'sudo -n journalctl -u {FDGUARD_SERVICE} -n 15 --no-pager --output cat 2>&1 || true',
            'echo "== guard status =="',
            f'if [ -x {FDGUARD_BIN} ]; then sudo -n {FDGUARD_BIN} --status; '
            f'else echo "guard not installed ({FDGUARD_BIN} missing)"; fi',
        ]
    )


def fdguard_uninstall_script() -> str:
    return '\n'.join(
        [
            'set -eu',
            f'sudo -n systemctl disable --now {FDGUARD_TIMER} 2>/dev/null || true',
            f'sudo -n rm -f /etc/systemd/system/{FDGUARD_TIMER} '
            f'/etc/systemd/system/{FDGUARD_SERVICE} {FDGUARD_BIN} {FDGUARD_CONF}',
            'sudo -n systemctl daemon-reload',
            'echo "aivm: virtiofs guard uninstalled"',
        ]
    )
