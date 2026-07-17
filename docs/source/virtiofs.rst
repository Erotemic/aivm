Virtiofs sharing and the EMFILE problem
=======================================

This page explains why long-lived virtiofs attachments have historically
failed with ``Too many open files`` (``EMFILE`` / ``OSError: [Errno 24]``),
what triggers it, and how aivm now mitigates it automatically. It replaces
the guidance of running periodic host-side ``aivm vm flush_caches`` jobs.

TL;DR
-----

* Host-side ``virtiofsd`` holds **one open file descriptor per inode the
  guest keeps cached**, and the guest keeps inodes cached until something
  forces eviction. On a large-RAM guest nothing ever does, so the daemon's
  fd count only grows.
* The ceiling is ``min(RLIMIT_NOFILE, fs.nr_open)`` on the host — typically
  1,048,576. Once reached, every lookup/open/stat on the share fails and
  the *guest* sees ``EMFILE`` even though guest limits look fine.
* The dominant trigger was hiding in the guest OS, not in any workload:
  Ubuntu ships ``plocate`` with a **daily updatedb sweep**, and virtiofs is
  **not** in the stock ``PRUNEFS`` list, so every attached tree was fully
  re-walked (every inode touched) every night.
* aivm now installs a guest-side systemd timer (the *virtiofs guard*) that
  (a) keeps updatedb from indexing virtiofs mounts and (b) uses soft and
  emergency watermarks to flush guest dentry/inode caches under sustained
  pressure. It intentionally tolerates short bursts and is not a strict
  instantaneous bound on the host daemon's descriptor count.
  New VMs get it via cloud-init; retrofit existing VMs with
  ``aivm vm fdguard --action install``.

The mechanism
-------------

Four facts combine into the failure:

1. **One host fd per guest-cached inode.** For every inode the guest kernel
   has instantiated (every file/directory it has ever looked up and not yet
   evicted), ``virtiofsd`` keeps an ``O_PATH`` descriptor open on the host.
   It cannot use file handles instead because libvirt's managed launch drops
   ``CAP_DAC_READ_SEARCH`` (see `The structural fix that is not available
   yet`_). There is no internal LRU: the daemon rides all the way to its
   rlimit.
2. **The guest never forgets on its own.** The guest kernel releases a FUSE
   inode (sending ``FORGET``, which lets virtiofsd close the fd) only under
   memory pressure or an explicit ``drop_caches``. Closing files does
   *not* release them — the dentry/inode cache retention is the point of a
   cache. A guest with tens of GB of RAM can cache millions of inodes
   indefinitely, so daemon-side fds accumulate across the VM's lifetime.
3. **The ceiling is host-side and invisible to the guest.** virtiofsd
   raises its own limit to ``min(1,000,000, fs.nr_open)``; ``fs.nr_open``
   defaults to 1,048,576. When the daemon hits it, its ``openat``/``statx``
   work on behalf of the guest fails, and the error propagates back through
   FUSE — which is why guest ``ulimit -n`` and ``fs.file-nr`` look healthy
   while ``ls`` fails with ``EMFILE``.
4. **Attached trees are bigger than the ceiling.** A handful of repos with
   ``.venv``/``target``/report/cache directories easily exceeds 1M inodes
   (a measured aivm persistent root contained 2.1M–7.6M entries). Any
   process that walks everything is guaranteed to saturate the daemon.

This was confirmed live on 2026-05-17: a persistent-root worker sat at
999,778 of 1,000,000 fds — 999,756 of them path-backed descriptors under the
attached token trees — and a single guest ``drop_caches=2`` took it to **45
fds within ~30 seconds** (the residual floor is one handle per attachment
root plus daemon plumbing). See
``dev/devcheck/virtiofsd_emfile_case_report_2026_05_17.md`` for the full
post-mortem.

The hidden trigger: the guest's nightly updatedb sweep
------------------------------------------------------

The incident fd composition was a broad, uniform sweep across *every*
attached tree — old report forests, virtualenvs, ``.git/objects``, mypy
caches — not the focused footprint of any agent workload. That is the
signature of a filesystem indexer, and the guest has one:

* Ubuntu cloud images ship ``plocate`` with ``plocate-updatedb.timer``
  enabled (daily, randomized start).
* The stock ``/etc/updatedb.conf`` ``PRUNEFS`` list prunes NFS, sshfs, 9p
  and friends — but **not** ``virtiofs``, which from the guest's
  perspective is a local filesystem.
* ``PRUNENAMES`` is commented out by default, so even ``.git`` gets walked.

So every night updatedb walked every inode of every attachment (verified:
the guest's ``plocate.db`` was 92 MB and contained the full incident tree),
recreating the saturated state daily no matter how carefully workloads
behaved, and turning the periodic ``flush_caches`` cron into a race. Any
other full-tree walker (``updatedb``, backup indexers, virus scans,
``grep -r`` at the share root, IDE indexers) has the same effect — which is
why the fix below is a watermark guard, not just an updatedb exception.

What aivm does about it now
---------------------------

aivm installs a small root-owned helper inside the guest — the **virtiofs
guard** (``/usr/local/libexec/aivm-virtiofs-guard``, run every
``virtiofs.fd_guard_interval_sec`` seconds by
``aivm-virtiofs-guard.timer``). Each tick it:

1. **Prunes indexers** — idempotently and atomically ensures both
   ``virtiofs`` and ``fuse.virtiofs`` are in ``PRUNEFS`` in
   ``/etc/updatedb.conf``. A missing ``updatedb.conf`` is harmless; an
   unreadable or malformed file is recorded as degraded health rather than
   silently treated as success.
2. **Checks whether virtiofs is mounted** — the guest-global ``fuse_inode``
   slab includes other FUSE filesystems such as sshfs. The guard therefore
   does not flush merely because another FUSE filesystem is busy when no
   virtiofs mount is present.
3. **Observes two watermarks** — it reads the guest-global ``fuse_inode``
   count from ``/proc/slabinfo``. In the observed aivm topology this tracks
   host virtiofsd path-backed fds nearly 1:1, but it is a conservative proxy,
   not a per-mount or per-daemon measurement.
4. **Sheds pressure in two stages** — crossing the soft watermark
   (``fd_guard_threshold``, default 500,000) permits a flush unless a recent
   ineffective flush is in cooldown. Crossing the emergency watermark
   (``fd_guard_emergency_threshold``, default 750,000) bypasses cooldown. The
   first pass writes ``2`` to ``/proc/sys/vm/drop_caches`` without a global
   ``sync``. Only when the count remains above the soft watermark does it run
   ``sync`` and try once more. Value ``2`` evicts reclaimable dentries and
   inodes; it does not discard dirty data or file page cache.
5. **Records health** — ``/run/aivm-virtiofs-guard.json`` records the last
   check, action, pre/post counts, flush stages, updatedb status, and any
   degraded reason. ``aivm vm fdguard`` displays this together with timer and
   systemd service health.

The default interval is deliberately relaxed to 600 seconds (10 minutes).
This means a short burst can cross either watermark and finish before a
check; that is intentional. The guard is aimed at long-lived accumulation
and repeated broad walks, not at enforcing a strict instantaneous cap. At
the next tick, emergency pressure bypasses cooldown and triggers an immediate
recovery attempt. A blind host cron is still worse: it flushes even when
idle, cannot remove the updatedb trigger, and has no pressure or health
feedback.

Deployment — the guard is config-driven and reconciled like everything
else:

* **New VMs**: installed automatically via cloud-init when
  ``virtiofs.fd_guard`` is enabled (the default).
* **Existing VMs**: ``aivm vm update`` detects guard drift against config
  while the VM is running and reachable — not installed, timer disabled or
  inactive, or installed files differing from what current config renders
  (e.g. changed watermarks/interval or a newer aivm) — plans the
  install/refresh/uninstall alongside CPU/RAM/disk changes, and applies it
  over SSH. Setting ``fd_guard = false`` and running ``aivm vm update``
  uninstalls it. If the VM is down or unreachable, update reports a note
  and reconciles on a later run; no restart is ever required.
* **Manual control**: ``aivm vm fdguard`` remains for direct use —
  ``status`` (the default action) shows timer/service state, recent guard
  runs, the live guest-global FUSE inode count, both watermarks, updatedb
  pruning, and degraded health; ``--action install`` /
  ``--action uninstall`` apply immediately
  without a full update pass. Uninstall removes the timer, service, helper,
  and guard config, but intentionally leaves the safe updatedb ``PRUNEFS``
  entries in place.

Config knobs (``[virtiofs]`` in ``~/.config/aivm/config.toml``)::

   [virtiofs]
   fd_guard = true                         # install the guard in guests
   fd_guard_threshold = 500000             # soft watermark
   fd_guard_emergency_threshold = 750000   # bypass cooldown here
   fd_guard_interval_sec = 600             # check every 10 minutes

Retiring old workarounds
------------------------

If you run a host-side cron/loop that calls ``aivm vm flush_caches``
periodically: once the guard is installed in the guest, **that job is no
longer needed** and should be removed — the guard performs the same flush,
but only when the watermark is actually approached, and it also removes the
nightly updatedb saturation at the source. ``aivm vm flush_caches`` remains
available as a manual recovery/diagnostic command.

Sizing the budget
-----------------

The invariant to preserve is::

   max guest-cached virtiofs inodes  <  min(virtiofsd RLIMIT_NOFILE, fs.nr_open)

* The guard attempts to control the left side with a 500,000 soft
  watermark and a 750,000 emergency watermark. Because it polls rather than
  intercepting lookups, neither value is a strict instantaneous bound.
* The right side is typically 1,048,576 (``fs.nr_open`` default; virtiofsd
  raises its own soft limit to ``min(1,000,000, nr_open)``).
* Each retained descriptor costs host kernel memory (a ``struct file`` plus
  the pinned host dentry/inode) — roughly 1 KB each, so a saturated
  million-fd daemon also pins ~1 GB of host slab. Raising host limits
  (``fs.nr_open`` + ``prlimit --nofile`` on a live daemon) buys headroom in
  an emergency but does not change the growth behavior; prefer the guard.
* On the guest side, 500k cached FUSE inodes cost roughly 0.5–0.7 GB of
  guest slab; lower both watermarks on small-RAM guests if needed. Keep the
  emergency watermark comfortably below the actual host virtiofsd soft
  ``RLIMIT_NOFILE``. The guest cannot discover that host-side limit itself.

Residual risks and hygiene
--------------------------

* **Pinned inodes cannot be shed.** ``drop_caches`` cannot evict inodes
  held by open files, process CWDs, or inotify watches (editors and file
  watchers such as VS Code hold many). If a soft-watermark flush is
  ineffective, the guard backs off for a cooldown period rather than
  flushing every tick; the emergency watermark still bypasses cooldown. If
  degraded health persists, a guest process is probably holding a huge
  watched/open set. Close the pinning process or raise host limits.
* **Keep attachments narrow.** Every attached inode is potential fd
  pressure. Avoid attaching home directories or trees dominated by
  ``.venv``/``target``/report forests when the workload does not need
  them; prefer ``--mode git`` for repos that tolerate explicit handoff.
* **Detach and clean stale trees.** Historical incidents were amplified by
  stale token trees left exported (including an accidental whole-home
  attach). Detach folders you no longer use so their inodes cannot be
  walked at all.

The structural fix that is not available yet
--------------------------------------------

``virtiofsd --inode-file-handles=prefer`` makes the daemon store *file
handles* (``name_to_handle_at``) instead of open ``O_PATH`` descriptors,
reducing fd usage from O(cached inodes) to O(concurrently open files) and
eliminating this failure class outright. aivm does not enable it because
the delivery paths are currently unacceptable or unavailable:

* **libvirt XML**: libvirt 10.0 (Ubuntu 24.04) exposes no
  ``inode-file-handles`` knob on ``<filesystem>``/``<binary>``. Re-check
  newer libvirt releases; first-class XML support is the preferred path.
* **Generated wrapper binaries**: rewriting ``<binary path=...>`` to an
  aivm-generated wrapper script broke VM startup ("virtiofsd died
  unexpectedly") and was rejected on host-trust grounds — aivm must not
  make libvirt execute generated host-side code.
* **Capabilities**: decoding a file handle (``open_by_handle_at``) requires
  ``CAP_DAC_READ_SEARCH``. virtiofsd's default capability set drops it, so
  the flag must be paired with ``--modcaps=+dac_read_search``. Note the
  observed ``CapBnd: 0`` on a running daemon does **not** preclude this:
  the bounding set is emptied by virtiofsd itself after startup and only
  constrains ``execve``; a daemon launched as root with ``--modcaps`` can
  retain the capability. This does mean the fix is only possible for
  privileged (root-launched) virtiofsd — under a fully unprivileged
  session-style launch, ``open_by_handle_at`` is unavailable on current
  kernels, and watermark control is the only lever.
* **Admin-owned external virtiofsd**: libvirt supports externally launched
  virtiofsd via a vhost-user socket, which would allow arbitrary flags
  under an administrator-reviewed systemd unit. This is the documented
  escape hatch if file handles are needed before libvirt exposes them; aivm
  will not install it automatically.

Incident runbook (saturated daemon)
-----------------------------------

Symptoms: guest tools fail with ``Too many open files`` on shared paths
while ``ulimit -n`` looks fine; on the host,
``ls /proc/<virtiofsd-pid>/fd | wc -l`` for the hot worker is at its
``Max open files`` limit (compare with ``grep 'open files'
/proc/<pid>/limits``).

1. ``aivm vm flush_caches`` — evicts guest dentry/inode caches; the hot
   daemon should drop to a small floor within seconds. This is the same
   action the guard automates.
2. If the guest is too wedged for SSH: on the host, raise the ceiling to
   restore service, then flush::

      sudo sysctl -w fs.nr_open=2097152
      sudo prlimit --pid <hot-pid> --nofile=2000000:2000000

3. Check why the guard did not prevent it: ``aivm vm fdguard`` (installed?
   timer active? pinned-floor warnings in the journal?).
4. For evidence collection (fd composition by token/directory/suffix), use
   ``dev/devcheck/virtiofsd_fd_postmortem.py collect --vm <name>``.
5. VM restart remains the last-resort reset.
