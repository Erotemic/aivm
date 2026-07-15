Virtiofs sharing and the EMFILE problem
=======================================

This page explains why long-lived virtiofs attachments have historically
failed with ``Too many open files`` (``EMFILE`` / ``OSError: [Errno 24]``),
what triggers it, and how aivm now prevents it automatically. It replaces
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
  (a) keeps updatedb from indexing virtiofs mounts and (b) flushes guest
  dentry/inode caches when the cached-inode count crosses a watermark,
  releasing the host-side descriptors before the ceiling is reached.
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

1. **Prunes indexers** — idempotently ensures ``virtiofs`` is in
   ``PRUNEFS`` in ``/etc/updatedb.conf`` (self-healing if plocate is
   installed or reconfigured later).
2. **Watches the watermark** — reads the ``fuse_inode`` slab count from
   ``/proc/slabinfo``. This guest-visible number tracks the host daemon's
   path-backed fd count nearly 1:1, so the guest can see the pressure it is
   creating without any host cooperation.
3. **Sheds pressure when needed** — if the count exceeds
   ``virtiofs.fd_guard_threshold`` (default 500,000, i.e. ~50% of the usual
   host ceiling), it runs ``sync`` and writes ``2`` to
   ``/proc/sys/vm/drop_caches`` (dentries and inodes only; page cache is
   untouched). The resulting FUSE ``FORGET`` storm lets virtiofsd close its
   retained descriptors within seconds. A cooldown prevents flush-thrash
   when inodes are pinned (see below).

Because the guard is closed-loop, it does nothing while the cache is small
(no blind periodic flushes discarding warm caches) and reacts within one
interval when a mass traversal starts — a blind 30-minute host cron can be
both too aggressive when idle and too slow during a fast sweep.

Deployment — the guard is config-driven and reconciled like everything
else:

* **New VMs**: installed automatically via cloud-init when
  ``virtiofs.fd_guard`` is enabled (the default).
* **Existing VMs**: ``aivm vm update`` detects guard drift against config
  while the VM is running and reachable — not installed, timer disabled,
  or installed files differing from what current config renders (e.g. a
  changed ``fd_guard_threshold`` or a newer aivm) — plans the
  install/refresh/uninstall alongside CPU/RAM/disk changes, and applies it
  over SSH. Setting ``fd_guard = false`` and running ``aivm vm update``
  uninstalls it. If the VM is down or unreachable, update reports a note
  and reconciles on a later run; no restart is ever required.
* **Manual control**: ``aivm vm fdguard`` remains for direct use —
  ``status`` (the default action) shows the timer state, recent guard
  runs, the live fuse inode count, threshold, and whether updatedb is
  pruned; ``--action install`` / ``--action uninstall`` apply immediately
  without a full update pass.

Config knobs (``[virtiofs]`` in ``~/.config/aivm/config.toml``)::

   [virtiofs]
   fd_guard = true              # install the guard in guests
   fd_guard_threshold = 500000  # flush when cached fuse inodes exceed this
   fd_guard_interval_sec = 60   # guard check period

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

* The guard bounds the left side (default 500,000).
* The right side is typically 1,048,576 (``fs.nr_open`` default; virtiofsd
  raises its own soft limit to ``min(1,000,000, nr_open)``).
* Each retained descriptor costs host kernel memory (a ``struct file`` plus
  the pinned host dentry/inode) — roughly 1 KB each, so a saturated
  million-fd daemon also pins ~1 GB of host slab. Raising host limits
  (``fs.nr_open`` + ``prlimit --nofile`` on a live daemon) buys headroom in
  an emergency but does not change the growth behavior; prefer the guard.
* On the guest side, 500k cached fuse inodes cost ~0.5–0.7 GB of guest slab;
  lower ``fd_guard_threshold`` on small-RAM guests if needed.

Residual risks and hygiene
--------------------------

* **Pinned inodes cannot be shed.** ``drop_caches`` cannot evict inodes
  held by open files, process CWDs, or inotify watches (editors and file
  watchers such as VS Code hold many). If the guard flushes and the count
  stays near the threshold, it logs a warning and backs off for a cooldown
  period rather than flushing every tick. If you see that warning
  persistently, a guest process is holding a huge watched/open set; the
  fix is to close it (or raise host limits).
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
