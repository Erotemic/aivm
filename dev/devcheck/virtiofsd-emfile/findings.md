# virtiofs EMFILE investigation: 2026-05-11 findings

Follow-up to the Apr 2026 `OSError(EMFILE)` reports on this VM, captured after
a host/guest diagnostic pass on 2026-05-11. The original investigation is
summarised in [context.txt](context.txt); the strongest single piece of
evidence at that time was the Python startup report
`python_emfile_report_20260402_162335.txt` (kept in the repo working
tree, not under devcheck).

## TL;DR

1. The Apr-2 EMFILE path `/home/joncrall/code/helm/src` was reachable only
   through a **leftover staged bind**: `hostcode-helm-647a8c86` was on the
   persistent-root mountpoint even though `helm` was not in the active
   attachment config.
2. As of 2026-05-11 there are **11 such stale token directories** under
   persistent-root, including `hostcode-joncrall-0d9afa44` (the entire
   `/home/joncrall` home-directory attachment that was noted as a footgun
   in [../../notes.txt](../../notes.txt)). All 11 are now empty stubs — the
   bind has been unmounted since then but the directory was never
   `rmdir`'d. Detach cleanup in `aivm` removes the mount but not the dir.
3. Current host `virtiofsd` runs with `NOFILE soft=1,000,000`, so the
   trivial "low RLIMIT_NOFILE" version of the hypothesis is ruled out for
   today's config. The Apr-2 failure was either (a) under a previously
   lower limit, or (b) driven by traversal across the stale `helm` bind
   exposing something the guest VFS / virtiofs path could not handle.
4. The full persistent-root tree contains **2,161,225 inode entries**
   (~1.5M regular files + ~437k directories). That is more than 2× the
   1M virtiofsd NOFILE ceiling. A single workload traversing the whole
   `/mnt/aivm-persistent` could still saturate virtiofsd's per-inode FD
   cache. Cache retention is sticky (observed below), so pressure can
   accumulate across sessions until the VM restarts.

## Diagnostic tools used

- [../virtiofsd_emfile_mwe.py](../virtiofsd_emfile_mwe.py) — Python MWE with
  guest-side stress (`guest demo`) and host-side probes (`host probe`,
  `host watch`). Every output line is tagged `[GUEST]` or `[HOST]`.
- [../virtiofsd_host_followups.sh](../virtiofsd_host_followups.sh) — one-shot
  host audit covering virtiofsd inventory, FD-target audit of the
  busiest daemon, tokens-on-disk vs tokens-in-config diff, systemd
  LimitNOFILE config + journal, per-token file counts.

## Empirical results

Raw outputs are in the working directory:
- [hostprobe.txt](hostprobe.txt) — initial host snapshot
- [host-watch.txt](host-watch.txt) — virtiofsd FD-count
  trajectory during the guest demo
- [guest-demo.txt](guest-demo.txt) — guest demo full output
- [host-followups.txt](host-followups.txt) — host audit dump

### 1:1 mapping between guest opens and virtiofsd FDs (confirmed)

From the [host-watch.txt](host-watch.txt) trajectory of the busy
persistent-root virtiofsd (pid=3821138):

```
19:03:11   fds=12,540   idle baseline
19:03:21   fds=30,934   peak during guest `demo` against geowatch token
19:03:22   fds=22,509   after guest closed FDs (sticky retention)
```

The guest demo opened 8,670 files under `hostcode-geowatch-5f1a05ef` and
its `os.walk` stat'd roughly 18k entries. The host daemon's FD count rose
by exactly that amount and **only partially released** when the guest
process closed: it retained ~10k cached inode FDs.

Implication: virtiofsd's per-inode FD cost is real, accumulates across
sessions, and is bounded only by its `RLIMIT_NOFILE` plus whatever its
internal eviction policy reclaims under pressure.

### Default `--inode-file-handles` everywhere

[host-followups.txt:20-25](host-followups.txt#L20-L25) — every running
virtiofsd is invoked without `--inode-file-handles=`. That means it falls
back to keeping one host file descriptor per cached inode, which is the
worst case for this failure mode. Passing
`--inode-file-handles=prefer` (or `mandatory`) would switch to
`name_to_handle_at` + `open_by_handle_at`, eliminating long-lived FDs per
cached inode.

### Stale staged binds (the core finding)

[host-followups.txt:146-157](host-followups.txt#L146-L157) lists the
11 stale tokens. All currently have 0 files — they are empty mountpoint
stubs that were left behind when their bind mounts were detached.
Earlier [host-snapshot.md:151-160](host-snapshot.md#L151-L160) (2026-04-09)
shows several of these tokens were *active* `/dev/nvme2n1p3` bind mounts
at that time, so the detach happened between Apr 9 and May 11.

The Apr-2 EMFILE path `/home/joncrall/code/helm/src` corresponds to the
`hostcode-helm-647a8c86` stale token. The path was reachable only through
that leftover bind, since `helm` was not in the active config in either
the original report or the current config. This makes the leftover bind
the single most plausible mechanism for the original failure.

Stale tokens currently present (all empty stubs):

```
hostcode-cc_templates-28df1b58
hostcode-dtool_ibeis-2d6d7352
hostcode-helm-647a8c86           <- matches original EMFILE path
hostcode-joncrall-0d9afa44       <- was /home/joncrall (homedir footgun)
hostcode-kwdagger-8395f087
hostcode-labelme-738cf148
hostcode-scriptconfig-ee3686e4
hostcode-service-repo-4d485863
hostcode-ubelt-df3ef1b0
hostcode-vllm_service-b4b1906b   <- old; cfc20148 is the active one
hostcode-xdev-d3371bc9
```

### Current virtiofsd cache composition

[host-followups.txt:31-71](host-followups.txt#L31-L71) — at the time
of the audit, the busy persistent-root virtiofsd held 47,478 FDs,
dominated by:

| FDs | path prefix |
|---:|---|
| 19,998 | `hostcode-xcookie-*/.venv/lib` |
|  3,525 | `hostcode-aivm-*/.git/objects` |
|  2,818 | `hostcode-aivm-*/.mypy_cache/3.13` |
|  2,811 | `hostcode-aivm-*/.mypy_cache/3.11` |
|  2,611 | `hostcode-aivm-*/.venv/lib` |
|  2,587 | `hostcode-xcookie-*/.mypy_cache/3.11` |
|  2,272 | `hostcode-geowatch-*/geowatch_tpl/submodules` |
|  ... | (smaller; see file) |

Approximate per-token totals from this snapshot: xcookie ~24.5k, aivm
~9.5k, geowatch ~7k. The xcookie share is dominant because the user was
actively editing in that tree at the time of the audit — virtiofsd's
cache is simply reflecting the live workload, not anything anomalous
about xcookie. **None of the stale tokens had cached FDs at the audit
moment** — they only generate cache pressure when actually traversed.

### Inode-touchable working set

[host-followups.txt:247-282](host-followups.txt#L247-L282) — large
active tokens by file count:

| files | token |
|---:|---|
| 303,979 | `hostcode-crfm-helm-public-c32520e2` |
| 284,704 | `hostcode-crfm-helm-audit-st-8bd60e77` |
| 104,957 | `hostcode-helm_audit-3bb1a84d` |
|  82,600 | `hostcode-tmp-9e3e37df` |
|  75,141 | `hostcode-aiq-magnet-36e91c94` |
|  69,577 | `hostcode-ambition-144244d0` |
|  40,487 | `hostcode-EEE_datastore-dc672c36` |
|  ...    | (others below 22k) |

Totals: 1,529,337 regular files; 436,772 directories; 2,161,225 entries
overall. With `virtiofsd NOFILE soft = 1,000,000`, a workload that walks
the entire `/mnt/aivm-persistent` mount could saturate. The crfm-helm
trees alone (~590k files) plus already-cached inodes from xcookie / aivm
/ geowatch would put the cache over half the NOFILE ceiling.

### Systemd limits

[host-followups.txt:230-232](host-followups.txt#L230-L232):

- `virtqemud` (the actually-used libvirt daemon): LimitNOFILE = 1,048,576
- `libvirtd` (legacy / unused on this host): LimitNOFILE soft = 1,024,
  hard = 524,288. Not used to spawn virtiofsd here, so not relevant.

No journal events matching `nofile` / `emfile` / `too many open files` in
the last 90 days, and last virtqemud restart was 2026-05-07.

## Interpretation

The Apr-2 EMFILE was most likely triggered by Python's `FileFinder._fill_cache`
calling `listdir` on `/home/joncrall/code/helm/src`, where that path
existed *only* via the stale `hostcode-helm-647a8c86` bind mount. The
guest kernel issued a virtiofs LOOKUP, which reached virtiofsd on the
host, which attempted an `openat(O_PATH|O_DIRECTORY)` on the bound
source. Whatever returned EMFILE was *either* virtiofsd hitting NOFILE
under a previous (lower) systemd limit, *or* the kernel hitting a
per-mount inode limit when crossing the stale bind boundary inside the
exported tree.

Either path implicates the **stale staged bind** as the load-bearing
ingredient: removing those binds removes the dangerous traversal target
even if the underlying limit isn't bumped further. The current generous
NOFILE almost certainly makes the symptom harder to hit; it does not
prevent the working set from eventually exceeding 1M as more attachments
accumulate.



## 2026-05-17 follow-up

A later incident reached the end state hypothesized here: one long-lived
`aivm-2404` `persistent-root` `virtiofsd` worker reached roughly 1,000,000
path-backed host file descriptors while peer workers stayed small.  The FD
aggregate was dominated by generated/cache/build/report trees across many
`hostcode-*` token mounts, especially `hostcode-crfm-helm-audit-st-8bd60e77`.

See [case_report_2026_05_17.md](case_report_2026_05_17.md)
for the updated case report and [fd_postmortem.py](fd_postmortem.py)
for the post-mortem collection and experiment helpers.

## Recommended follow-ups

In approximate priority order:

1. **Fix detach to also `rmdir` empty token directories under
   `persistent-root`.** The current behaviour leaves stubs that (a) clutter
   the export and (b) can be re-bound to unintended paths. Cleanup should
   be conservative: only `rmdir` if the directory is genuinely empty and
   not currently a mountpoint.
2. **Add a garbage-collect command** that lists tokens on disk vs config
   and offers to clean up the leftovers, mirroring the comparison done
   by [../virtiofsd_host_followups.sh](../virtiofsd_host_followups.sh) section 3.
3. **Pass `--inode-file-handles=prefer` to virtiofsd** via libvirt's
   `<binary>` element for the filesystem device, so cached inodes do not
   each cost a host FD. This is the structural fix that decouples
   cache-pressure from NOFILE entirely. Verify it works under the
   relevant kernel / AppArmor configuration before rolling out as
   default.
4. **Refuse to attach a parent of an existing attachment.** The
   `hostcode-joncrall-0d9afa44` leftover is exactly the footgun noted in
   [../../notes.txt](../../notes.txt). Detect overlap at attach time and
   surface a clear error.
5. **Optional: cap the persistent-root export's exposed working set.**
   For very large data trees (e.g. `crfm-helm-public` with 304k files),
   consider whether they should ride a separate virtiofs export rather
   than sharing the persistent-root NOFILE budget.

The first item is the smallest, most localised change and would
mechanically prevent the regression mode that produced the Apr-2 report.

## Open questions

- Was virtiofsd's `NOFILE` historically lower on this host? `journalctl`
  didn't surface anything, and there is no surviving systemd drop-in
  showing the prior value, so this is hard to confirm.
- Does the kernel-side virtio-fs path have its own per-export inode
  ceiling on this kernel (6.8.0-106)? Worth a targeted test if the
  symptom recurs after stale-bind cleanup.
- Are there any other on-disk artefacts that get left behind by detach
  (cloud-init seed entries, systemd helper unit fragments, etc.)?
  Same garbage-collection question, broader scope.
