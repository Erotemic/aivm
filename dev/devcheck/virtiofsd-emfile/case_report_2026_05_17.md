# virtiofsd EMFILE case report: persistent-root worker saturated at ~1M FDs

Date: 2026-05-17  
Host: `toothbrush`  
VM: `aivm-2404`  
Primary artifact type: incident / post-mortem analysis

This report records a live incident where a long-lived AIVM `persistent-root`
virtiofs export reached the host-side `virtiofsd` file descriptor ceiling and
propagated `EMFILE` back into guest filesystem operations.  It extends the
earlier [findings.md](findings.md) notes.

## Status of these experiments

The experiments in this report are **post-mortem / incident experiments** unless
otherwise stated.  They inspect or perturb an already-saturated live
`virtiofsd` process.  They are useful for diagnosis and recovery planning, but
they are not deterministic cold-start reproducers by themselves.

For controlled repro / growth experiments from a clean VM, use
[../virtiofsd_emfile_mwe.py](../virtiofsd_emfile_mwe.py).  The MWE can demonstrate
host-side FD growth during guest traversal/open workloads.  The post-mortem
experiments below answer different questions:

- What exactly is the saturated daemon holding?
- Can guest cache eviction release those FDs?
- Can detaching stale AIVM token trees release those FDs?
- Does a live `prlimit` bump merely buy time, or does it fix the state?
- Is `--inode-file-handles=prefer` likely to avoid this FD-backed inode table?

## Incident summary

A host audit found six running `virtiofsd` processes.  The hot process was the
second `persistent-root` worker for `aivm-2404`:

```text
PID=350482
cmdline=/usr/libexec/virtiofsd --fd=34 -o source=/var/lib/libvirt/aivm/aivm-2404/persistent-root
virtiofsd version=1.10.0
NOFILE soft/hard=1000000/1000000
observed FD count=999999, later 999780
```

Peer workers were small:

```text
shared-root worker        7 FDs
shared-root worker       21 FDs
fd-mwe shared-root        7 FDs
fd-mwe shared-root       21 FDs
persistent-root peer      7 FDs
persistent-root hot  999999 FDs
```

This rules out the simple "guest process ulimit" explanation.  The live failure
state was a host-side `virtiofsd` worker sitting at the host daemon's FD ceiling.

The saturated worker had:

```text
CapEff: 00000000880000db
CapBnd: 0000000000000000
```

Decoding `CapEff` gives:

```text
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_FOWNER
CAP_FSETID
CAP_SETGID
CAP_SETUID
CAP_MKNOD
CAP_SETFCAP
```

Notably absent:

```text
CAP_DAC_READ_SEARCH
```

This is relevant because successful file-handle backed inode references require
`CAP_DAC_READ_SEARCH` for `open_by_handle_at`.  The live evidence is consistent
with `virtiofsd` retaining `O_PATH` or otherwise path-backed host descriptors
instead of using file handles for the discovered inode set.

## FD target evidence

A sample of `/proc/350482/fd` showed real path-backed file descriptors under
AIVM token mounts, for example:

```text
/proc/350482/fd/52674 -> /hostcode-ambition-144244d0/target/debug/incremental/trace_replay-.../work-products.bin
/proc/350482/fd/52675 -> /hostcode-ambition-144244d0/target/debug/incremental/trace_replay-.../dep-graph.bin
/proc/350482/fd/52676 -> /hostcode-ambition-144244d0/target/debug/incremental/trace_replay-.../query-cache.bin
/proc/350482/fd/52680 -> /hostcode-ambition-144244d0/target/debug/deps/ambition_sandbox-...rcgu.o
```

A full aggregate of 999,758 path targets made the picture clearer: the hot
worker was not merely holding files from one currently-running agent traversal.
It had accumulated path-backed descriptors across many historical token trees.

### Aggregate by token

```text
517765   51.79%  hostcode-crfm-helm-audit-st-8bd60e77
110043   11.01%  hostcode-ambition-144244d0
106441   10.65%  hostcode-helm_audit-3bb1a84d
 84072    8.41%  hostcode-aiq-magnet-36e91c94
 83480    8.35%  hostcode-every_eval_ever-e2c15d17
 25160    2.52%  hostcode-xcookie-97a25ccb
 21270    2.13%  hostcode-xdoctest-e3bb652d
 12856    1.29%  hostcode-aivm-90d38f9a
  9970    1.00%  hostcode-geowatch-5f1a05ef
  9127    0.91%  hostcode-kwcoco-9135e4b4
```

The top token alone accounted for more than half of the hot daemon's FDs.  The
top five tokens accounted for roughly 90%.

### Aggregate by top directory

```text
147044   14.71%  /hostcode-crfm-helm-audit-st-8bd60e77/crfm-helm-public-eee-test
139090   13.91%  /hostcode-crfm-helm-audit-st-8bd60e77/reports-orig
105440   10.55%  /hostcode-crfm-helm-audit-st-8bd60e77/analysis
 93205    9.32%  /hostcode-ambition-144244d0/target
 63868    6.39%  /hostcode-crfm-helm-audit-st-8bd60e77/old-backup-reports
 49666    4.97%  /hostcode-helm_audit-3bb1a84d/.venv313
 42484    4.25%  /hostcode-every_eval_ever-e2c15d17/hack
 42476    4.25%  /hostcode-crfm-helm-audit-st-8bd60e77/virtual-experiments
 39536    3.95%  /hostcode-aiq-magnet-36e91c94/.venv
 38578    3.86%  /hostcode-every_eval_ever-e2c15d17/.venv
 34721    3.47%  /hostcode-aiq-magnet-36e91c94/.devcontainer-state
 32755    3.28%  /hostcode-helm_audit-3bb1a84d/em_helm_mwe_out
```

### Aggregate by suffix

```text
278470   27.85%  <no-ext>
175061   17.51%  .json
127792   12.78%  .py
 83251    8.33%  .txt
 62332    6.23%  .h
 49650    4.97%  .csv
 27661    2.77%  .pyc
 19376    1.94%  .jsonl
 15014    1.50%  .pyi
 14841    1.48%  .sh
 14607    1.46%  .o
 12786    1.28%  .png
```

This distribution indicates broad inode/path retention over source files,
metadata, generated reports, virtualenvs, build outputs, and caches.  It is not
just one Rust `target/` tree, one Python venv, or one current process keeping
files open.

## Working diagnosis

The current diagnosis is:

> A long-lived `persistent-root` `virtiofsd` worker retained host-side
> path-backed file descriptors for inodes discovered across many AIVM
> `hostcode-*` token trees.  The current workload may have triggered the
> visible `EMFILE`, but the million-FD state was accumulated history across
> generated/cache/build/report trees.  This is not a guest process FD leak.

This is consistent with the earlier 2026-05-11 finding that `virtiofsd` FD
pressure can be sticky after guest opens close.  The 2026-05-17 incident is the
same failure mode at production scale: the daemon's retained FD-backed inode
working set reached the daemon's `NOFILE` ceiling.

## Why this happens even when guest files are closed

The guest process owns guest-visible file descriptors.  Those descriptors can be
opened, read, and closed correctly.

`virtiofsd` owns host-visible descriptors used to serve the virtiofs export.  If
it represents cached/discovered inodes with host FDs, those descriptors can live
beyond the guest process's short-lived open/close cycle.  They may only be
released when the guest forgets cached dentries/inodes, when `virtiofsd` evicts
internal state, or when the backend process exits.

Therefore both statements can be true:

- the guest-side agent is not leaking descriptors;
- the host-side `virtiofsd` process is still holding hundreds of thousands of
  descriptors that were caused by previous guest walks/lookups/builds/indexing.

## Design implications for AIVM

The risky topology is:

```text
one long-lived persistent virtiofs export
  containing many tokenized hostcode subtrees
    including huge generated/cache/build/report directories
```

The aggregate shows that AIVM should treat the following path classes as
high-risk under persistent live virtiofs sharing:

- `target/`
- `.venv*/`, `venv*/`
- `.mypy_cache/`
- `.devcontainer-state/uv-cache/`
- `.git/objects/`
- `reports*/`
- `old-backup-reports/`
- `analysis/experiments/`
- `virtual-experiments/`
- `em_*_mwe_out/`
- large generated JSON/CSV/TXT report forests

Candidate mitigations:

1. Prefer `aivm attach --mode git` or snapshot/copy modes for huge repos that do
   not need live writable host sharing.
2. Add guardrails or warnings for attaching trees with very large generated
   subtrees.
3. Add an attachment health command that reports per-token file counts and
   common high-risk directory classes.
4. Add a safe garbage-collection command for stale token mountpoints and stale
   detached trees.
5. Investigate an exclusion mechanism for persistent live sharing.
6. Make `--inode-file-handles=prefer` effective for `virtiofsd` where supported.
7. Consider separate virtiofs exports for extremely large data/report trees so
   one export's inode table cannot poison the main persistent root.

## New helper script

This overlay adds [fd_postmortem.py](fd_postmortem.py), a
read-only host-side collector with one explicit guest-side cache-drop helper.

### Preserve the current incident state

Run on the host:

```bash
sudo python3 dev/devcheck/virtiofsd-emfile/fd_postmortem.py collect \
    --vm aivm-2404 \
    --out virtiofsd-incident-$(date +%Y%m%dT%H%M%S)
```

Outputs are bundled under the requested incident directory.  The aggregate
files are grouped in a subdirectory so the command does not scatter report files
into the caller's current working directory.

```text
summary.txt
virtiofsd-inventory.tsv
fd-targets.tsv
aggregate/aggregate-report.txt
aggregate/aggregate-by_hostcode_token.tsv
aggregate/aggregate-by_token_topdir.tsv
aggregate/aggregate-by_token_topdir_seconddir.tsv
aggregate/aggregate-by_suffix.tsv
aggregate/aggregate-other_special_kinds.tsv
README.txt
```

By default `collect` also prints `aggregate/aggregate-report.txt` to stdout, so
the operator has a compact report that can be pasted into an issue or chat.  Use
`--no-print-report` to suppress that stdout report.

Use `--sample-limit N` for a quick sample instead of reading every FD target.
Do not use a sample when making a final incident report.

### Aggregate an existing FD target file

The script can aggregate either its own `fd-targets.tsv` format or the common
`/proc/<pid>/fd/N -> target` format:

```bash
python3 dev/devcheck/virtiofsd-emfile/fd_postmortem.py aggregate \
    virtiofsd-incident-20260517T102128/fd-targets.tsv
```

By default this creates a timestamped subdirectory beside the input, for example
`virtiofsd-incident-20260517T102128/fd-targets-aggregate-.../`, writes the TSV
counters there, and prints `aggregate-report.txt` to stdout.  Pass `--out DIR`
when a specific output directory is desired.

### Watch the hot daemon

Run on the host while performing guest-side experiments:

```bash
sudo python3 dev/devcheck/virtiofsd-emfile/fd_postmortem.py watch \
    --vm aivm-2404 \
    --interval 5 \
    | tee fd-watch.txt
```

### Count one token before/after detach

Run on the host before detaching a stale heavy attachment:

```bash
sudo python3 dev/devcheck/virtiofsd-emfile/fd_postmortem.py token-count \
    hostcode-crfm-helm-audit-st-8bd60e77 \
    --vm aivm-2404
```

Then detach the corresponding AIVM folder if it is stale and safe:

```bash
aivm list --section folders
aivm detach /path/to/stale/heavy/repo
```

Then re-run `token-count`.

Interpretation:

| Result | Meaning |
|---|---|
| token count drops near zero | detach can reclaim daemon state; document as an emergency recovery path |
| token count unchanged | detach prevents future replay but does not reclaim current daemon state |
| total drops but token count remains | concurrent cleanup happened; repeat with another token |

### Guest cache eviction experiment

Run a host watcher first.  Then run this inside the guest:

```bash
sudo python3 dev/devcheck/virtiofsd-emfile/fd_postmortem.py guest-drop-caches
```

This performs `sync`, writes `2` to `/proc/sys/vm/drop_caches`, waits, then
writes `3`.  It is an incident experiment, not a general fix.

Interpretation:

| Result | Meaning |
|---|---|
| FDs drop by hundreds of thousands | guest dentry/inode cache eviction can reclaim daemon FDs |
| FDs drop by only hundreds/thousands | some forget/release traffic happens, but not enough for recovery |
| no meaningful drop | backend restart / VM power cycle is probably required |

Observed 2026-05-17 result after the live `NOFILE` bump: the hot worker dropped
from `999778` to `4162` and then `1479` FDs within about 15 seconds after the
guest cache eviction probe.  This showed that most of the retained FD set was
reclaimable by guest inode/dentry cache eviction, likely because eviction caused
virtiofs/FUSE forget/release traffic back to the daemon.

### Capability check

Decode the live daemon's capabilities:

```bash
sudo python3 dev/devcheck/virtiofsd-emfile/fd_postmortem.py decode-caps 350482
```

Then run the existing file-handle feasibility checker:

```bash
sudo python3 dev/devcheck/virtiofsd_filehandles_check.py aivm-2404
```

If filesystems support file handles but the live daemon lacks
`CAP_DAC_READ_SEARCH`, focus on how libvirt launches `virtiofsd`, capability
bounding, AppArmor/seccomp constraints, and whether `--inode-file-handles=prefer`
is actually in the backend command line.

## Recovery / mitigation experiments

### Live `prlimit` bump

This does not reclaim already-retained descriptors, but it can buy time if the
only immediate blocker is `virtiofsd` hitting `RLIMIT_NOFILE`.

```bash
HOT=350482
cat /proc/sys/fs/nr_open
sudo sysctl -w fs.nr_open=2097152
sudo prlimit --pid "$HOT" --nofile=2000000:2000000
grep 'Max open files' /proc/$HOT/limits
sudo ls /proc/$HOT/fd | wc -l
```

Interpretation:

| Result | Meaning |
|---|---|
| guest operations resume | strong evidence guest-visible `EMFILE` came from host-side daemon FD exhaustion |
| guest operations still fail | another worker/state may be wedged; preserve evidence before restarting |

Observed 2026-05-17 result: host `fs.nr_open` started at `1048576`.  Raising it
to `2097152` and applying `prlimit --nofile=2000000:2000000` to the hot worker
succeeded without restarting the VM.  The worker remained around `999778` FDs,
so the operation created headroom but did not reclaim retained descriptors.  A
small guest `os.stat()` probe succeeded afterward, which supports the conclusion
that the previous guest-visible `EMFILE` was caused by the host-side daemon
hitting its FD ceiling.

This should be documented as a temporary workaround, not the structural fix.

### Clean unmount experiment

Only do this after stopping active guest workloads.  Prefer a normal unmount;
lazy unmount makes results harder to interpret.

Inside the guest:

```bash
findmnt -t virtiofs
findmnt -R /mnt/aivm-persistent
sudo umount /mnt/aivm-persistent
```

If busy:

```bash
sudo fuser -vm /mnt/aivm-persistent
```

Then check the host FD count.  A large drop means guest mount teardown emits
sufficient forgets to release daemon state.  No drop means the backend process
must be restarted.

### Destructive subtree rename/delete experiment

This is optional and risky.  Only use disposable generated outputs.

Goal: determine whether removing a massive generated subtree releases daemon
FDs, converts them to `(deleted)` pinned FDs, or leaves the count unchanged.

Procedure:

1. Count FDs under one subtree with `fd-targets.tsv` or `grep`.
2. Rename the corresponding host directory outside the VM.
3. Recount total FDs, subtree FDs, and `(deleted)` FDs.

Interpretation:

| Result | Meaning |
|---|---|
| count drops | path removal can trigger release |
| paths become `(deleted)` but count stays high | descriptors pin deleted files; bad recovery path |
| count unchanged | daemon retained state is independent of current path reachability |

## Handoff summary for future agents

Start from these facts, not from guest `ulimit` debugging:

```text
We confirmed host-side virtiofsd FD exhaustion.  The hot process was the
persistent-root worker PID 350482.  It ran virtiofsd 1.10.0 with
NOFILE=1,000,000 and was observed at ~999,780-999,999 FDs.  FD targets were
almost entirely path-backed descriptors under /hostcode-* token trees, not
anonymous FDs and not guest-process FDs.

The FD aggregate was dominated by historical generated/cache/build/report trees
across many repos.  Top token:
hostcode-crfm-helm-audit-st-8bd60e77 = 517,765 FDs / 51.79%.
Top directories included reports-orig/aggregate-summary,
crfm-helm-public-eee-test/classic, analysis/experiments, .venv*/lib,
target/debug, uv-cache, old-backup-reports, virtual-experiments, and
.mypy_cache.

Current hypothesis: persistent-root virtiofsd retained host-side O_PATH or
similar inode reference FDs for discovered inodes across the long-lived export.
The current workload may trigger EMFILE, but the saturated state is accumulated
history.  Remaining experiments: check whether detach, guest drop_caches, clean
unmount, or deletion/rename of stale heavy subtrees reduces the hot daemon's FD
count; check whether --inode-file-handles=prefer can be made effective.
```

## Recommended next implementation work

1. Convert `fd_postmortem.py collect` output into an `aivm doctor` or
   `aivm diagnose virtiofs` subcommand.
2. Add a persistent attachment health report: per-token file count, risky path
   classes, top generated/cache directories, and stale token stubs.
3. Add warning thresholds for large live attachments.
4. Add a safe detach/garbage-collect recovery flow and explicitly record whether
   it reclaims live daemon FDs on this host.
5. Make file-handle mode measurable: record command-line flag, effective caps,
   and a before/after FD growth experiment from a clean VM.

## Recovery command added after the post-drop experiment

The 2026-05-17 incident showed that guest-side inode/dentry cache eviction can
reclaim the vast majority of the hot daemon's retained FD set: the saturated
`persistent-root` worker fell from about 999,778 FDs to 4,162 and then 1,479 FDs
shortly after `drop_caches` was run inside the guest.  A post-drop aggregate
then showed only 395 FD targets, with the former 517,765-FD top token reduced to
a single descriptor.

This justifies a first-class recovery command:

```bash
aivm vm flush_caches
```

The command runs inside the guest over SSH.  Its default action is deliberately
`drop_caches=2`, which evicts dentries and inodes without also discarding the
page cache.  That is the targeted recovery action for the observed virtiofsd FD
pressure.  Operators can request a broader cache drop when needed:

```bash
aivm vm flush_caches --levels 2,3 --settle_seconds 30
```

This is a recovery lever, not a structural fix.  It does not prevent the same
working set from being rediscovered by future broad traversals.  Long-term
prevention still needs one or more of:

- effective `--inode-file-handles=prefer` support;
- warnings or exclusions for huge generated/cache/build/report trees;
- narrower persistent live shares;
- `git`/snapshot attachment modes for repos that do not need live host sharing;
- stale-token cleanup and attachment garbage collection.
