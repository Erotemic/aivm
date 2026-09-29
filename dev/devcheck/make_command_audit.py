"""Turn the call-site scan into a reviewable audit table."""

import json
import re
from collections import defaultdict
from pathlib import Path

SITES = Path(
    '/tmp/claude-1000/-home-joncrall-code-aivm/'
    '96cc7661-f780-4162-9e18-e885857992d0/scratchpad/sites.json'
)
OUT = Path('/home/joncrall/code/aivm/docs/planning/command-approval-audit.md')

READ_VERBS = (
    'dominfo',
    'domstate',
    'dumpxml',
    'domblkinfo',
    'domiflist',
    'domifaddr',
    'net-info',
    'net-dumpxml',
    'net-dhcp-leases',
    "'list'",
    'list --name',
    'qemu-img info',
    'findmnt',
    'stat',
    'command -v',
    'sha256sum',
    'mountpoint',
    'getent',
    'id -u',
    'systemctl is-',
    'nft list',
    'test -',
    'true',
    'lsblk',
    'df ',
    'readlink',
    'which',
    'ip -j',
    'ip addr',
    'ss -',
    # git read-only subcommands
    'rev-parse',
    'get-url',
    'show-toplevel',
    'ls-remote',
    '--get',
    'symbolic-ref',
    'is-enabled',
    'is-active',
    'systemctl show',
    'systemd-detect-virt',
    "'ls'",
    'ls -',
    'cat ',
)
TOOL_HINTS = (
    'base_dir',
    'state_dir',
    'export root',
    'cloud-init',
    'cloudinit',
    'noble-base',
    'images',
    'cache',
)


# Reviewed decisions, authoritative over the heuristics below. Keyed by
# (file, line). Basis is reported as "reviewed".
OVERRIDES = {
    # mkdir: a write, except into a directory aivm owns
    ('aivm/attachments/persistent/host_bind.py', 154): (
        'tool',
        'persistent-root export dir under base_dir',
    ),
    ('aivm/attachments/persistent/host_bind.py', 218): (
        'tool',
        'bind staging parent under base_dir',
    ),
    ('aivm/attachments/persistent/host_bind.py', 226): (
        'tool',
        'bind staging target under base_dir',
    ),
    ('aivm/attachments/shared_root.py', 91): (
        'tool',
        'shared-root export parent under base_dir',
    ),
    ('aivm/attachments/shared_root.py', 399): (
        'tool',
        'shared-root bind parent under base_dir',
    ),
    ('aivm/attachments/shared_root.py', 407): (
        'tool',
        'shared-root bind target under base_dir',
    ),
    ('aivm/cli/host_permissions.py', 786): ('tool', 'creates base_dir itself'),
    ('aivm/vm/host_access.py', 129): ('tool', 'qemu-access dir under base_dir'),
    ('aivm/vm/host_access.py', 191): ('tool', 'qemu-access dir under base_dir'),
    ('aivm/vm/images.py', 263): ('tool', 'image cache dir under base_dir'),
    ('aivm/credentials/keys.py', 336): (
        'tool',
        'aivm credential dir; the mkdir only',
    ),
    ('aivm/credentials/keys.py', 342): (
        'tool',
        'aivm credential dir; the mkdir only',
    ),
    ('aivm/credentials/keys.py', 347): (
        'tool',
        'aivm credential dir; the mkdir only',
    ),
    # mkdir into directories the user owns
    ('aivm/services.py', 156): (
        'user',
        "creates the user's ~/.ssh; not aivm-owned",
    ),
    ('aivm/attachments/persistent/transport.py', 106): (
        'user',
        'installs under host system config, not aivm-owned',
    ),
    ('aivm/attachments/persistent/transport.py', 98): (
        'user',
        'removes an installed host system file',
    ),
    # image fetch cleanup: regenerable by redownload
    ('aivm/vm/images.py', 141): (
        'tool',
        'removes a checksum-failed cached image; refetchable',
    ),
    ('aivm/vm/images.py', 272): ('tool', 'removes the download temp file'),
    ('aivm/vm/images.py', 348): (
        'tool',
        'removes a stale cached base image; refetchable',
    ),
    # disk lifecycle is not bookkeeping
    ('aivm/vm/disk.py', 50): (
        'user',
        'qemu-img create makes the VM disk; not a read, not regenerable',
    ),
    ('aivm/vm/disk.py', 35): (
        'user',
        'removes the VM disk; destroys guest data',
    ),
    ('aivm/vm/update/detect.py', 57): ('read', 'qemu-img info inspects only'),
    # confirmed reads
    ('aivm/attachments/guest.py', 375): (
        'read',
        'git rev-parse --show-toplevel',
    ),
    ('aivm/attachments/guest.py', 421): ('read', 'git rev-parse --path-format'),
    ('aivm/attachments/guest.py', 442): ('read', 'git remote get-url'),
    ('aivm/cli/config/discover.py', 41): ('read', 'virsh list --all --name'),
    ('aivm/cli/config/discover.py', 50): ('read', 'virsh list --all --name'),
    ('aivm/cli/config/discover.py', 114): ('read', 'virsh dominfo'),
    ('aivm/cli/config/discover.py', 137): ('read', 'virsh dumpxml'),
    ('aivm/vm/drift.py', 209): ('read', 'reads actual VM hardware'),
    ('aivm/vm/host_access.py', 271): ('read', 'getent group lookup'),
    # image fetch, same flow as the refetchable rm calls
    ('aivm/vm/images.py', 294): (
        'tool',
        'downloads the base image into the cache',
    ),
    ('aivm/vm/images.py', 311): (
        'tool',
        'moves the verified download into the cache',
    ),
    # cloud-init: written into an aivm dir, but installed into the VM later
    ('aivm/vm/cloudinit.py', 362): (
        'tool',
        'ci_dir under base_dir; regenerated from config',
    ),
    ('aivm/vm/cloudinit.py', 370): (
        'tool',
        'user-data rendered entirely from cfg',
    ),
    ('aivm/vm/cloudinit.py', 385): (
        'tool',
        'meta-data rendered entirely from cfg',
    ),
    ('aivm/vm/cloudinit.py', 393): (
        'tool',
        'network-config rendered entirely from cfg',
    ),
    ('aivm/vm/cloudinit.py', 410): (
        'tool',
        'removes the seed ISO before rebuilding it',
    ),
    ('aivm/vm/cloudinit.py', 418): (
        'tool',
        'rebuilds the seed ISO from the files above',
    ),
}


def classify(row):
    """Return (disposition, why, basis)."""
    key = (row['file'], row['line'])
    if key in OVERRIDES:
        disp, why = OVERRIDES[key]
        return disp, why, 'reviewed'
    cmd = row['cmd']
    fn = row['func']
    fil = row['file']
    low = (cmd + ' ' + fn + ' ' + (row['summary'] or '')).lower()

    if row['role'] == 'read' or row['enclosing_role'] == 'read':
        return 'read (already)', 'already declared read-only', 'rule'

    probe_fn = any(
        tok in fn.lower()
        for tok in (
            'probe',
            'detect',
            'inspect',
            'status',
            '_get_',
            'check',
            'read',
            'parse',
            'find',
            'resolve',
            'capacity',
            'exists',
        )
    )
    looks_read = any(v in cmd for v in READ_VERBS)

    if fil.endswith('status.py'):
        basis = 'rule' if (looks_read or probe_fn) else 'unsure'
        return 'read', 'status reporting; inspects only', basis
    if looks_read and probe_fn:
        return 'read', 'read-only verb in an inspection helper', 'rule'
    if looks_read:
        return 'read', 'read-only verb; enclosing function unclear', 'unsure'
    if probe_fn and row['check'] is False:
        return 'read', 'unchecked call in an inspection helper', 'unsure'

    if 'mkdir' in cmd and any(h in low for h in TOOL_HINTS):
        return 'tool', 'creates an aivm-owned directory', 'rule'
    if 'mkdir' in cmd:
        return (
            'tool',
            'directory creation; confirm the target is aivm-owned',
            'unsure',
        )
    if fil.endswith('images.py'):
        return 'tool', 'base-image cache; regenerable by redownload', 'unsure'
    if 'cloudinit' in fil:
        return 'tool', 'generated cloud-init, derived from config', 'unsure'

    return 'user', 'no read or bookkeeping rule matched', 'default'


rows = json.load(SITES.open())
affected = [
    r
    for r in rows
    if not (
        r['role'] == 'read'
        or (r['role'] is None and r['enclosing_role'] == 'read')
    )
]

by_file = defaultdict(list)
for r in affected:
    by_file[r['file']].append(r)

counts = defaultdict(int)
bases = defaultdict(int)
uncertain = 0
lines = []
for fil in sorted(by_file):
    lines.append(f'\n### `{fil}`\n')
    lines.append(
        '| Line | Function | Command | Declared | sudo | In step | Proposed | Basis | Rationale |'
    )
    lines.append('|---|---|---|---|---|---|---|---|---|')
    for r in sorted(by_file[fil], key=lambda x: x['line']):
        disp, why, basis = classify(r)
        counts[disp] += 1
        bases[basis] += 1
        if basis != 'rule':
            uncertain += 1
        mark = {'rule': '', 'unsure': ' **?**', 'default': '', 'reviewed': ''}[
            basis
        ]
        cmd = r['cmd'].replace('|', '\\|')
        if len(cmd) > 62:
            cmd = cmd[:59] + '...'
        declared = r['role'] or (
            f'({r["enclosing_role"]})' if r['enclosing_role'] else '—'
        )
        lines.append(
            f'| {r["line"]} | `{r["func"]}` | `{cmd}` | {declared} | '
            f'{r["sudo"] if r["sudo"] is not None else "—"} | '
            f'{"yes" if r["grouped"] else "no"} | **{disp}**{mark} | {basis} | {why} |'
        )

header = f"""# Command approval audit

Generated inventory of every command submission affected by the
"a write is the guard" policy in `docs/source/design.rst`. Purpose is wholesale
review: confirm or correct the **Proposed** column, then the code change is
mechanical.

## How to read this, and how much to trust it

The **Basis** column says *why* a disposition was proposed. It matters more than
the disposition, because the three bases are not equally trustworthy:

- **rule** — a positive match: a known read-only verb inside an inspection
  helper, or a directory creation under an aivm-owned path. Evidence-based.
  Skim these.
- **unsure** (marked **?**) — something matched, but weakly: a read verb in a
  function whose purpose is unclear, or a write that might be bookkeeping.
  **Review these.**
- **default** — nothing matched, so it fell through to `user`. This is *not* a
  judgment that the command writes user-owned state; it is the absence of a
  judgment. **Review these too if you want completeness.**

So the answer to "do I only need to call out the **?** rows" is: those plus the
`default` rows. The `default` rows fail safe — being wrong there costs an
unnecessary prompt rather than a missing one — but they were never recognized,
only assumed. A `default` row that is really a read keeps a prompt it should not
have and stays at `INFO` when it should drop to `--verbose 2`.

## Dispositions

- **read** — inspects only. Declare `role='read'`. No prompt, and the command
  drops to `--verbose 2`. Many of these are undeclared today and default to
  `modify`, which is why they are in this table at all.
- **tool** — a write to aivm's own regenerable bookkeeping. Declare the
  ownership exemption. No prompt.
- **user** — a write to state the user owns, including the guest. Prompts.
  These need no marking; `user` is the default.
- **scrutiny** — unresolved. Written into an aivm-owned directory, but the
  content leaves that directory and becomes guest state. See open questions.

## Totals

| Disposition | Sites |
|---|---|
| read (misclassified today) | {counts['read']} |
| tool (exempt, must be declared) | {counts['tool']} |
| user (prompts) | {counts['user']} |
| **total affected** | **{len(affected)}** |

### Basis

| Basis | Sites | Trust |
|---|---|---|
| reviewed (decided by the maintainer) | {bases['reviewed']} | settled |
| rule (positive match) | {bases['rule']} | skim |
| unsure (**?**) | {bases['unsure']} | review |
| default (fell through to `user`) | {bases['default']} | review for completeness |

Of the {len(rows)} total command submissions in `aivm/`, {len(rows) - len(affected)}
already declare `role='read'` and are unaffected.

## What changes in the code

1. `CommandSpec` gains an ownership field defaulting to `user`.
2. `_command_needs_approval` returns True for any `modify` whose ownership is
   not `tool`, replacing the `spec.sudo or _is_system_libvirt_mutation(spec)`
   test.
3. `_is_system_libvirt_mutation` is deleted; hypervisor control is subsumed.
4. `test_unprivileged_libvirt_mutation_keeps_approval_contract` encodes the
   overturned rule and is rewritten.
5. Each **read** row below declares `role='read'`; each **tool** row declares
   the exemption. **user** rows change nothing.

## Resolved: cloud-init is `tool`

All six sites meet the bookkeeping bar. `ci_dir` is `base_dir / 'cloud-init'`,
an aivm-owned path. The content is rendered entirely from ``cfg`` by
``_render_user_data_text`` and friends -- password, SSH authorization, network
and timezone all come from config the user already wrote. Nobody hand-edits
``user-data``; deleting the directory and re-running produces identical output.

The earlier worry -- "the artifact becomes the guest" -- does not survive
inspection, because writing the file is not what reaches the guest. At create
time the seed is consumed by ``virt-install``, itself a guarded write. The
artifacts sit inert until something boots a VM with them.

### But the act that reaches the guest is not in this table

``refresh_cloud_init_seed_for_next_boot`` (`aivm/vm/cloudinit.py:70`, called
from `aivm/cli/vm_attach.py:403`) rewrites cloud-init for an **existing** VM and
bumps a NoCloud instance-id so the next boot replays the payload. That bump is
what changes guest state, and it is a bare ``token_path.write_text(...)`` at
`aivm/vm/cloudinit.py:105`, with a ``Path.mkdir`` beside it at line 89.

Neither goes through ``CommandManager``. They are not logged as commands, carry
no role or ownership, and cannot be prompted. The consequential half of the
cloud-init flow is invisible to this policy -- which is why the six audited
commands looked more dangerous than they are, and the real one was not on the
list at all.

## Open question: writes that never reach CommandManager

The policy governs commands. Direct filesystem mutation from Python bypasses it
completely, and there are **38** such call sites across `aivm/` --
``write_text``, ``write_bytes``, ``mkdir``, ``shutil.copy/move/rmtree``,
``os.replace``, ``unlink`` -- concentrated in `config_store/io.py` (14),
`fdguard.py` (4), and `attachments/persistent/transport.py` (4).

Most are legitimately aivm's own state, and `config_store/io.py` writing the
config store is the tool's whole job. But the instance-id bump shows the
category is not uniformly safe, and nothing currently distinguishes them.

Deciding this is separate from the table below and probably wants its own pass.
The options are roughly: route consequential filesystem writes through the
manager so they inherit visibility and approval; or define a narrow rule for
which direct writes are permissible and audit against it the way this table
audits commands.

## Findings this audit surfaced

**Read probes are invalidating the probe cache.** 56 of {len(rows)} submissions
declare no role and inherit the `modify` default. `_execute_one` bumps
`mutation_generation` for every `modify`, and probe caches key on that counter,
so a plain `aivm status` invalidates the cache a dozen times over commands that
only report. Declaring these `read` is required by the approval policy anyway;
the cache behaviour is a second reason.

**`aivm status --sudo` is missing read-only auto-approval.** Same cause:
`auto_approve_readonly_sudo` applies only when the effective role is `read`, and
these probes are `modify` by default. Several are sudo probes, so today they
consume approval on a command that only reports.

**Grouping and classification are one backlog.** Almost every undeclared site is
also ungrouped, so this table and the "not grouped into an explicit step"
warning are the same work seen from two directions. Wrapping a call site in
`mgr.step(...)` with `role='read'` settles both.

**The exemption stayed narrow.** Only {counts['tool']} of {len(affected)}
affected sites look like genuine aivm-owned bookkeeping, which is a good sign
for the policy's bar: most writes really are to the user's host or the guest.

## Review method

Generated by `dev/devcheck/scan_command_sites.py`, which AST-walks
`aivm/**/*.py` for `.run(...)` / `.submit(...)` calls on a command manager and
records the declared `role`, `sudo`, `check`, `summary`, and any enclosing
`mgr.intent(...)` / `mgr.step(...)` role. Dispositions are then proposed from
the command text and enclosing function name. Regenerate after editing code
rather than hand-maintaining this file.

## Sites
"""

OUT.write_text(header + '\n'.join(lines) + '\n')
print(f'wrote {OUT}')
print(dict(counts), 'uncertain:', uncertain)
